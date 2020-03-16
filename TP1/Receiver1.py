import os
import asyncio
import socket
import base64
import hashlib
import ast
import numpy as np
import secrets
from tinyec import registry
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.hazmat.primitives.serialization import load_der_public_key

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class Receiver(object):

    def __init__(self, cnt, parameters, addr=None):

        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.server_private_key = None
        self.server_public_key = None
        self.shared_key = None

    def process(self, msg):
        if (self.msg_cnt == 0):

            print("aqui1")
            curve = registry.get_curve('secp256r1')

            self.server_private_key = secrets.randbelow(curve.field.n)
            self.server_public_key = self.server_private_key * curve.g

            new_msg = {
                "curve": curve,
                "pub_key": self.server_public_key
            }

            print("\n\n")
            print(self.server_public_key)
            print("\n\n")
            print(self.server_private_key)
            print("\n\n")

            msg = new_msg

            print("aqui4")

            self.msg_cnt += 1

        elif (self.msg_cnt == 1):

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            nounce = msg_dict['nounce']
            key = msg_dict['key']
            ciphertext = msg_dict['ct']
            signature = msg_dict['signature']
            client_public_key = msg_dict['pub_key']
            print("aqui1")
            self.shared_key = self.server_private_key + client_public_key

            print(self.shared_private_key)

            cip = ChaCha20Poly1305(key)

            if (Ecdsa.verify(message, signature, self.server_public_key)):
                message = cip.decrypt(nonce,ciphertext)
                print('%d : %r' % (self.id, message.decode('utf-8')))

            else:
                print("nao deu")

        else:

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            nounce = msg_dict['nounce']
            ciphertext = msg_dict['ct']
            signature = msg_dict['signature']

            cip = ChaCha20Poly1305(self.shared_key)

            if (Ecdsa.verify(message, signature, self.server_public_key)):

                message = cip.decrypt(nonce,ciphertext)
                print('%d : %r' % (self.id, message.decode('utf-8')))

            else:
                print("nao deu")

            self.msg_cnt +=1

        print('NEXT!')
        return msg if len(msg)>0 else None

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    srvwrk = Receiver(conn_cnt,parameters,addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data==b'\n': break
        data = srvwrk.process(data)
        print("passei aqui")
        if not data: break
        writer.write(bytes(str(data).encode('utf-8')))
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()

def run_receiver():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_receiver()