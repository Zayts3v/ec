import os
import asyncio
import socket
import base64
import hashlib
import ast
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.hazmat.primitives.serialization import load_der_public_key

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class Receiver(object):

    def __init__(self, cnt, addr=None):

        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.server_private_key = None
        self.server_public_key = None
        self.client_public_key = None
        self.shared_key = None

    def process(self, msg):
        if (self.msg_cnt == 0):

            self.server_private_key = ec.generate_private_key(
                ec.SECP256K1(), default_backend())
            
            self.server_public_key = self.server_private_key.public_key()

            new_msg = {
                "pubKey": self.server_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            }

            msg = new_msg

            self.msg_cnt += 1

        elif (self.msg_cnt == 1):

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            nounce = msg_dict['nounce']
            key = msg_dict['key']
            ciphertext = msg_dict['ct']
            signature = msg_dict['sign']
            pub_key = msg_dict['pub_key']

            self.client_public_key = load_der_public_key(pub_key, backend=default_backend())

            self.shared_key = self.server_private_key.exchange(ec.ECDH(), self.client_public_key)

            cip = ChaCha20Poly1305(key)

            try:
                self.client_public_key.verify(signature,ciphertext,ec.ECDSA(hashes.SHA256()))
                message = cip.decrypt(nounce,ciphertext,None)
                print('%d : %r' % (self.id, message.decode('utf-8')))

            except:
                print("Error while decrypt")

            self.msg_cnt += 1
        else:

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            nounce = msg_dict['nounce']
            key = msg_dict['key']
            ciphertext = msg_dict['ct']
            signature = msg_dict['sign']

            cip = ChaCha20Poly1305(key)

            try:
                self.client_public_key.verify(signature,ciphertext,ec.ECDSA(hashes.SHA256()))
                message = cip.decrypt(nounce,ciphertext,None)
                print('%d : %r' % (self.id, message.decode('utf-8')))

            except:
                print("Error while decrypt")

            self.msg_cnt += 1

        print('NEXT!')
        return msg if len(msg)>0 else None

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = Receiver(conn_cnt,addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data==b'\n': break
        data = srvwrk.process(data)
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