import os
import asyncio
import socket
import base64
import hashlib
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
        self.parameters = parameters
        self.server_private_key = None
        self.public_key = None
        self.shared_key = None

    def process(self, msg):
        if (self.msg_cnt == 0):
            print('READY!')

            self.server_private_key = self.parameters.generate_private_key()
            self.public_key         = self.server_private_key.public_key()

            new  = self.parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)
            new2 = self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

            new_msg = {
                "txt1": new,
                "txt2": new2
            }

            msg = new_msg

            print(new_msg["txt1"])

            print('AQUI!')
            self.msg_cnt += 1
        elif (self.msg_cnt == 1):

            client_key = load_der_public_key(msg["ct"], backend=default_backend())
            self.shared_key = self.server_private_key.exchange(client_key)
            msg["ct"] = "Done!"
            self.msg_cnt += 1

        else:

            if len(self.shared_key) not in (16, 24, 32):
                key = hashlib.sha256(self.shared_key).digest()

            nonce = msg["nonce"]

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)

            decryptor = cipher.decryptor()
            mensagem = decryptor.update(msg["ct"])

            print('%d : %r' % (self.id,plaintext.decode('utf-8')))
            msg["ct"] = plaintext

            self.msg_cnt += 1

        return msg if len(msg)>0 else None

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    srvwrk = Receiver(conn_cnt,parameters,addr)
    data = yield from reader.read(max_msg_size)
    msg = {
            "txt": data
        }
    while True:
        if not data: continue
        if data==b'\n': break
        msg["data"] = srvwrk.process(msg)
        if not data: break
        writer.write(data)
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