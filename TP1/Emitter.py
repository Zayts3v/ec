import os
import asyncio
import socket
import base64
import hashlib
import ast
import random
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.hazmat.primitives.serialization import load_der_public_key

conn_port = 8888
max_msg_size = 9999

class Emitter:

    def __init__(self, sckt=None):

        self.sckt = sckt
        self.msg_cnt = 0
        self.client_private_key = None
        self.client_public_key = None
        self.shared_key = None

    def process(self, msg=b""):

        if (self.msg_cnt == 0):

            new_msg = bytes("Hello".encode('utf-8'))
            self.msg_cnt += 1

        elif (self.msg_cnt == 1):

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)
            txt1 = msg_dict.get("txt1")
            txt2 = msg_dict['txt2']

            parameters        = load_der_parameters(txt1, backend=default_backend())
            server_public_key = load_der_public_key(txt2, backend=default_backend())

            self.client_private_key = parameters.generate_private_key()
            self.client_public_key  = self.client_private_key.public_key()
            self.shared_key         = self.client_private_key.exchange(server_public_key)

            new_msg = {
                "ct": self.client_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            }

            self.msg_cnt +=1
        else:
            inicial = os.urandom(512)
            nonce = random.choices(inicial, k=128)
            nounce = np.asarray(nonce)

            if len(self.shared_key) not in (16, 24, 32):
                key = hashlib.sha256(self.shared_key).digest()

            cipher = Cipher(algorithms.AES(key), modes.GCM(nounce), backend=default_backend())
            encryptor = cipher.encryptor()

            print('Input message to send (empty to finish)')
            data = input()
            message = data.encode('utf-8')

            ct = encryptor.update(message) + encryptor.finalize()

            print('Received (%d): %r' % (self.msg_cnt,data))

            new_msg = {
               "nonce": nonce,
               "ct": ct
            }

            self.msg_cnt +=1

        print("Mensagem enviada!\n")

        return new_msg if len(new_msg)>0 else None

@asyncio.coroutine
def tcp_echo_emitter(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    emitter = Emitter(addr)
    msg = emitter.process()
    while msg:
        writer.write(bytes(str(msg).encode('utf-8')))
        msg = yield from reader.read(max_msg_size)
        if msg:
            msg = emitter.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_emitter():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_emitter())


run_emitter()