import os
import asyncio
import socket
import base64
import hashlib
import ast
import random
import numpy as np
import secrets
from tinyec import registry
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

            print("aqui1")

            curve = msg_dict['curve']
            server_public_key = msg_dict['pub_key']
            print("aqui2")

            self.client_private_key = secrets.randbelow(curve.field.n)
            self.client_public_key = self.client_private_key * curve.g
            self.shared_key = self.client_private_key + server_public_key

            key = os.urandom(32)
            nounce = os.urandom(32)
            cip = ChaCha20Poly1305(key)

            print('Input message to send (empty to finish)')
            data = input()
            message = data.encode('utf-8')

            print("aqui3")           
            ciphertext = cip.encrypt(nonce,message)

            signature = Ecdsa.sign(message,privateKey)

            new_msg = {
                "nounce": nounce,
                "key": key,
                "ct": ciphertext,
                "sign": signature,
                "pub_key": self.server_public_key
            }

            self.msg_cnt +=1
        else:
            key = os.urandom(32)
            nounce = os.urandom(32)
            cip = ChaCha20Poly1305(self.shared_key)

            print('Input message to send (empty to finish)')
            data = input()
            message = data.encode('utf-8')

            ciphertext = cip.encrypt(nonce,message)

            signature = Ecdsa.sign(message,privateKey)

            new_msg = {
                "key": key,
                "nounce": nounce,
                "ct": ciphertext,
                "sign": signature
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