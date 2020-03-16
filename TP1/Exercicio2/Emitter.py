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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
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

            pub_key = msg_dict['pubKey']

            server_public_key = load_der_public_key(pub_key, backend=default_backend())

            self.client_private_key = ec.generate_private_key(
                                            ec.SECP256K1(), default_backend())
            self.client_public_key = self.client_private_key.public_key()
            self.shared_key = self.client_private_key.exchange(ec.ECDH(), server_public_key)

            key = os.urandom(32)
            nounce = os.urandom(12)

            cip = ChaCha20Poly1305(key)

            print('Input message to send (empty to finish)')
            data = input()
            message = data.encode('utf-8')

            ciphertext = cip.encrypt(nounce,message,None)

            signature = self.client_private_key.sign(
                                            ciphertext,
                                            ec.ECDSA(hashes.SHA256()))

            new_msg = {
                "nounce": nounce,
                "key": key,
                "ct": ciphertext,
                "sign": signature,
                "pub_key": self.client_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            }

            self.msg_cnt +=1
        else:
            key = os.urandom(32)
            nounce = os.urandom(12)
            
            cip = ChaCha20Poly1305(key)

            print('Input message to send (empty to finish)')
            data = input()
            message = data.encode('utf-8')

            ciphertext = cip.encrypt(nounce,message,None)

            signature = self.client_private_key.sign(
                                            ciphertext,
                                            ec.ECDSA(hashes.SHA256()))

            new_msg = {
                "nounce": nounce,
                "key": key,
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