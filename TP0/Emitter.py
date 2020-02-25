import asyncio
import socket
import base64
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

conn_port = 8888
max_msg_size = 9999

class Emitter:

    def __init__(self, sckt=None):

        self.sckt = sckt
        self.msg_cnt = 0
        self.backend = default_backend()

    def process(self, msg=b""):

        salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )

        print("Para enviar nova mensagem intruduza password:")
        info = input()
        password = info.encode('utf-8')

        fkey = kdf.derive(password)

        key  = fkey[:32]
        kmac = fkey[32:]

        mac = hmac.new(kmac, key, hashlib.sha256).digest()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        print("Mensagem a enviar:")
        data = input()
        message = data.encode('utf-8')

        ct = encryptor.update(message) + encryptor.finalize()

        new_msg = salt + iv + mac + ct

        print("Mensagem enviada!\n")

        self.msg_cnt += 1
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
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
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