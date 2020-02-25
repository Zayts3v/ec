import asyncio
import base64
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class Receiver(object):

    def __init__(self, cnt, addr=None):

        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.backend = default_backend()

    def process(self, msg):


        salt = msg[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )

        print("Intruduza password para ler a mensagem recebida:")
        info = input()
        password = info.encode('utf-8')

        fkey = kdf.derive(password)

        key  = fkey[:32]
        kmac = fkey[32:]

        mac = hmac.new(kmac, key, hashlib.sha256).digest()

        if (mac == msg[32:64]):

            iv = msg[16:32]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)

            decryptor = cipher.decryptor()
            mensagem = decryptor.update(msg[64:])

            print("Mensagem recebida:")
            print(mensagem.decode('utf-8'))

            new_msg = b"Mensagem recebida"
        else:
            print("Password errada!")
            new_msg = b"Algo correu mal"

        self.msg_cnt += 1
        return new_msg if len(new_msg)>0 else None

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = Receiver(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
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