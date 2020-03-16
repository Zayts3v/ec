import os
import asyncio
import socket
import base64
import hashlib
import ast
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh, dsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.hazmat.primitives.serialization import load_der_public_key

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class Receiver(object):

    def __init__(self, cnt, parameters_DH, parameters_DSA, addr=None):

        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.parameters_DH = parameters_DH
        self.parameters_DSA = parameters_DSA
        self.server_private_key = None
        self.public_key = None
        self.shared_key = None

    def process(self, msg):
        if (self.msg_cnt == 0):
            print('READY!')

            dsa_private_key = self.parameters_DSA.generate_private_key()
            dsa_public_key  = dsa_private_key.public_key()

            self.server_private_key = self.parameters_DH.generate_private_key()
            self.public_key         = self.server_private_key.public_key()

            param_dh  = self.parameters_DH.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)
            pubK_dh   = self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            pubK_dsa  = dsa_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

            sig = dsa_private_key.sign(
                pubK_dh,
                hashes.SHA256()
            )

            new_msg = {
                "parameters_DH": param_dh,
                "public_key_DH": pubK_dh,
                "public_key_DSA": pubK_dsa,
                "signature": sig
            }

            msg = new_msg

            self.msg_cnt += 1
        elif (self.msg_cnt == 1):

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            client_key = load_der_public_key(msg_dict['ct'], backend=default_backend())
            self.shared_key = self.server_private_key.exchange(client_key)
            msg_dict['ct'] = "Done!"

            msg = msg_dict

            self.msg_cnt += 1
        else:

            msg = msg.decode()

            msg_dict = ast.literal_eval(msg)

            if len(self.shared_key) not in (16, 24, 32):
                key = hashlib.sha256(self.shared_key).digest()

            mac = hmac.HMAC(key,hashes.SHA256(),default_backend())
            mac = mac.finalize()

            if (mac == msg_dict['mac']):

                nonce = msg_dict['nonce']
                nounce = np.asarray(nonce)

                cipher = Cipher(algorithms.AES(key), modes.CFB(nounce), backend=default_backend())

                decryptor = cipher.decryptor()
                mensagem = decryptor.update(msg_dict['ct'])

                print('%d : %r' % (self.id, mensagem.decode('utf-8')))
                msg_dict['ct'] = mensagem

                msg = msg_dict

            else:
                print("Erro no MAC!")    

            self.msg_cnt += 1

        print('Next Step!')
        return msg if len(msg)>0 else None

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    parameters_DH = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
    parameters_DSA = dsa.generate_parameters(key_size=1024,backend=default_backend())
    srvwrk = Receiver(conn_cnt,parameters_DH,parameters_DSA,addr)
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