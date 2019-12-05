from flask import jsonify
from base64 import b64decode
from base64 import b64encode
from hashlib import md5
import binascii
from typing import *
from sympy.crypto.crypto import encipher_gm

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from os import path
import random
import string
import json


class AESCipher:
    def __init__(self, key_s='hej'):
        self.key_s = key_s
        self.key = md5(self.key_s.encode('utf-8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
                                                      AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


def json_message(message, error=None):
    return jsonify(message=message, error=error)


def normal_message(info):
    return json.dumps({'message': info})


def key_message(key):
    return json.dumps({'info': key})


def error_message(error):
    return json.dumps({'error': error})


def send_key(key):
    return jsonify(info=key)


def get_file(name):
    p = 'data/{}'.format(name)
    if not path.isfile(p):
        with open(p, 'w') as fout:
            pass
    with open(p, 'r') as fin:
        return ''.join(fin)


def store_file(name, data):
    with open('data/{}'.format(name), 'w') as fout:
        fout.write(data)


def generate_AES():
    return get_random_bytes(AES.key_size[0])


def generate_random_str(l=20):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(l))


def generate_code(n=8):
    return ''.join(str(random.randint(0,9)) for _ in range(n))


class GMS:
    @staticmethod
    def encode(message: str, pub_key: Tuple[int, int]):
        message_code = int(binascii.hexlify(message.encode("utf-8")), 16)
        return encipher_gm(message_code, pub_key)


if __name__ == '__main__':
    print(generate_code())
