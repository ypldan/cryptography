from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from base64 import b64decode
from base64 import b64encode
from hashlib import md5

import requests as rq
from requests.auth import HTTPBasicAuth as auth

import binascii
from random import sample
from typing import *
from sympy.crypto.crypto import gm_public_key, decipher_gm


prime_numbers = [99991, 99989, 99971, 99961, 99929,
                 99923, 99907, 99901, 99881, 99877,
                 99871, 99859, 99839, 99833, 99829,
                 99823, 99817, 99809, 99793, 99787,
                 99767, 99761, 99733, 99721, 99719,
                 99713, 99709, 99707, 99689, 99679]


class GMC:
    def __init__(self):
        self.priv_key = tuple(sample(prime_numbers, 2))

    def get_pub_key(self):
        return gm_public_key(self.priv_key[0], self.priv_key[1])

    def decode(self, encoded_message: List[int]):
        message_code = decipher_gm(encoded_message, self.priv_key)
        decoded_message = binascii.unhexlify(format(message_code, "x").encode("utf-8")).decode("utf-8")
        return decoded_message


class AESCipher:
    def __init__(self, key_s='hej'):
        self.key_s = key_s
        self.key = md5(self.key_s.encode('utf-8')).digest()
        self.cipher = None

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
                                                      AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


class Session:

    def __init__(self, url: str, user: str, passwd: str, code=None, debug=False):
        self.user = user
        self.passwd = passwd
        self.url = url
        self.key = None
        self.aes = None
        self.debug = debug
        self.code = code

    def set_code(self, code):
        self.code = code

    def login(self):
        response = rq.get('{}/login'.format(self.url),
                          auth=auth(self.user, self.passwd))
        if response.status_code == 200:
            return response.json()['message']
        return f'Something went wrong: {response.text}, {response.status_code}'

    def get_key(self) -> str:
        gmc = GMC()
        a, N = gmc.get_pub_key()
        response = rq.post('{}/key'.format(self.url),
                           json={'a': a, 'N': N},
                           auth=auth(self.user, self.passwd),
                           headers={'Session-Code': self.code})
        if response.status_code == 200:
            decoded = response.json()['info']
            return gmc.decode(decoded)
        else:
            raise Exception(response.json()['error'])

    def init_session(self):
        if self.debug:
            print('Getting key for AES.')
        self.key = self.get_key()
        self.aes = AESCipher(self.key)
        if self.debug:
            print('Key is here.')

    def send_text(self, name, text: str):
        if self.key is None or self.aes is None:
            self.init_session()
        headers = {'Content-type': 'application/octet-stream',
                   'Session-Code': self.code}
        encrypted = self.aes.encrypt(text)
        if self.debug:
            print('Raw data:', text)
            print('Encrypted data:', encrypted)
        response = rq.post('{}/store?name={}'.format(self.url, name),
                           encrypted,
                           headers=headers,
                           auth=auth(self.user, self.passwd))
        message = response.json()
        if response.status_code == 200:
            return message['message']
        elif response.status_code == 401:
            self.key = None
            self.aes = None
            return self.send_text(name, text)
        else:
            raise Exception(message['error'])

    def get_text(self, name: str):
        if self.key is None or self.aes is None:
            self.init_session()
        response = rq.get('{}/file?name={}'.format(self.url, name),
                          auth=auth(self.user, self.passwd),
                          headers={'Session-Code': self.code})
        if response.status_code == 200:
            decrypted = self.aes.decrypt(response.content)
            if self.debug:
                print('Encrypted data:', response.content)
                print('Decrypted data:', decrypted)
            return decrypted.decode('utf-8')
        elif response.status_code == 401:
            self.key = None
            self.aes = None
            return self.get_text(name)
        else:
            raise Exception(response.json()['error'])
