from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from base64 import b64decode
from base64 import b64encode
from hashlib import md5

import requests as rq


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

    def __init__(self, url: str, user: str, debug=False):
        self.user = user
        self.url = url
        self.key = None
        self.aes = None
        self.debug = debug

    def get_key(self) -> str:
        key = RSA.generate(2048)
        pub = key.publickey()
        response = rq.post('{}/key?user={}'.format(self.url, self.user),
                           json={'pub': pub.exportKey('PEM').decode('utf-8')})
        decrypter = PKCS1_OAEP.new(key)
        return decrypter.decrypt(response.content).decode('utf-8')

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
        headers = {'Content-type': 'application/octet-stream'}
        encrypted = self.aes.encrypt(text)
        if self.debug:
            print('Raw data:', text)
            print('Encrypted data:', encrypted)
        response = rq.post('{}/store?user={}&name={}'.format(self.url, self.user, name),
                           encrypted,
                           headers=headers)
        message = response.json()
        return message['error'] if message['message'] is None else message['message']

    def get_text(self, name: str):
        if self.key is None or self.aes is None:
            self.init_session()
        response = rq.get('{}/file?user={}&name={}'.format(self.url, self.user, name))
        decrypted = self.aes.decrypt(response.content)
        if self.debug:
            print('Encrypted data:', response.content)
            print('Decrypted data:', decrypted)
        return decrypted.decode('utf-8')
