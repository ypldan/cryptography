import binascii
from random import sample
from typing import *
from sympy.crypto.crypto import gm_private_key, gm_public_key, encipher_gm, decipher_gm

prime_numbers = [99991, 99989, 99971, 99961, 99929,
                 99923, 99907, 99901, 99881, 99877,
                 99871, 99859, 99839, 99833, 99829,
                 99823, 99817, 99809, 99793, 99787,
                 99767, 99761, 99733, 99721, 99719,
                 99713, 99709, 99707, 99689, 99679]

# CLIENT
class GMC:
    def __init__(self):
        self.priv_key = tuple(sample(prime_numbers, 2))

    def get_pub_key(self):
        return gm_public_key(self.priv_key[0], self.priv_key[1])

    def decode(self, encoded_message: List[int]):
        message_code = decipher_gm(encoded_message, self.priv_key)
        decoded_message = binascii.unhexlify(format(message_code, "x").encode("utf-8")).decode("utf-8")
        return decoded_message


# SERVER
class GMS:
    def __init__(self):
        pass

    def encode(self, message: str, pub_key: Tuple[int, int]):
        message_code = int(binascii.hexlify(message.encode("utf-8")), 16)
        return encipher_gm(message_code, pub_key)

### EXAMPLE OF USE
m = "It's a secret message"
client = GMC()
pub_key = client.get_pub_key()
print("public_key", pub_key)

server = GMS()
m_enc = server.encode(m, pub_key)
print("encoded message sample", m_enc[:10])

m_dec = client.decode(m_enc)
print(m_dec)
