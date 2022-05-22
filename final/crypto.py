from Crypto.PublicKey import RSA  # pycryptodome
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from arc4 import ARC4  # arc4
from tinyec import registry  # tinyec ECC 曲线库
from tinyec import ec
import secrets
import datetime
import calendar
import struct
import hashlib


class ECDH:
    def __init__(self, curve):
        self.curve = registry.get_curve(curve)
        self.public_key = RSA.importKey(open("public.pem").read())
        self.private_key = RSA.importKey(open("private.key").read())
        self.ecc_private_key = secrets.randbelow(self.curve.field.n)

    def encrypt(self, plain_text):
        cipher = Cipher_pkcs1_v1_5.new(self.public_key)  # 创建用于执行pkcs1_v1_5加密或解密的密码
        cipher_text = cipher.encrypt(plain_text)
        return cipher_text

    def decrypt(self, cipher_text):
        cipher = Cipher_pkcs1_v1_5.new(self.private_key)  # 创建用于执行pkcs1_v1_5加密或解密的密码
        plain_text = cipher.decrypt(cipher_text, 'ERROR')
        return plain_text

    def generate_first_handshake_data(self):
        timestamp = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        timestamp_hex = struct.pack('>L', timestamp)

        ecc_public_key = self.ecc_private_key * self.curve.g
        ecc_public_key_x = bytes(hex(ecc_public_key.x)[2:].zfill(64).encode())
        ecc_public_key_y = bytes(hex(ecc_public_key.y)[2:].zfill(64).encode())

        message = timestamp_hex + ecc_public_key_x + ecc_public_key_y + hashlib.sha256(timestamp_hex + ecc_public_key_x + ecc_public_key_y).digest()
        data = self.encrypt(message)
        return data

    def parse_share_key_from_first_handshake_data(self, data):
        text = self.decrypt(data)
        timestamp = struct.unpack('>L', text[0:4])[0]
        sha256_hash = text[-32:]
        ecc_public_key_x = int(text[4:68].decode(), 16)
        ecc_public_key_y = int(text[68:132].decode(), 16)
        ecc_public_key = ec.Point(self.curve, ecc_public_key_x, ecc_public_key_y)

        if sha256_hash == hashlib.sha256(text[:-32]).digest() and calendar.timegm(datetime.datetime.utcnow().utctimetuple()) - timestamp < 5:  # 哈希校验&时间戳校验
            share_key = self.ecc_private_key * ecc_public_key
            share_key = hex(share_key.x) + hex(share_key.y % 2)[2:]
            return share_key
        else:
            return


class Cipher:
    def encrypt(self, key, plaintext):
        arc4 = ARC4(key)
        data = arc4.encrypt(plaintext)
        return data

    def decrypt(self, key, ciphertext):
        arc4 = ARC4(key)
        data = arc4.decrypt(ciphertext)
        return data


if __name__ == '__main__':
    from configparser import ConfigParser

    config = ConfigParser()
    config.read('config.ini')
    curve = config.get('encrypt', 'curve')
    encrypt = ECDH(curve)
    data = encrypt.generate_first_handshake_data()
    share_key = encrypt.parse_share_key_from_first_handshake_data(data)
    print(share_key)

    cipher = Cipher()

    key = share_key[10:42].encode()
    print(key)
    data = cipher.encrypt(key, b'asdf')
    print(data)
    data = cipher.decrypt(key, data)
    print(data)
