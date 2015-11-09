import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

modes_list = {'CBC': modes.CBC, 'CFB': modes.CFB, 'CFB8': modes.CFB8}

class KeyAlgorithm:
    def encrypt(self, text):
        enc = self.cipher.encryptor()
        ct = enc.update(text) + enc.finalize()
        return ct

    def decrypt(self, text):
        dec = self.cipher.decryptor()
        pt = dec.update(text) + dec.finalize()
        return pt


class KeyRC4(KeyAlgorithm):
    def __init__(self, key):
        self.algorithm = algorithms.ARC4(key)
        self.mode = None
        self.backend = default_backend()

        self.cipher = Cipher(self.algorithm, self.mode, self.backend)

class KeyAES(KeyAlgorithm):
    def __init__(self, key, mode, padding):
        self.iv = os.urandom(16)
        self.algorithm = algorithms.AES(key)
        self.mode = modes_list[mode](self.iv)
        self.backend = default_backend()

        self.cipher = Cipher(self.algorithm, self.mode, self.backend)

        if padding == True:
            setattr(KeyAES, 'encrypt', pad_encrypt)
            setattr(KeyAES, 'decrypt', pad_decrypt)

    def padding(self, text):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text)
        padded_data += padder.finalize()
        return padded_data

    def unpadding(self, text):
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(text)
        data += unpadder.finalize()
        return data

def pad_encrypt(self, text):
    text = self.padding(text)
    ct = super(KeyAES, self).encrypt(text)
    return ct

def pad_decrypt(self, text):
    pt = super(KeyAES, self).decrypt(text)
    pt = self.unpadding(pt)
    return pt
