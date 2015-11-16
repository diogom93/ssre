from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os

class MAC:
    def __init__(self, key):
        self.mac = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        self.counter = 0

    def genMAC(self, text, counter = self.counter):
        self.counter = counter
        if type(text) == str:
            text = bytes(text, encoding = 'UTF-8')

        self.mac.update(text)
        self.mac.update(bytes(str(counter), encoding = 'UTF-8'))
        return self.mac.finalize()

    def verMAC(self, text, rcv_mac, counter = self.counter):
        self.counter = counter
        mac = self.genMAC(text, counter)
        if mac == rcv_mac:
            return True
        else:
            return False

    def counterUp(self):
        self.counter += 1
