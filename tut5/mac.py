from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

class MAC:
    def __init__(self, key):
        self.mac = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    def genMAC(self, text, counter):
        if type(text) == str:
            text = bytes(text, encoding = 'UTF-8')

        self.mac.update(text)
        self.mac.update(bytes(counter))
        return self.mac.finalize()

    def verMAC(self, text, counter, rcv_mac):
        mac = self.genMAC(text, counter)
        if mac == rcv_mac:
            return True
        else:
            return False
