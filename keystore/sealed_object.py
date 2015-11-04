"""
Basic Sealed Object class/module

Diogo Martins & João Meira
MIEEC//FEUP 2015

License: Beerware (free to use and abuse but you buy us a beer if we ever meet)

Currently:
In development
As of:
October 2015
"""
import base64
try:
   import cPickle as pickle
except:
   import pickle

class SealedObject:
    """
    Basic SealedObject object. Encapsulates a sealable, encryptable object with all its structure
    """

    def __init__(self):
        """
        Basic SealedObject object constructor.

        Arguments:
            none
        """
        self.object_    = None
        self.serial_    = None
        self.encrypted_ = None

    def __serialize(obj):
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def __deserialize(ser):
        return pickle.loads(ser)

    def __encrypt(cipher, ser):
        encryptor = cipher.encryptor()
        ct = encryptor.update(ser) + encryptor.finalize()
        return base64.b64encode(ct)

    def __decrypt(cipher, enc):
        decryptor = cipher.decryptor()
        dt = base64.b64decode(enc)
        return decryptor.update(dt) + decryptor.finalize()

    def seal(self, obj, cipher):
        self.object_    = obj
        self.serial_    = SealedObject.__serialize(obj)
        self.encrypted_ = SealedObject.__encrypt(cipher, self.serial_)
        return self.encrypted_

    def unseal(self, enc, cipher):
        self.encrypted_ = enc
        self.serial_    = SealedObject.__decrypt(cipher, self.encrypted_)
        self.object_    = SealedObject.__deserialize(self.serial_)
        return self.object_
