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
    Basic SealedObject object. Encapsulates a sealable, encryptable object with all its structure.
    """

    def __init__(self):
        self.object_    = None
        self.serial_    = None
        self.encrypted_ = None

    def __serialize_(obj):
        """
        Serializes a Python object into bytes.
        Internal use only.

        Arguments:
            obj     - The Python object to serialize
        Return:
            bytes representing the serialized object
        """
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def __deserialize_(ser):
        """
        Deserializes bytes into a Python object.
        Internal use only.

        Arguments:
            ser     - bytes representing the serialized data
        Return:
            Python object representing the deserialized data
        """
        return pickle.loads(ser)

    def __encrypt(cipher, ser):
        """
        Encrypts and encodes bytes using the provided cipher.
        Internal use only.

        Arguments:
            cipher  - the cipher object to use in encryption
            ser     - bytes representing the data to encrypt
        Return:
            Base64 String representing the encrypted and encoded data
        """
        ct = cipher.encrypt(ser)
        return base64.b64encode(ct)

    def __decrypt(cipher, enc):
        """
        Decodes and decrypts a Base64 String using the provided cipher.
        Internal use only.

        Arguments:
            cipher  - the cipher object to use in decryption
            enc     - Base64 String representing the data to decrypt
        Return:
            bytes representing the decoded and decrypted data
        """
        dt = base64.b64decode(enc)
        return cipher.decrypt(dt)

    def seal(self, obj, cipher):
        """
        Seals an external object into the referenced SealedObject using the provided cipher.

        Arguments:
            obj     - external object to be encapsulated
            cipher  - the cipher object to use in encryption
        Return:
            Base64 String representing the sealed object
        """
        self.object_    = obj
        self.serial_    = SealedObject.__serialize_(obj)
        self.encrypted_ = SealedObject.__encrypt(cipher, self.serial_)
        return self.encrypted_

    def unseal(self, enc, cipher):
        """
        Unseals the referenced SealedObject into an external object using the provided cipher.

        Arguments:
            enc     - Base64 String representing the encapsulated object
            cipher  - the cipher object to use in encryption
        Return:
            External unsealed object
        """
        self.encrypted_ = enc
        self.serial_    = SealedObject.__decrypt(cipher, self.encrypted_)
        self.object_    = SealedObject.__deserialize_(self.serial_)
        return self.object_

    def serialize(self, obj):
        """
        Seals an external object into the referenced SealedObject using simple serialization.

        Arguments:
            obj     - external object to be encapsulated
        Return:
            Base64 String representing the sealed object
        """
        self.object_    = obj
        self.serial_    = SealedObject.__serialize_(obj)
        self.encrypted_ = None
        return base64.b64encode(self.serial_)

    def deserialize(self, ser):
        """
        Unseals the referenced SealedObject into an external object using simple deserialization.

        Arguments:
            ser     - Base64 String representing the encapsulated object
        Return:
            External unsealed object
        """
        self.encrypted_ = None
        self.serial_    = base64.b64decode(ser)
        self.object_    = SealedObject.__deserialize_(self.serial_)
        return self.object_
