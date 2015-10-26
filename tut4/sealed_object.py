import pickle

class SealedObject:

    def __init__(self):
        self.object_    = None
        self.serial_    = None
        self.encrypted_ = None

    def __serialize(obj):
        return pickle.dumps(obj)

    def __deserialize(ser):
        return pickle.loads(ser)

    def __encrypt(cipher, ser):
        encryptor = cipher.encryptor()
        return encryptor.update(ser)# + encryptor.finalize()

    def __decrypt(cipher, enc):
        decryptor = cipher.decryptor()
        return decryptor.update(enc)# + decryptor.finalize()

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
