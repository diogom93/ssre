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
        return encryptor.update(ser)

    def __decrypt(cipher, enc):
        decryptor = cipher.decryptor()
        return decryptor.update(enc)

    def seal(self, obj, cipher):
        self.object_    = obj
        self.serial_    = __serialize(obj)
        self.encrypted_ = __encrypt(cipher, self.serial_)
        return self.encrypted_

    def unseal(self, enc, cipher):
        self.encrypted_ = enc
        self.serial_    = __decrypt(cipher, self.encrypted_)
        self.object_    = __deserialize(self.serial_)
        return self.object_
