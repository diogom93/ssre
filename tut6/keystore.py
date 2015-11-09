import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, AlreadyFinalized

def __generate_key(password):
    backend = default_backend()
    salt_file = open('salt.hex', 'rb')
    salt = salt_file.read()
    # derive
    kdf = PBKDF2HMAC(
     algorithm=hashes.SHA1(),
     length=32,
     salt=salt,
     iterations=100000,
     backend=backend
    )
    salt_file.close()
    return kdf.derive(password)

def __verify(password, key):
    backend = default_backend()
    salt_file = open('salt.hex', 'rb')
    salt = salt_file.read()
    # verify
    kdf = PBKDF2HMAC(
     algorithm=hashes.SHA1(),
     length=32,
     salt=salt,
     iterations=100000,
     backend=backend
    )
    salt_file.close()
    try:
        kdf.verify(password, key)
    except:
        return False

    return True

def store_key(key, keystore_file, master_password):
    """Encrypts file with the given password using RC4"""

    if(type(master_password) is str):
        master_password = str.encode(master_password)

    cipher = Cipher(algorithms.ARC4(master_password), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    ct = encryptor.update(key)
    keystore_file.write(ct)

def load_key(keystore_file, master_password):
    """Decrypts file with the given password using RC4"""

    if(type(master_password) is str):
        master_password = str.encode(master_password)

    cipher = Cipher(algorithms.ARC4(master_password), None, backend=default_backend())
    decryptor = cipher.decryptor()

    ct = keystore_file.read()

    dt = decryptor.update(ct)
    return dt

def store_password(password, keystore_file_name, master_password):
    key = __generate_key(password)
    keystore_file = open(keystore_file_name, 'wb')
    store_key(key, keystore_file, master_password)
    keystore_file.close()

def verify_key(rec_key, keystore_file_name, master_password):
    keystore_file = open(keystore_file_name, 'rb')
    good_key = load_key(keystore_file, master_password)
    keystore_file.close()
    return __verify(rec_key, good_key)
