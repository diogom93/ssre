import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
backend = default_backend()
salt_file = open('salt.hex', 'rb')
salt = salt_file.read
# derive
kdf = PBKDF2HMAC(
 algorithm=hashes.SHA256(),
 length=32,
 salt=salt,
 iterations=100000,
 backend=backend
)
key = kdf.derive(b"my great password")
# verify
kdf = PBKDF2HMAC(
 algorithm=hashes.SHA256(),
 length=32,
 salt=salt,
 iterations=100000,
 backend=backend
)
kdf.verify(b"my great password", key)

def derive(password):
    return kdf.derive(password)

def verify(password):
    return kdf.verify(b"my great password", key)
