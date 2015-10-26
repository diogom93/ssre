
import click
from keystore_new import *
import os
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

modes_ls = dict(
    CBC = modes.CBC
)

def decrypt_RC4(connection, outfile):

    ks = KeyStore('enc_key.store', os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)[0:15]

    print(key)

    cipher = Cipher(algorithms.ARC4(key), None, backend=default_backend())
    decryptor = cipher.decryptor()

    ct = b""
    while True:
        chunk = connection.recv(50)
        if not chunk:
            break
        ct += chunk

    dt = decryptor.update(ct)
    outfile.write(dt)

    click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))

def decrypt_AES(connection, outfile, keystore, mode_name='CBC'):
    iv  = open("iv.txt", 'rb').read(16)

    ks = KeyStore(keystore, os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)

    mode_ = modes_ls[mode_name](iv)

    cipher = Cipher(algorithms.AES(key), mode_, backend=default_backend())
    decryptor = cipher.decryptor()

    ct = b""
    while True:
        chunk = connection.recv(50)
        if not chunk:
            break
        ct += chunk

    dt = decryptor.update(ct)
    outfile.write(dt)

    click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))

def accept_session_key(connection, keystore, mode_name='CBC'):
    iv  = open("iv.txt", 'rb').read(16)

    ks = KeyStore(keystore, os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)


    click.echo(click.style('DEBUG : Decrypting session key with keystore key: %s' % key, bold = True, fg = 'yellow'))

    mode_ = modes_ls[mode_name](iv)

    ct = b""
    while True:
        chunk = connection.recv(50)
        if not chunk:
            break
        ct += chunk

    cipher = Cipher(algorithms.AES(key), mode_, backend=default_backend())
    so = SealedObject()
    sk = so.unseal(ct, cipher)
    click.echo(click.style('DEBUG : Obtained session key: %s' % sk, bold = True, fg = 'yellow'))
    #click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))
    return sk

def decrypt_AES_with_key(connection, outfile, key, mode_name='CBC'):
    iv  = open("iv.txt", 'rb').read(16)

    mode_ = modes_ls[mode_name](iv)

    click.echo(click.style('DEBUG : Decrypting with key %s' % key, bold = True, fg = 'yellow'))

    cipher = Cipher(algorithms.AES(key), mode_, backend=default_backend())
    decryptor = cipher.decryptor()

    ct = b""
    while True:
        chunk = connection.recv(50)
        if not chunk:
            break
        ct += chunk

    dt = decryptor.update(ct)
    outfile.write(dt)

    click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))
