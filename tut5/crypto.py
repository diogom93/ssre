
import click, ciphers
from keystore_new import *
import os
from packet import Packet
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

modes_ls = dict(
    CBC = modes.CBC,
    CFB = modes.CFB8
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

def accept_session_packet(connection, keystore, mode_name='CFB'):
    iv  = open("iv.txt", 'rb').read(16)

    ks = KeyStore(keystore, os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)

    ct = b""
    #while True:
    chunk = connection.recv(512)
        #if not chunk:
            #break
    ct += chunk

    so = SealedObject()
    packet = so.deserialize(ct)

    cipher = ciphers.KeyAES(key, 'CFB8', False, packet.iv)
    sk = cipher.decrypt(packet.msg)

    #send private key
    connection.sendall(ct)


    #click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))
    return sk

def decrypt_AES_with_key_mac(connection, outfile, s_key, m_key, mode_name='CFB8'):

    ct = b""
    while True:
        chunk = connection.recv(100)
        if not chunk:
            break
        ct += chunk

    so = SealedObject()
    packet = so.deserialize(ct)

    #verify mac
    hmac = mac.MAC(m_key)
    if hmac.verMAC(packet.msg, 0, packet.mac):
        #reject
        click.echo(click.style('Decryptionphailed', bold = True, fg = 'red'))
    else:
        cipher = ciphers.KeyAES(s_key, 'CFB8', False, packet.iv)
        dt = cipher.decrypt(packet.msg)

        outfile.write(dt)

        click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))



def decrypt_AES_with_key(connection, outfile, key, mode_name='CFB'):
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

    dt = decryptor.update(ct) + decryptor.finalize()
    outfile.write(dt)

    click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))
