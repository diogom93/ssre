
import click, ciphers, mac
from keystore_new import *
import os
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def negotiate_asymmetric_session_key(connection, private_key, public_key):

    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    #send public key over network
    connection.sendall(pem)
    #accept session key
    csk = connection.recv(512)
    #unseal session key
    so = SealedObject()
    sk = so.unseal_asym(csk, private_key)

    return sk

def decrypt_AES_with_key_mac(connection, outfile, s_key, hmac):

    ct = b""
    while True:
        chunk = connection.recv(50)
        if not chunk:
            break
        ct += chunk

    so = SealedObject()
    packet = so.deserialize(ct)

    #verify mac
    if not hmac.verMAC(packet.msg, 0,  packet.mac):
        #reject
        click.echo(click.style('Decryptionphailed', bold = True, fg = 'red'))
    else:
        cipher = ciphers.KeyAES(s_key, 'CFB8', False, packet.iv)
        dt = cipher.decrypt(packet.msg)

        outfile.write(dt)

        click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))
