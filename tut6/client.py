import os
import click
import socket
import time
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from keystore_new import KeyStore

@click.command()
@click.argument('filename', type = click.File('rb'))
def cli(filename):
    """Send file over to server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 4567

    click.echo(click.style('Connecting...', bold = True, fg = 'yellow'))
    try:
        s.connect((host, port))
    except socket.error as msg:
        click.echo(click.style('Error connecting to server: ' + str(msg[1]), bold = True, fg = 'red'))

    pt = b""
    while True:
        chunk = filename.read(100)
        if not chunk:
            break
        pt += chunk

    pem = s.recv(2048)
    #click.echo(click.style('Client: public key = %s' % rsa_public_key, bold = True, fg = 'green'))

    rsa_public_key = serialization.load_pem_public_key(pem, backend=default_backend())

    sk = os.urandom(16)

    so = SealedObject()
    csk = so.seal_asym(sk, rsa_public_key)
    s.sendall(csk)

    cipher = Cipher(algorithms.AES(sk), mode=modes.CFB8(open('iv.txt', 'rb').read(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()

    s.send(ct)
    s.close()


    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
