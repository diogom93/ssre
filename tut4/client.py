import os
import click
import socket
import time
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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

    ks = KeyStore('enc_key.store', os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)

    sk = os.urandom(16)

    so = SealedObject()
    cipher = Cipher(algorithms.AES(key), mode=modes.CFB8(open('iv.txt', 'rb').read(16)), backend=default_backend())
    csk = so.seal(sk, cipher)
    s.sendall(csk)

    #time.sleep(1)
    s.recv(512)

    cipher = Cipher(algorithms.AES(sk), mode=modes.CFB8(open('iv.txt', 'rb').read(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()

    s.send(ct)
    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
