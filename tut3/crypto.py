
import click
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def decrypt_RC4(connection, outfile):
    key = open("key.txt", 'rb').read(16)

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

def decrypt_AES(connection, outfile):
    key = open("key.txt", 'rb').read(16)

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
