import os
import click
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

@click.group()
def cli():
    """Network Security - Diogo Martins & João Meira"""

@cli.command(short_help = 'Generate key')
@click.argument('keyfile', type = click.File('wb'))
def genkey(keyfile):
    """Generates key for the encryption"""
    key = os.urandom(16)
    keyfile.write(key)

@cli.command(short_help = 'Encrypt file')
@click.argument('keyfile', type = click.File('rb'))
@click.argument('infile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def enc(keyfile, infile, outfile):
    """Encrypts file with the given key"""
    key = keyfile.read(16)

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    pt = b""
    while True:
        chunk = infile.read(1)
        if not chunk:
            break
        pt += chunk

    ct = encryptor.update(pt)
    outfile.write(ct)

@cli.command(short_help = 'Decrypt file')
@click.argument('keyfile', type = click.File('rb'))
@click.argument('infile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def dec(keyfile, infile, outfile):
    """Decrypts file with the given key"""
    key = keyfile.read(16)

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()

    ct = b""
    while True:
        chunk = infile.read(1)
        if not chunk:
            break
        ct += chunk

    dt = decryptor.update(ct)
    outfile.write(dt)

if __name__ == "__main__":
    cli()
