import click
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

@click.command()
@click.argument('filename', type = click.File('rb'))
def cli(filename):
    """Send file over to server"""
    s = socket.socket()

    host = '172.30.7.187'
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

    key = open("key.txt", "rb").read(16)
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt)

    s.send(ct)
    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
