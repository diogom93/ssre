import os, click, socket, mac, ciphers, packet
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

    ks = KeyStore('enc_key.store', os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)

    sk = os.urandom(32)
    sk1 = sk[0:16]
    sk2 = sk[16:32]

    cipher = ciphers.KeyAES(key, 'CFB8', False)
    ct = cipher.encrypt(sk)

    pkt = packet.Packet(ct, None, cipher.iv)

    so = SealedObject()
    csk = so.serialize(pkt)

    s.sendall(csk)
    s.recv(512)

    pt = b""
    while True:
        chunk = filename.read(100)
        if not chunk:
            break
        pt += chunk

    cipher = ciphers.KeyAES(sk1, 'CFB8', False)
    ct = cipher.encrypt(pt)

    hmac = mac.MAC(sk2)
    mac = hmac.genMAC(ct, 0)

    pkt = packet.Packet(ct, None, cipher.iv)

    so = SealedObject()
    csk = so.serialize(pkt)

    s.send(csk)

    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
