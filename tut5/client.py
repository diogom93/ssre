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

    pt = b""
    while True:
        chunk = filename.read(100)
        if not chunk:
            break
        pt += chunk

    ks = KeyStore('enc_key.store', os.path.abspath(''))
    key = str.encode(ks.keys['mother_base_key'].public_key)

    sk = os.urandom(32)
    sk1 = sk[0:16]
    sk2 = sk[16:32]

    so = SealedObject()
    cipher = ciphers.KeyAES(key, 'CFB8', False)

    mac_ = mac.MAC(sk2)

    ct = cipher.encrypt(sk)
    hmac = mac_.genMAC(ct, 0)
    iv = cipher.iv

    pkt = packet.Packet(ct, None, iv)
    csk = so.serialize(pkt)
    s.sendall(csk)

    s.recv(512)


    cipher = ciphers.KeyAES(sk1, 'CFB8', False)
    ct = cipher.encrypt(pt)
    
    s.send(ct)

    cipher = Cipher(algorithms.AES(sk1), mode=modes.CFB8(open('iv.txt', 'rb').read(16)), backend=default_backend())
    encryptor = cipher.encryptor()

    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
