import os
import click
import socket
import time
import ciphers, packet, mac
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidKey

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

    r_pkt = s.recv(2048)
    #click.echo(click.style('Client: public key = %s' % rsa_public_key, bold = True, fg = 'green'))

    so = SealedObject()
    pkt = so.deserialize(r_pkt)

    signature = pkt.get_attribute('sig')
    pem = pkt.msg

    rsa_public_key = serialization.load_pem_public_key(pem.encode(), backend=default_backend()) #.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_bytes = rsa_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    verifier = rsa_public_key.verifier(signature, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    verifier.update(key_bytes)
    try:
        verifier.verify()
    except InvalidKey:
        click.echo(click.style('Error verifying key', bold = True, fg = 'red'))
        return



    sk = os.urandom(32)
    sk1 = sk[0:16]
    sk2 = sk[16:32]

    so = SealedObject()
    csk = so.seal_asym(sk, rsa_public_key)
    s.sendall(csk)

    cipher = ciphers.KeyAES(sk1, 'CFB8', False)
    ct = cipher.encrypt(pt)

    hmac = mac.MAC(sk2)
    mac1 = hmac.genMAC(ct, 0)

    pkt = packet.Packet(ct, mac1, cipher.iv)

    so = SealedObject()
    csk = so.serialize(pkt)

    s.send(csk)

    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
