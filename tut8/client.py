import os
import click
import socket
import time
import ciphers, packet, mac
from sealed_object import SealedObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidKey
from OpenSSL import crypto
from cryptography import x509

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

    in_cert = s.recv(2048)

    # Validate server certificate using CA certificate
    server_cert = x509.load_der_x509_certificate(in_cert, default_backend())

    ca_cert_file = open('ca.cer', 'rb')
    ca_cert = ca_cert_file.read()
    ca_cert_file.close()

    store = crypto.X509Store()

    store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, ca_cert))

    store_ctx = crypto.X509StoreContext(store, server_cert)

    if store_ctx.verify_certificate() != None:
        click.echo(click.style('Error validating server certificate', bold = True, fg = 'red'))
        return
    else:
        click.echo(click.style('Valid server certificate!', bold = True, fg = 'green'))

    server_public_key = server_cert.public_key()

    client_cert_file = open('client.cer', 'rb')
    client_cert = client_cert_file.read()
    client_cert_file.close()

    s.send(client_cert)

    sk = os.urandom(32)
    sk1 = sk[0:16]
    sk2 = sk[16:32]

    so = SealedObject()
    csk = so.seal_asym(sk, server_public_key)
    s.sendall(csk)

    challenge = s.recv(32)

    private_key_file = open('client.pk8', 'rb')
    private_key = private_key_file.read()
    private_key_file.close()

    private_key = load_der_private_key(private_key, password=None, backend=default_backend())

    signer = private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    signer.update(challenge)
    signature = signer.finalize()

    s.send(signature)

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
