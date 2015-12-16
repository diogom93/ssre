import click
import socket
import sys
import ciphers
import mac
import os
import crypto as crypt
from sealed_object import SealedObject
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto
from cryptography import x509

@click.command(short_help = 'Start server on folder')
@click.argument('folder')
def server(folder):
    HOST = ''
    PORT = 4567

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #Create server socket
    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    #Start listening on socket
    s.listen(10)
    print('Server started ...')

    #Start upload counter
    counter = 0;

    #now keep talking with the client
    while 1:
        #wait for client - conn is input stream
        conn, addr = s.accept()

        #Increment counter
        counter += 1

        print("Accepted connection " + str(counter) + ".");

        # Load and send server certificate

        server_cert_file = open('server.cer', 'rb')
        server_cert = server_cert_file.read()
        server_cert_file.close()

        conn.send(bytes(server_cert))

        in_cert = conn.recv(2048)

        # Validate server certificate using CA certificate
        client_cert = x509.load_der_x509_certificate(in_cert, default_backend())

        ca_cert_file = open('ca.cer', 'rb')
        ca_cert = ca_cert_file.read()
        ca_cert_file.close()

        store = crypto.X509Store()

        store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, ca_cert))

        store_ctx = crypto.X509StoreContext(store, client_cert)

        if store_ctx.verify_certificate() != None:
            click.echo(click.style('Error validating client certificate', bold = True, fg = 'red'))
            return
        else:
            click.echo(click.style('Valid client certificate!', bold = True, fg = 'green'))

        client_public_key = client_cert.public_key()

        private_key_file = open('server.pk8', 'rb')
        private_key = private_key_file.read()
        private_key_file.close()

        private_key = load_der_private_key(private_key, password=None, backend=default_backend())

        #accept session key
        csk = conn.recv(512)

        #unseal session key
        so = SealedObject()
        sk = so.unseal_asym(csk, private_key)

        challenge = os.urandom(32)

        conn.send(challenge)

        signature = conn.recv(512)

        verifier = client_public_key.verifier(signature, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        verifier.update(challenge)

        try:
            verifier.verify()
        except InvalidKey:
            click.echo(click.style('Error verifying signature!', bold = True, fg = 'red'))
            return

        #Open file to write to
        f = open(folder + "/" + str(counter), 'wb')

        sess_k = sk[0:16]
        mac_k  = sk[16:32]

        hmac = mac.MAC(mac_k)

        crypt.decrypt_AES_with_key_mac(conn, f, sess_k, hmac)
        f.close()
        print("Closed connection.")

    s.close()


if __name__ == '__main__':
    server()
