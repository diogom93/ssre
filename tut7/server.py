
import click
import socket
import sys
import ciphers
import mac
import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import crypto

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

        print("Accepted connection "+str(counter)+".");

        #negotiate private keypair
        keyfile = open('keypair_server.xml', 'r')
        sigfile = open('signature_server.sig', 'rb')
        signature = sigfile.read()
        tree = ET.parse(keyfile)
        root = tree.getroot()

        pr_k_pem = root.findtext('private_key')
        pu_k_pem = root.findtext('public_key')
        rsa_private_key = serialization.load_pem_private_key(pr_k_pem.encode(), password=None, backend=default_backend())
        #rsa_public_key = serialization.load_pem_public_key(pu_k_pem.encode(), backend=default_backend())

        sk = crypto.negotiate_asymmetric_session_key(conn, rsa_private_key, pu_k_pem, signature)

        #Open file to write to
        f = open(folder+"/"+str(counter), 'wb')

        sess_k = sk[0:16]
        mac_k  = sk[16:32]

        hmac = mac.MAC(mac_k)

        crypto.decrypt_AES_with_key_mac(conn, f, sess_k, hmac)
        f.close()
        print("Closed connection.")

    s.close()


if __name__ == '__main__':
    server()
