import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import xml.dom.minidom
import base64
import click

@click.group()
def cli():
    """
    Network Security - Diogo Martins & João Meira
    """

@cli.command(short_help = "Generate key pair")
@click.argument('filename', type = click.File('w'))
def genkeypair(filename):
    """
    Generates Key Pair
    """

    doc = ET.Element("keypair")

    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    ET.SubElement(doc, "private_key", name="Generated RSA").text = rsa_private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()
    ET.SubElement(doc, "public_key", name="Derived RSA").text = rsa_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


    clean = xml.dom.minidom.parseString( ET.tostring(doc, 'utf-8') ).toprettyxml(indent="    ")

    filename.write(clean)

@cli.command(short_help = "Sign Public Key")
@click.argument('keyfile', type = click.File('r'))
@click.argument('outfile', type = click.File('wb'))
def certkeypair(keyfile, outfile):
    """
    Signs given Key Pair
    """

    tree = ET.parse(keyfile)
    root = tree.getroot()

    pr_k_pem = root.findtext('private_key')
    pu_k_pem = root.findtext('public_key')

    pr_k = serialization.load_pem_private_key(pr_k_pem.encode(), password=None, backend=default_backend())
    pu_k = serialization.load_pem_public_key(pu_k_pem.encode(), backend=default_backend()).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    signer = pr_k.signer( padding.PSS( mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    signer.update(pu_k)
    signature = signer.finalize()

    outfile.write(signature)

@cli.command(short_help = "Sign File")
@click.argument('keyfile', type = click.File('r'))
@click.argument('infile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def certfile(keyfile, infile, outfile):
    """
    Signs given Key Pair
    """

    tree = ET.parse(keyfile)
    root = tree.getroot()

    pr_k_pem = root.findtext('private_key')
    pu_k_pem = root.findtext('public_key')

    pr_k = serialization.load_pem_private_key(pr_k_pem.encode(), password=None, backend=default_backend())
    message = infile.read()

    signer = pr_k.signer( padding.PSS( mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    signer.update(message)
    signature = signer.finalize()

    outfile.write(signature)

if __name__ == "__main__":
    cli()
