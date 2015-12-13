import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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

@cli.command(short_help = "Sign")
@click.argument('keyfile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def certkeypair(keyfile, outfile):
    """
    Signs given Key Pair
    """

    tree = ET.parse(keyfile)
    root = tree.getroot()

    pr_k_pem = root.findtext('private_key')
    pu_k_pem = root.findtext('public_key')
    print(pr_k_pem)
    print(pu_k_pem)
    pr_k = serialization.load_pem_private_key(pr_k_pem.encode(), password=None, backend=default_backend())
    pu_k = serialization.load_pem_public_key(pu_k_pem.encode(), backend=default_backend())

if __name__ == "__main__":
    cli()
