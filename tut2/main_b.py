import os
import click
import rc4

@click.group()
def cli():
    """Network Security - Diogo Martins & João Meira"""

@cli.command(short_help = 'Generate key')
@click.argument('keyfile', type = click.File('wb'))
def genkey(keyfile):
    """Generates key for the encryption"""
    key = os.urandom(16)
    keyfile.write(key)

    click.echo(click.style('Keygen successful!', bold = True, fg = 'green'))

@cli.command(short_help = 'Encrypt file')
@click.argument('keyfile', type = click.File('rb'))
@click.argument('infile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def enc(keyfile, infile, outfile):
    """Encrypts file with the given key"""
    key = keyfile.read(16)

    pt = b""
    while True:
        chunk = infile.read(1)
        if not chunk:
            break
        pt += chunk

    ct = rc4.crypto(key, pt)
    outfile.write(ct)

    click.echo(click.style('Encryption successful!', bold = True, fg = 'green'))

@cli.command(short_help = 'Decrypt file')
@click.argument('keyfile', type = click.File('rb'))
@click.argument('infile', type = click.File('rb'))
@click.argument('outfile', type = click.File('wb'))
def dec(keyfile, infile, outfile):
    """Decrypts file with the given key"""
    key = keyfile.read(16)

    ct = b""
    while True:
        chunk = infile.read(1)
        if not chunk:
            break
        ct += chunk

    dt = rc4.crypto(key, ct)
    outfile.write(dt)

    click.echo(click.style('Decryption successful!', bold = True, fg = 'green'))

if __name__ == "__main__":
    cli()
