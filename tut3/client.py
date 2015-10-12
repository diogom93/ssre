import click
import socket

@click.command()
@click.argument('filename', type = click.File('rb'))
def cli(filename):
    """Send file over to server"""
    s = socket.socket()

    host = '172.30.7.187'
    port = 4567

    click.echo(click.style('Connecting...', bold = True, fg = 'yellow'))
    s.connect((host, port))

    while True:
        chunk = filename.read(100)
        if not chunk:
            break
        s.send(chunk)

    s.close()

    click.echo(click.style('File sent!', bold = True, fg = 'green'))

if __name__ == '__main__':
    cli()
