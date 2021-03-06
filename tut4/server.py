
import click
import socket
import sys
import crypto
import sealed_object

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

        #Open file to write to
        f = open(folder+"/"+str(counter), 'wb')

        sk = crypto.accept_session_key(conn, 'enc_key.store')

        crypto.decrypt_AES_with_key(conn, f, sk)

        f.close()
        print("Closed connection.")

    s.close()


if __name__ == '__main__':
    server()
