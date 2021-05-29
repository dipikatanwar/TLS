import socket
import json
from datetime import datetime
import secrets
from OpenSSL import crypto
from cryptography.fernet import Fernet
import os
import rsa
import hashlib
from utility import utility

IP="localhost"
PORT=4455
ADDR=(IP,PORT)
CA_PORT=9999
CA_ADDR=(IP,CA_PORT)
FORMAT="utf-8"
SIZE=1024
VER="3.0"
cert = crypto.X509()
server_cert = crypto.X509()
keyexchange= 'RSA_AES'
secret_key = 'xx'

def getCertificate():
    print("Get certificate from TTP")
    global cert
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    private=crypto.dump_privatekey(crypto.FILETYPE_PEM,k)
    public=crypto.dump_publickey(crypto.FILETYPE_PEM,k)
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect(CA_ADDR)
    key=public.decode('utf8').replace("'", '"')
    msg = {
        'name':'myclient',
        'public_key': key
    }
    msg=json.dumps(msg, indent = 2)
    client.send(msg.encode(FORMAT))
    cert=client.recv(SIZE).decode(FORMAT)
    print("Client certificate from TTP: ")
    print(cert)

def client_hello(client):
    global keyexchange
    msg = {
        "version":VER,
        "random": [secrets.randbits(28*8), str(datetime.now().timestamp())],
        "sessionId":"0",
        "cipherSuite": { 'keyexchange':['RSA_AES','ECDSA_AES','RSA_CHACHA20','ECDSA_CHACHA20'], 'algo': ['SHA256','SHA384']},
        "compressionMethod":['zip','tar']
    }
    msg=json.dumps(msg, indent = 5)
    client.send(msg.encode(FORMAT))
    msg=json.loads(client.recv(SIZE).decode(FORMAT))
    cipherSuite = msg['cipherSuite']
    keyexchange=cipherSuite['keyexchange']
    print("Server Hello Message \n")
    print(msg)
    return


def certificate_message(client):
    global server_cert
    server_cert = client.recv(SIZE).decode(FORMAT)
    print("Server certificate received")
    #print(server_cert)
    #TO DO

def certificate_request(client):
    certreq = json.loads(client.recv(SIZE).decode(FORMAT))
    return certreq


def sendCertificate(client):
    print("send client certificate")
    global cert
    client.send(cert.encode(FORMAT))

def client_key_exchange(client,server_pub):
    #global secret_key
    print("Client Key exchange for exchanging secret key")
    key = Fernet.generate_key()
    asym,sym = keyexchange.split('_')
    print(key)
    if(asym == 'RSA'):
        server_pub = rsa.PublicKey.load_pkcs1(server_pub)
        print(server_pub)
        encrypted_key = rsa.encrypt(key,server_pub)
        print(encrypted_key)
        client.send(str(encrypted_key).encode(FORMAT))

def tlsHandshake(client):
    print("TLS Handshake begins at client")
    client_hello(client)

    certificate_message(client)
    server_pub=client.recv(SIZE)
    if(client.recv(SIZE).decode(FORMAT) == 'HELLO_DONE'):
        print("Successfully received hello Done message")
        sendCertificate(client)
        print("Successfully send certificate to server")
        client_key_exchange(client,server_pub)
    #   certificate_verify(conn)
        msg='FINISHED'
        client.send(msg.encode(FORMAT))
        return 'success'
    return 'fail'

def tlsRecord(client):
    global secret_key
    print("TLS Record begins at client")
    
    # data = ''
    # while True:
    #     r=client.recv(SIZE)
    #     if (len(r) == 0):
    #         break
    #     y=utility.decrypt(r,secret_key)
    #     print(y)
    data=client.recv(SIZE).decode(FORMAT)
    print(data)            


def main():
    print("Client starts")
    getCertificate()
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    client.connect(ADDR)
    if tlsHandshake(client)=='success':
        print("TLS handshaking success")
        tlsRecord(client)
    else:
        print("TLS handshaking fail")


if __name__ == "__main__":
    main()