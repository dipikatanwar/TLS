import socket
from OpenSSL import crypto
import json
from datetime import datetime
import secrets
import rsa
import zlib
import hashlib
from utility import utility

IP="localhost"
PORT=4455
ADDR=(IP,PORT)
CA_PORT=9999
CA_ADDR=(IP,CA_PORT)
FORMAT="utf-8"
SIZE=1024
VER = "2.0"
SESSION = '1'
cert = crypto.X509()
client_cert = crypto.X509()
keyexchange = 'RSA_AES'
RSA_PRIVATE_KEY = 'xx'
AES_key='xx'
hash_algo='SHA256'
iv = ''
def getCertificate():
    global cert
    print("Get certificate from TTP")
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, SIZE)
    private=crypto.dump_privatekey(crypto.FILETYPE_PEM,k)
    public=crypto.dump_publickey(crypto.FILETYPE_PEM,k)

    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.connect(CA_ADDR)
    key=public.decode('utf8').replace("'", '"')
    msg = {
        'name':'myserver',
        'public_key': key
    }
    msg=json.dumps(msg, indent = 2)
    server.send(msg.encode(FORMAT))
    cert=server.recv(SIZE).decode(FORMAT)
    print("Server certificate received From TTP: \n")
    print(cert)
    #print("-----------------------------------------------")

def server_hello(conn):
    global SESSION
    global hash_algo
    msg=json.loads(conn.recv(SIZE).decode(FORMAT))
    print("Client Hello Message:\n")
    print(msg)
    msg['version'] = str(min(float(VER),float(msg['version'])))
    msg['random'] = [secrets.randbits(28*8),str(datetime.now().timestamp())]
    if msg['sessionId'] == '0':
        msg['sessionId'] = str(int(SESSION)+1)
        SESSION=msg['sessionId']
    msg['cipherSuite']['keyexchange'] = msg['cipherSuite']['keyexchange'][0]
    msg['cipherSuite']['algo'] = msg['cipherSuite']['algo'][0]
    msg['compressionMethod'] = msg['compressionMethod'][0]
    msg=json.dumps(msg, indent = 5)
    conn.send(msg.encode(FORMAT))
    print("Server hello End")
    

def certificate_message(conn):
    global cert
    conn.send(cert.encode(FORMAT))
    print("Server certificate send")
    #print(cert)
    pass

def keyexchange_message(conn):
    global RSA_PRIVATE_KEY
    print("server public key send for key exchange")
    publicKey, privateKey = rsa.newkeys(512)
    RSA_PRIVATE_KEY=privateKey.save_pkcs1().decode().encode(FORMAT)
    conn.send(publicKey.save_pkcs1().decode().encode(FORMAT))

def server_hello_done(conn):
    print("Start Hello Done")
    msg='HELLO_DONE'
    conn.send(msg.encode(FORMAT))

def certificate(conn):
    global client_cert
    client_cert = conn.recv(SIZE).decode(FORMAT)
    print("Client certificate received")

def client_key_exchange(conn):
    global AES_key
    global RSA_PRIVATE_KEY
    key = conn.recv(SIZE).decode(FORMAT)
    print("Secret key received from client")
    RSA_PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(RSA_PRIVATE_KEY)
    #AES_key = rsa.decrypt(AES_key,RSA_PRIVATE_KEY.encode(FORMAT))
    #print(AES_key)

def tlsHandshake(conn):
    print("TLS Handshake begins at server")
    server_hello(conn)
    certificate_message(conn)
    
    asym,sym = keyexchange.split('_')
    if(asym == 'RSA'):
        keyexchange_message(conn)
    
    server_hello_done(conn)

    certificate(conn)
    client_key_exchange(conn)
    msg=conn.recv(SIZE).decode(FORMAT)
    if(msg == 'FINISHED'):
        return 'success'
    else:
        return 'fail'

def tlsRecord(conn):
    global hash_algo
    print("TLS Record begins at server")
    msg='The OTP for transferring Rs 100000 to your friend account is 256345'
    fragments = [msg[i:i+4] for i in range(0, len(msg), 4)]
    #fragments = msg.split(" ")
    # print(fragments)
    # print(len(fragments))

    # for x in fragments:
    #     if(hash_algo =='SHA256'):
    #         message_digest=hashlib.sha256(x.encode('utf-8')).hexdigest()
    #         data = {
    #             'header':'SSL_HEADER',
    #             'msg': x,
    #             'mac': str(message_digest)
    #             }
    #         datastr = json.dumps(data)
    #         enc=utility.encrypt(datastr,AES_key)
    #         #conn.send(enc)
    
    conn.send(msg.encode(FORMAT))

    conn.close()
    print("disconnected")

def main():
    print("Server starts")
    getCertificate()
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    while True:
        conn,addr= server.accept()
        print("Client connected")
        if tlsHandshake(conn)=='success':
            print("TLS handshaking success")
            tlsRecord(conn)
        else: print("TLS handshake fail")


if __name__ == "__main__":
    main()
