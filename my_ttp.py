import socket
from datetime import datetime
from OpenSSL import crypto
import json

IP="localhost"
CA_PORT=9999
ADDR=(IP,CA_PORT)
FORMAT="utf-8"
SIZE=1024

def generateCertificate(conn,subject_name,subject_publickey):
    pass
    print(subject_name)
    print(subject_publickey)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_DSA, 4096)
    cert = crypto.X509()
    cert.set_version(1)
    cert.set_serial_number(1)
    issuer = cert.get_subject()
    issuer.commonName='myttp'
    cert.set_issuer(issuer)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.get_subject().commonName = subject_name
    subject_key=crypto.load_publickey(crypto.FILETYPE_PEM,subject_publickey)
    cert.set_pubkey(subject_key)
    cert.sign(k, 'sha256')
    conn.send(bytes(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)))
#    with open(subject_name + ".crt", "wt") as f:
#        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

def main():
    ttp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ttp.bind(ADDR)
    ttp.listen(5)
    print("Trusted Third Party listening")
    while True:
        conn,addr= ttp.accept()
        request=json.loads(conn.recv(SIZE).decode(FORMAT))
        generateCertificate(conn,request['name'],request['public_key'])
        conn.close()

if __name__ == "__main__":
    main()