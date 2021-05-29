import base64
import hashlib
from OpenSSL import crypto
from Crypto.Cipher import AES 
from Crypto import Random

class utility():

    def pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(raw, AES_key):
        raw=utility.pad(raw)
        iv = Random.new().read(AES.block_size)
        key = hashlib.sha256(AES_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(enc, AES_key):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        key = hashlib.sha256(AES_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return utility.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
