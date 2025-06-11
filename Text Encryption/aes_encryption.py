from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(msg, key):
    key = key.encode('utf-8').ljust(16, b'0')[:16]  # 16 bytes for AES-128
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def aes_decrypt(enc, key):
    key = key.encode('utf-8').ljust(16, b'0')[:16]
    iv, ct = enc.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

enc = aes_encrypt("hello", "mysecretkey")
dec = aes_decrypt(enc, "mysecretkey")
print(dec)  # Should print "hello"