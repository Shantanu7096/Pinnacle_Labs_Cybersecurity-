import rsa

def generate_keys():
    (pubkey, privkey) = rsa.newkeys(512)
    return pubkey, privkey

def rsa_encrypt(msg, public_key):
    return rsa.encrypt(msg.encode('utf-8'), public_key)

def rsa_decrypt(enc_bytes, private_key):
    return rsa.decrypt(enc_bytes, private_key).decode('utf-8')