import os
import hmac
import hashlib
import base64
import json

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def encrypt_aes_gcm(plaintext, key):
    nonce = os.urandom(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    return json.dumps({
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
    })


def decrypt_aes_gcm(token, key):
    data = json.loads(token)
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    tag = base64.b64decode(data['tag'])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def compute_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(data, key, expected):
    actual = compute_hmac(data, key)
    return hmac.compare_digest(actual, expected)


def generate_rsa_keypair():
    k = RSA.generate(2048)
    return k.export_key().decode(), k.publickey().export_key().decode()


def sign_data(data, private_pem):
    key = RSA.import_key(private_pem)
    h = SHA256.new(data)
    sig = pkcs1_15.new(key).sign(h)
    return base64.b64encode(sig).decode()

def verify_signature(data, signature_b64, public_pem):
    try:
        key = RSA.import_key(public_pem)
        h = SHA256.new(data)
        pkcs1_15.new(key).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False
