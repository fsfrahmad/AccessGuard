from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import os

def generate_aes_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key, salt

def encrypt_message(message: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    encrypted_data = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(encrypted_message: str, key: bytes) -> str:
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')
