from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import zlib
import json
import os

def passwordToKey(password: str) -> bytes:
    key = hashlib.sha256(password.encode()).hexdigest()[:32].encode()
    return key

def encrypt(data: dict, password: str) -> bytes:
    compressed_data = zlib.compress(json.dumps(data).encode())
    key = passwordToKey(password)
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(compressed_data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + encrypted

def decrypt(data: bytes, password: str) -> dict:
    key = passwordToKey(password)
    iv = data[:16]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(data[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return json.loads(zlib.decompress(decrypted).decode())
