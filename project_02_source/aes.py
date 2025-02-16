# To implement AES-GCM 128 bit encryption and decryption on files for the client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def encrypt_bytes(bytes: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    tag = os.urandom(16)
    return nonce + tag + aesgcm.encrypt(nonce, bytes, tag)

def decrypt_bytes(bytes: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = bytes[:12]
    tag = bytes[12:28]
    ciphertext = bytes[28:]
    return aesgcm.decrypt(nonce, ciphertext, tag)

def file_to_encrypted_base64(file_path: str, key: bytes) -> str:
    with open(file_path, "rb") as file:
        return base64.b64encode(encrypt_bytes(file.read(), key)).decode()

def encrypted_base64_to_bytes(encrypted_base64: str, key: bytes) -> bytes:
    return decrypt_bytes(base64.b64decode(encrypted_base64), key)

def encrypted_base64_to_file(encrypted_base64: str, key: bytes, file_path: str) -> None:
    with open(file_path, "wb") as file:
        file.write(encrypted_base64_to_bytes(encrypted_base64, key))
