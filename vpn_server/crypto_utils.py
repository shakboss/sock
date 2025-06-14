from Crypto.Hash import SHA512, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import hmac

def generate_hmac(key: bytes, message: bytes) -> bytes:
    """Generate HMAC-SHA512 for message authentication"""
    return hmac.new(key, message, SHA512).digest()

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key using PBKDF2-HMAC-SHA512"""
    return PBKDF2(password, salt, 64, count=100000, hmac_hash_module=SHA512)

def encrypt_data(key: bytes, data: bytes) -> bytes:
    """Encrypt data using AES-256 in GCM mode"""
    cipher = AES.new(key[:32], AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    """Decrypt data using AES-256 in GCM mode"""
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key[:32], AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
