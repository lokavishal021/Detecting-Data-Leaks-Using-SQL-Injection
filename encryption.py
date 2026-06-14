import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generate or load a system key
DEFAULT_SECRET = "cloud_secure_data_protection_system_sql_injection_key_2026"

def get_encryption_key(user_secret: str = None) -> bytes:
    """
    Derives a 256-bit key from a secret string using SHA-256.
    If no user_secret is provided, falls back to environment variable or standard key.
    """
    secret = user_secret or os.environ.get("AES_SECRET_KEY", DEFAULT_SECRET)
    return hashlib.sha256(secret.encode("utf-8")).digest()

def encrypt_data(plain_text: str, key: bytes) -> str:
    """
    Encrypts plain text using AES-256-GCM.
    Returns hex encoded representation of nonce + ciphertext.
    """
    if not plain_text:
        return ""
    
    # AESGCM takes 256-bit keys
    aesgcm = AESGCM(key)
    # Standard GCM nonce is 12 bytes
    nonce = os.urandom(12)
    
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    
    # Store nonce prepended to ciphertext
    payload = nonce + ciphertext
    return payload.hex()

def decrypt_data(cipher_hex: str, key: bytes) -> str:
    """
    Decrypts hex encoded cipher text using AES-256-GCM.
    """
    if not cipher_hex:
        return ""
    
    try:
        data = bytes.fromhex(cipher_hex)
        if len(data) < 12:
            return "[Error: Invalid encrypted format]"
        
        nonce = data[:12]
        ciphertext = data[12:]
        
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")
    except Exception as e:
        return f"[Decryption Failed: {str(e)}]"
