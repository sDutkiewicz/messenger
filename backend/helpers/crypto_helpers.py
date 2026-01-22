"""Cryptography helpers for key generation and encryption"""
import base64
import re
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from argon2.low_level import hash_secret_raw, Type
from constants import MIN_PASSWORD_LENGTH


def is_strong_password(password):
    """Validate password: 12+ chars, 1 uppercase, 1 lowercase, 1 digit"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True


def generate_rsa_keypair():
    """Generate RSA 2048-bit key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return public_pem, private_pem


def encrypt_private_key(private_key_pem, password, salt):
    """Encrypt private key using Argon2id key derivation"""
    # Derive encryption key from password
    key_material = hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    
    # Encrypt with Fernet
    key = base64.urlsafe_b64encode(key_material)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(private_key_pem.encode())
    
    return encrypted.decode('utf-8')


def decrypt_private_key(encrypted_key_str, password, salt):
    """Decrypt private key using Argon2id key derivation"""
    try:
        # Derive decryption key from password
        key_material = hash_secret_raw(
            password.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        
        # Decrypt with Fernet
        key = base64.urlsafe_b64encode(key_material)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_key_str.encode())
        
        return decrypted.decode('utf-8')
    except Exception:
        return None

def encrypt_totp_secret(totp_secret, secret_key, salt):
    """Encrypt TOTP secret using Argon2id key derivation from server secret"""
    # Derive encryption key from server secret + salt
    key_material = hash_secret_raw(
        secret_key.encode(),
        salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    
    # Encrypt with Fernet
    key = base64.urlsafe_b64encode(key_material)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(totp_secret.encode())
    
    return encrypted.decode('utf-8')


def decrypt_totp_secret(encrypted_totp_str, secret_key, salt):
    """Decrypt TOTP secret using Argon2id key derivation from server secret"""
    try:
        # Derive decryption key from server secret + salt
        key_material = hash_secret_raw(
            secret_key.encode(),
            salt,
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        
        # Decrypt with Fernet
        key = base64.urlsafe_b64encode(key_material)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_totp_str.encode())
        
        return decrypted.decode('utf-8')
    except Exception:
        return None