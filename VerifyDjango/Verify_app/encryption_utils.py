import base64
import os

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def derive_key_from_password(password, salt):
    hasher = PBKDF2PasswordHasher()
    derived_key = hasher.encode(password, salt, iterations=100000)
    return derived_key[:32]


def derive_key(password, salt):
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def encrypt_private_key(private_key, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_private_key = padder.update(private_key.encode()) + padder.finalize()

    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()

#    unpadder = padding.PKCS7(128).unpadder()
#    private_key = unpadder.update(padded_private_key) + unpadder.finalize()

    return  base64.b64encode(salt + iv + encrypted_private_key).decode()

def decrypt_private_key(encrypted_private_key, password):
    try:
        # Ensure correct padding - looks like this may not be necessary after some tinkering
        #encrypted_private_key = encrypted_private_key + '=' * (-len(encrypted_private_key) % 4)
        # Decode the base64-encoded string
        encrypted_private_key_bytes = base64.b64decode(encrypted_private_key)
        salt = encrypted_private_key_bytes[:16]  # Extract the first 16 bytes for the salt
        iv = encrypted_private_key_bytes[16:32]  # The next 16 bytes are the IV
        encrypted_data = encrypted_private_key_bytes[32:]  # The rest is the encrypted data

        # Derive the key using the provided password
        key = derive_key(password, salt)

        # Set up the cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and unpad the data
        padded_private_key = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        private_key = unpadder.update(padded_private_key) + unpadder.finalize()

        return private_key.decode('utf-8')
    except ValueError as ve:
        print(f"Decryption failed: {ve}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None



   # encrypted_private_key = encrypted_private_key + '=' * (-len(encrypted_private_key) % 4)