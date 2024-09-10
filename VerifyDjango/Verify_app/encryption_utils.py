import base64
import os
import json

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir


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

#### PASSWORDS IN DJANGO DEFAULTED TO PBKDF2 REMOVE DERIVE_KEY AND EXTEND ####

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


# Function to encrypt data and generate Shamir's Secret Shares
def encrypt_and_split(data):
    # Generate AES key
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')

    # Generate Shamir's Secret Shares (2-of-3 scheme)
    shares = Shamir.split(2, 3, key)

    return encrypted_data, shares


def encrypt_certificate(certificate_data, encryption_key):
    """Encrypts the certificate data using AES."""
    iv = os.urandom(16)  # 16-byte IV for AES
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(certificate_data) + encryptor.finalize()
    return iv + encrypted_data  # Return IV and encrypted data together


# Function to decrypt data using Shamir's Secret Shares
def decrypt_with_shares(encrypted_data, shares):
    key = Shamir.combine(shares)

    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:16]
    ct = encrypted_data_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    original_data = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

    return original_data

# Function to upload data to IPFS

def write_shares_to_local_file(shares):
    # Get the path to the user's desktop
    from django.conf import settings
    # Define the file name
    file_path = os.path.join(settings.BASE_DIR, "shamir_keys.txt")

    # Write the shares to the file
    with open(file_path, 'w') as file:
        file.write("Shamir Secret Shares:\n")
        for index, share in enumerate(shares, 1):
            file.write(f"Share {index}: {share}\n")

    print(f"Shamir keys have been written to {file_path}")


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_with_public_key(content: str, public_key_hex: str) -> bytes:
    # Convert the hex string to bytes
    public_key_bytes = bytes.fromhex(public_key_hex[2:])

    # Load the public key from bytes (assuming the public key is in DER format)
    public_key = serialization.load_der_public_key(public_key_bytes)

    # Encrypt the content using the public key
    encrypted_data = public_key.encrypt(
        content.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data