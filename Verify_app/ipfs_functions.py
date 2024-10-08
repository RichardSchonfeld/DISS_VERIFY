import requests
import ast

from django.conf import settings
from django.http import JsonResponse

from .encryption_utils import decrypt_with_shares, decrypt_with_shares_file, encrypt_shamir_key, decrypt_shamir_key
from .forms import get_user_by_address
from .models import KeyFragment


def upload_to_ipfs(encrypted_data):
    #ipfs_url = "http://127.0.0.1:5001/api/v0/add"
    #files = {'file': ('encrypted_data.txt', encrypted_data)}

    #ipfs_url = "https://api.filebase.io/v1/ipfs/pins"
    #headers = {
    #    'Authorization': 'Bearer RDAyNUI0NTNERTZENjhGREJERTk6TE1yamVKZEVhU2lzbncySnBQSEdjZGlVanpMVkpDanV2SjBwRmczbzp2ZXJpZnlpbw==',
    #    'Accept': 'application/json'
    #}

    ipfs_url = settings.IPFS_PIN_ENDPOINT

    headers = {
        "Authorization": f"Bearer {settings.PINATA_JWT}"
    }

    files = {'file': ('encrypted_data.txt', encrypted_data)}
    response = requests.post(ipfs_url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()['IpfsHash']
    else:
        raise Exception("Failed to upload to IPFS")


def upload_ipfs_file(file_bytes):
    ipfs_url = settings.IPFS_PIN_ENDPOINT

    headers = {
        "Authorization": f"Bearer {settings.PINATA_JWT}"
    }

    # Create a file-like object from the bytes (the file must have a name for the IPFS API to accept it)
    files = {'file': ('encrypted_certificate.pdf', file_bytes)}

    # Send the file to IPFS
    response = requests.post(ipfs_url, headers=headers, files=files)

    if response.status_code == 200:
        ipfs_hash = response.json()['IpfsHash']
        return ipfs_hash
    else:
        raise Exception(f"Failed to upload file to IPFS. Status code: {response.status_code}")


import hashlib
import multihash
from base58 import b58encode

import hashlib
import multihash
from base58 import b58encode

import hashlib
import multihash
import base64
import base58

def predetermine_ipfs_hash(content: str) -> str:
    # Convert the input string to bytes
    data_bytes = content.encode('utf-8')

    # Step 1: Hash the data using SHA-256
    sha256_hash = hashlib.sha256(data_bytes).digest()

    # Step 2: Wrap the hash in a multihash (CIDv0 uses SHA-256 multihash)
    mh = multihash.encode(sha256_hash, 'sha2-256')

    # Step 3: CIDv0 is Base58 encoded (no CID version prefix)
    cid_v0 = base58.b58encode(mh).decode('utf-8')

    return cid_v0
def predetermine_ipfs_hash_dep(content: str) -> str:
    # Convert the string to bytes (IPFS hashes byte data)
    content_bytes = content.encode('utf-8')

    # Step 1: Generate SHA-256 hash of the content
    sha256_hash = hashlib.sha256(content_bytes).digest()

    # Step 2: Wrap it in a multihash (to create the CID)
    mh = multihash.encode(sha256_hash, 'sha2-256')

    # Step 3: Convert it to base58 format (CID v0)
    cid = b58encode(mh).decode('utf-8')
    return cid

def get_decrypted_data_from_ipfs(ipfs_hash, user):
    """
    Retrieve and decrypt data from IPFS using the user's key fragment and the server's key fragment.

    Args:
        ipfs_hash (str): The IPFS hash of the encrypted data.
        user (CustomUser): The user requesting the data.

    Returns:
        str: The decrypted data if successful, or None if any part of the process fails.
    """
    # Retrieve the encrypted data from IPFS
    ipfs_url = settings.IPFS_GET_ENDPOINT + ipfs_hash
    response = requests.get(ipfs_url)

    if response.status_code != 200:
        return None  # Handle the error by returning None or raising an exception

    encrypted_data = response.text

    # Get the user's key fragment
    user_fragment = KeyFragment.objects.filter(user=user, ipfs_hash=ipfs_hash).first()

    # Get the server's key fragment
    server_user = get_user_by_address(settings.SERVER_OP_ACC_ADDRESS)
    server_fragment = KeyFragment.objects.filter(user=server_user, ipfs_hash=ipfs_hash).first()

    if not user_fragment or not server_fragment:
        return None  # If fragments are missing, return None or handle accordingly

    # Combine fragments to decrypt
    shares = [decrypt_shamir_key(user_fragment.fragment), decrypt_shamir_key(server_fragment.fragment)]

    # Decrypt the data using the provided shares
    decrypted_data = decrypt_with_shares(encrypted_data, shares)

    return decrypted_data


def get_decrypted_data_from_ipfs_file(ipfs_hash, user):
    """
    Retrieve and decrypt data from IPFS using the user's key fragment and the server's key fragment.

    Args:
        ipfs_hash (str): The IPFS hash of the encrypted data.
        user (CustomUser): The user requesting the data.

    Returns:
        str: The decrypted data if successful, or None if any part of the process fails.
    """
    try:
        # 1. Retrieve the encrypted data from IPFS
        ipfs_url = settings.IPFS_GET_ENDPOINT + ipfs_hash
        response = requests.get(ipfs_url)

        if response.status_code != 200:
            return None  # Handle the error by returning None or raising an exception

        encrypted_data = response.content  # Retrieve the raw encrypted data

        # 2. Get the user's key fragment from the database
        user_fragment = KeyFragment.objects.filter(user=user, ipfs_hash=ipfs_hash).first()

        # 3. Get the server's key fragment from the database
        server_user = get_user_by_address(settings.SERVER_OP_ACC_ADDRESS)
        server_fragment = KeyFragment.objects.filter(user=server_user, ipfs_hash=ipfs_hash).first()

        if not user_fragment or not server_fragment:
            return JsonResponse({'error': 'Missing key fragments.'}, status=404)

        # 4. Combine the user's fragment and the server's fragment to decrypt the data
        shares = [decrypt_shamir_key(user_fragment.fragment), decrypt_shamir_key(server_fragment.fragment)]

        # 5. Decrypt the data using the provided shares
        decrypted_data = decrypt_with_shares_file(encrypted_data, shares)

        return decrypted_data

    except Exception as e:
        print(f"Error while decrypting data from IPFS: {str(e)}")
        return None

def check_if_pinned(cid):
    url = f'http://127.0.0.1:5001/api/v0/pin/ls?arg={cid}'
    response = requests.post(url)
    if response.status_code == 200:
        result = response.json()
        if cid in result.get('Keys', {}):
            print(f"File {cid} is pinned.")
        else:
            print(f"File {cid} is not pinned.")
    else:
        print(f"Error checking pin status: {response.status_code}, {response.text}")

def parse_json_decrypted_ipfs_data(decrypted_data):
    parts = decrypted_data.split(',')
    certificate_data = {
        "year_of_graduation": parts[0],
        "student_number": parts[1],
        "name": parts[2],
        "course_details": "Bachelor of Science in Computer Science",  # Example course details
        "issuer": "University Name",
        "date_of_issue": "2024-08-15"
    }
    return certificate_data


def unpin_from_pinata(ipfs_hash):
    url = f"https://api.pinata.cloud/pinning/unpin/{ipfs_hash}"

    headers = {
        "Authorization": f"Bearer {settings.PINATA_JWT}"
    }

    response = requests.delete(url, headers=headers)

    if response.status_code == 200:
        print("Successfully unpinned from Pinata.")
        return True
    else:
        print(f"Failed to unpin. Status code: {response.status_code}, Response: {response.text}")
        return False
