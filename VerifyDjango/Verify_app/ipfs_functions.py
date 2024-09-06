import requests
import ast

from django.conf import settings

from .encryption_utils import decrypt_with_shares
from .forms import get_user_by_address
from .models import KeyFragment


def get_ipfs_raw_data(ipfs_hash):
    """Retrieve encrypted data from IPFS."""
    ipfs_url = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
    try:
        response = requests.get(ipfs_url, timeout=10)  # Set a timeout for the request
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
        return response.text
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")  # Handle specific HTTP errors
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")  # Handle connection errors
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")  # Handle request timeouts
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")  # Handle any other request-related errors
    return None

def get_ipfs_decrypted_data(ipfs_hash, share1, share2):
    """Retrieve encrypted data from IPFS."""
    ipfs_url = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
    try:
        response = requests.get(ipfs_url, timeout=10)  # Set a timeout for the request
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)

        encrypted_data = response.text

        share1 = ast.literal_eval(share1)
        share2 = ast.literal_eval(share2)
        shares = [share1, share2]

        # Decrypt the data using the provided shares
        decrypted_data = decrypt_with_shares(encrypted_data, shares)
        return decrypted_data
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")  # Handle specific HTTP errors
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")  # Handle connection errors
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")  # Handle request timeouts
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")  # Handle any other request-related errors
    return None


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
    ipfs_url = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
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
    shares = [ast.literal_eval(user_fragment.fragment), ast.literal_eval(server_fragment.fragment)]

    # Decrypt the data using the provided shares
    decrypted_data = decrypt_with_shares(encrypted_data, shares)

    return decrypted_data


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