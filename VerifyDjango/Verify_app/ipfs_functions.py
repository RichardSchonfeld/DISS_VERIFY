import requests
import ast
from .encryption_utils import decrypt_with_shares

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