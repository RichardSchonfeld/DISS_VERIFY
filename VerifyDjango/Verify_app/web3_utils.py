import json
import string
import random
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login
from django.contrib.auth.models import User
from web3 import Web3
from eth_account.messages import encode_defunct
from .models import CustomUser

# In-memory storage for nonces (need to move this for prod)
nonces = {}


def generate_nonce():
    """Generate a random nonce."""
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))


def get_nonce(request):
    """Generate and return a nonce associated with an Ethereum address."""
    address = request.GET.get('address')
    if not address:
        return JsonResponse({'error': 'Address is required'}, status=400)

    nonce = generate_nonce()
    nonces[address] = nonce
    return JsonResponse({'nonce': nonce})

def upload_to_ipfs(encrypted_data):
    ipfs_url = "http://127.0.0.1:5001/api/v0/add"
    files = {'file': ('encrypted_data.txt', encrypted_data)}
    response = requests.post(ipfs_url, files=files)

    if response.status_code == 200:
        return response.json()['Hash']
    else:
        raise Exception("Failed to upload to IPFS")