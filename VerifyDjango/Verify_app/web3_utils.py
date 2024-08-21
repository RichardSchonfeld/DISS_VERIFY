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

@csrf_exempt
def verify_signature_login_metamask(request):
    """Verify the signature and authenticate the user."""
    data = json.loads(request.body)
    account = data.get('account')
    signature = data.get('signature')
    nonce = nonces.get(account)

    if not nonce:
        return JsonResponse({'error': 'Invalid nonce or account'}, status=400)

    # Clear nonce to prevent replay attacks
    del nonces[account]

    # Create the message that was signed
    message = f"Sign this nonce: {nonce}"

    # Encode the message to the format expected by Ethereum
    encoded_message = encode_defunct(text=message)

    # Recover the address that signed the message
    recovered_address = Web3().eth.account.recover_message(encoded_message, signature=signature)

    if recovered_address.lower() == account.lower():
        # User authenticated successfully, find or create user
        try:
            user = CustomUser.objects.get(public_key=account)
        except CustomUser.DoesNotExist:
            # Create a new Web3 user if it doesn't exist
            user = CustomUser(
                username=account,
                public_key=account,
                is_web3_user=True,
            )
            user.save()

        # Log the user in
        login(request, user)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Signature verification failed'}, status=400)



def upload_to_ipfs(encrypted_data):
    ipfs_url = "http://127.0.0.1:5001/api/v0/add"
    files = {'file': ('encrypted_data.txt', encrypted_data)}
    response = requests.post(ipfs_url, files=files)

    if response.status_code == 200:
        return response.json()['Hash']
    else:
        raise Exception("Failed to upload to IPFS")