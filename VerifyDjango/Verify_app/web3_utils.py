import json
import string
import random
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login
from django.contrib.auth.models import User
from web3 import Web3
from eth_account.messages import encode_defunct
from .models import Web3Account, CustomUser

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
def verify_signature(request):
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
            eth_account = Web3Account.objects.get(public_key=account)
            user = eth_account.user
        except Web3Account.DoesNotExist:
            # Create a new user if it doesn't exist
            user = CustomUser(username=account)
            ### TEMPORARY - ACCOUNT REQUIRES FIX ###
            user.email = 'asdjkl@a.com'
            user.public_key = account
            ### END OF TEMP FIX ###

            user.save()
            eth_account = Web3Account(user=user, public_key=account)
            eth_account.save()

        # Log the user in
        login(request, user)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Signature verification failed'}, status=400)
