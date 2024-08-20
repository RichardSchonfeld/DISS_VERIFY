import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from eth_account.messages import encode_defunct
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

import requests
import ast
from web3 import Web3

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required

from .models import Claim, CustomUser, Certificate
from .forms import UserRegisterForm
from .ipfs_functions import get_ipfs_raw_data, parse_json_decrypted_ipfs_data, get_ipfs_decrypted_data

from .serializers import ClaimSerializer
from .eth_utils import create_claim, sign_claim, get_claim, fund_account

from .encryption_utils import encrypt_private_key, derive_key, decrypt_private_key, encrypt_and_split, decrypt_with_shares

from .exceptions import IPFSHashNotReturnedException


def index(request):
    return render(request, "index.html")

def login_view(request):
    return render(request, "login.html")


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            password = form.cleaned_data.get('password1')

            # Generate Ethereum account
            web3 = Web3()
            account = web3.eth.account.create()
            eth_address = account.address
            private_key = account._private_key.hex()
            print("PRIV KEY")
            print(private_key)
            # Encrypt the private key
            encrypted_private_key = encrypt_private_key(private_key, password)

            # Save the Ethereum address and encrypted private key to the user profile
            user.public_key = eth_address
            user.encrypted_private_key = encrypted_private_key
            user.save()

            fund_account(eth_address)

            login(request, user)
            return redirect('index')
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {'form': form})


@login_required
def recover_key(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user = request.user

        try:
            private_key = decrypt_private_key(user.encrypted_private_key, password)
            return render(request, 'recover_key.html', {'private_key': private_key})
        except Exception as e:
            return render(request, 'recover_key.html',
                          {'error': 'Invalid password or key could not be decrypted.'})

    return render(request, 'recover_key.html')

def transaction_confirmation(request):
    txn_hash = request.GET.get('txn_hash')
    return render(request, 'transaction_confirmation.html', {'txn_hash': txn_hash})

@login_required
def create_claim(request):
    if request.method == 'POST':
        year_of_graduation = request.POST['year_of_graduation']
        student_number = request.POST['student_number']
        full_name = request.POST['full_name']
        authority_public_key = request.POST['authority']

        import json
        # Load contract ABI and address
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']
        # Update the contract address here after migration
        contract_address = settings.CONTRACT_ADDRESS
        # Connect to local Ganache
        web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        # Initialize the contract
        verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

        # Encrypting data and getting key shares
        data = f"{year_of_graduation},{student_number},{full_name}"
        encrypted_data, shares = encrypt_and_split(data)

        print("SHARES")
        print(shares)

        # Uploading to IPFS and getting hash back
        from .web3_utils import upload_to_ipfs
        IPFS_hash = upload_to_ipfs(encrypted_data)

        print("IPFS_hash")
        print(IPFS_hash)

        user_profile = request.user

        # Save shamir fragment and IPFS hash to user profile
        from .forms import store_key_fragment
        store_key_fragment(user_profile, shares, IPFS_hash)

        # Determine the type of user
        #if isinstance(request.user, Web3Account):
        if user_profile.is_web3_user:
            # MetaMask user - Web3Account
            wallet_address = Web3.to_checksum_address(user_profile.public_key)

            # Prepare the transaction data for MetaMask
            transaction = verify_contract_instance.functions.createClaim(
                _requester=wallet_address,
                _authority=authority_public_key,
                _yearOfGraduation=year_of_graduation,
                _studentNumber=student_number,
                _fullName=full_name,
                _ipfsHash=IPFS_hash
            )
            context = {
                'transaction_data': transaction.build_transaction({
                    'chainId': 1337,  # Ganache
                    'gas': 300000,
                    'gasPrice': web3.to_wei('50', 'gwei'),
                    'nonce': web3.eth.get_transaction_count(wallet_address),
                    'from': wallet_address
                }),
                'use_metamask': True,
            }
            return render(request, 'submit_metamask.html', context)

        elif not user_profile.is_web3_user:

            wallet_address = Web3.to_checksum_address(user_profile.public_key)
            from .encryption_utils import decrypt_private_key

            private_key = decrypt_private_key(user_profile.encrypted_private_key, request.POST['password'])
            # Prepare the transaction data for Django user

            transaction = verify_contract_instance.functions.createClaim(
                _requester=wallet_address,
                _authority=authority_public_key,
                _yearOfGraduation=year_of_graduation,
                _studentNumber=student_number,
                _fullName=full_name,
                _ipfsHash=IPFS_hash
            )

            built_txn = transaction.build_transaction({
                'chainId': 1337,  # Ganache
                'gas': 300000,
                'gasPrice': web3.to_wei('50', 'gwei'),
                'nonce': web3.eth.get_transaction_count(wallet_address),
            })

            # Sign the transaction
            signed_txn = web3.eth.account.sign_transaction(built_txn, private_key)
            # Send the transaction
            txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

            context = {
                'txn_hash': txn_hash.hex(),
                'use_metamask': False,
            }

            return render(request, 'submit_confirmation.html', context)
    else:
        authorities = CustomUser.objects.filter(is_authority=True)
        return render(request, 'create_claim.html', {'authorities': authorities})

def view_claims(request):
    claims = get_claim()
    return render(request, 'view_claims.html', {'claims': claims})


#### DOUBLE CHECK IF CSRF EXEMPT IS OKAY HERE ####
@csrf_exempt
def sign_certificate(request):
    """Handle certificate signing and storage."""
    if request.method == 'POST':
        # Get POST data
        ipfs_hash = request.POST.get('ipfs_hash')
        share1 = request.POST.get('share1')
        share2 = request.POST.get('share2')

        try:
            # Decrypt IPFS data
            decrypted_data = get_ipfs_decrypted_data(ipfs_hash, share1, share2)

            # Parse the decrypted data to form the certificate structure
            certificate_data = parse_json_decrypted_ipfs_data(decrypted_data)

            # Prepare certificate data
            certificate_json = json.dumps(certificate_data)
            certificate_hash = hashlib.sha256(certificate_json.encode()).hexdigest()

            # Encode the hash as an Ethereum message
            message = encode_defunct(hexstr=certificate_hash)

            # Return the certificate data and the encoded message hash for signing
            return JsonResponse({
                "certificate_hash": Web3.to_hex(message.body),  # This ensures the correct Ethereum-prefixed hash
                "certificate_data": certificate_data
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    # Render the signing page for GET requests
    return render(request, 'sign_certificate.html')


@csrf_exempt
def store_signed_certificate(request):
    """Store the signed certificate in the database."""
    if request.method == 'POST':
        data = json.loads(request.body)
        certificate_data = data.get('certificate')
        certificate_hash = data.get('certificate_hash')
        signature = data.get('signature')
        user = request.user  # Assuming the user is authenticated

        # Save the signed certificate to the database
        certificate = Certificate.objects.create(
            user=user,
            certificate_data=certificate_data,
            certificate_hash=certificate_hash,
            signature=signature
        )

        return JsonResponse({'status': 'success', 'message': 'Certificate signed and stored successfully.', 'certificate_id': certificate.id})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)


def verify_signature(request):
    """Verify the signature of a certificate based on user input."""
    if request.method == 'POST':
        public_key = request.POST.get('public_key')
        certificate_hash = request.POST.get('certificate_hash')
        signature = request.POST.get('signature')

        try:
            # Create a Web3 instance
            web3 = Web3()

            # Encode the hash as an Ethereum message
            message = encode_defunct(hexstr=certificate_hash)

            # Recover the signer's address from the signature
            recovered_address = web3.eth.account.recover_message(
                message,
                signature=signature
            )

            # Check if the recovered address matches the provided public key
            if recovered_address.lower() == public_key.lower():
                return render(request, 'verify_signature.html', {
                    'result': 'Success: Signature is valid and matches the public key.',
                    'result_color': 'green'
                })
            else:
                return render(request, 'verify_signature.html', {
                    'result': 'Error: Signature does not match the public key.',
                    'result_color': 'red'
                })
        except Exception as e:
            return render(request, 'verify_signature.html', {
                'result': f'Error: {str(e)}',
                'result_color': 'red'
            })

    # Render the form page for GET requests
    return render(request, 'verify_signature.html')

class SignClaimView(APIView):
    def post(self, request):
        data = request.data
        claim_id = data.get('claim_id')
        authority_address = data.get('authority_address')

        tx_hash = sign_claim(claim_id, authority_address)

        claim = Claim.objects.get(id=claim_id)
        claim.signed = True
        claim.transaction_hash = tx_hash
        claim.save()

        return Response({"tx_hash": tx_hash}, status=status.HTTP_200_OK)


from django.shortcuts import render
from django.http import JsonResponse


def decrypt_claim(request):
    if request.method == 'POST':
        ipfs_hash = request.POST['ipfs_hash']
        share1 = request.POST['share1']
        share2 = request.POST['share2']

        # Retrieve the encrypted data from IPFS
        ipfs_url = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
        #response = requests.post(ipfs_url, params={'arg': ipfs_hash})
        response = requests.get(ipfs_url)

        if response.status_code == 200:
            encrypted_data = response.text
            share1 = ast.literal_eval(share1)
            share2 = ast.literal_eval(share2)
            shares = [share1, share2]

            # Decrypt the data using the provided shares
            decrypted_data = decrypt_with_shares(encrypted_data, shares)

            # Render the decrypted data on the page
            return render(request, 'decrypted_data.html', {'decrypted_data': decrypted_data})
        else:
            return render(request, 'decrypt_claim.html', {'error': 'Failed to retrieve data from IPFS'})

    return render(request, 'decrypt_claim.html')





class ListClaimsView(APIView):
    def get(self, request):
        claim = get_claim()
        return Response(claim)

    #queryset = Claim.objects.all()
    #serializer_class = ClaimSerializer