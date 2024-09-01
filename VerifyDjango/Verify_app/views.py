import hashlib
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from eth_account.messages import encode_defunct
from rest_framework.views import APIView
from rest_framework.response import Response

import requests
import ast
from web3 import Web3

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from .models import Claim, CustomUser, Certificate
from .forms import UserRegisterForm, store_key_fragment, get_user_by_address
from .ipfs_functions import get_ipfs_raw_data, parse_json_decrypted_ipfs_data, get_ipfs_decrypted_data
from .eth_utils import create_claim, sign_claim, get_claim, fund_account
from .encryption_utils import encrypt_private_key, derive_key, decrypt_private_key, encrypt_and_split, \
    decrypt_with_shares, encrypt_with_public_key
from .web3_utils import upload_to_ipfs


def index(request):
    return render(request, "index.html")

def login_view(request):
    return render(request, "login.html")


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.address = request.POST['address']
            user.encrypted_private_key = request.POST['encrypted_private_key']
            user.save()

            ### ----- TEMPORARY user fund initial ----- ###
            fund_account(user.address)
            ### ----- END TEMP ----- ###

            return redirect('index')
        else:
            # If the form is not valid, return the form with errors
            return render(request, 'register.html', {'form_errors': form.errors})
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {'form': form})


def transaction_confirmation(request):
    txn_hash = request.GET.get('txn_hash')
    return render(request, 'transaction_confirmation.html', {'txn_hash': txn_hash})

@login_required
@csrf_exempt
def create_claim(request):
    if request.method == 'POST':
        data = request.body.decode('utf-8')
        web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

        if 'signedTransaction' in data:
            # Django User Flow: Send the signed transaction to the blockchain
            try:
                data = json.loads(data)
                txn_hash = web3.eth.send_raw_transaction(data['signedTransaction'])
                return JsonResponse({'txn_hash': txn_hash.hex()})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

        elif 'txnHash' in data:
            # MetaMask User Flow: Transaction already sent, just log the transaction hash
            data = json.loads(data)
            txn_hash = data['txnHash']
            return JsonResponse({'txn_hash': txn_hash})

        else:
            # Handle claim creation and transaction preparation
            year_of_graduation = request.POST.get('year_of_graduation')
            student_number = request.POST.get('student_number')
            full_name = request.POST.get('full_name')
            authority_address = request.POST.get('authority')

            # Load the contract ABI and address
            with open('build/contracts/Verify.json') as f:
                contract_data = json.load(f)
                contract_abi = contract_data['abi']
            contract_address = settings.CONTRACT_ADDRESS
            verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

            # Encrypting data and getting key shares
            data = f"{year_of_graduation},{student_number},{full_name}"
            encrypted_data, shares = encrypt_and_split(data)

            user_profile = request.user
            # Uploading to IPFS and getting hash back
            IPFS_hash = upload_to_ipfs(encrypted_data)

            # Distributing keys
            store_key_fragment(user_profile, shares, IPFS_hash)

            # First the requester (claimant)
            #claimant_share = encrypt_with_public_key(repr(shares[0]), user_profile.public_key)
            # Then the server (Dapp)
            #server_share = encrypt_with_public_key(repr(shares[0]), settings.PUBLIC_KEY)
            # Finally the Authority
            #authority_share = encrypt_with_public_key(repr(shares[0]), authority_public_key)

            ### Above for encryption that needs resolution - TBI

            claimant_share = shares[0]
            server_share = shares[1]
            authority_share = shares[2]

            # Storing
            store_key_fragment(user_profile, claimant_share, IPFS_hash)

            server_user = get_user_by_address(settings.SERVER_OP_ACC_ADDRESS)
            store_key_fragment(server_user, server_share, IPFS_hash)

            authority_user = get_user_by_address(authority_address)
            store_key_fragment(authority_user, authority_share, IPFS_hash)

            wallet_address = Web3.to_checksum_address(user_profile.address)

            # Prepare the transaction data
            transaction = verify_contract_instance.functions.createClaim(
                _requester=wallet_address,
                _authority=authority_address,
                _yearOfGraduation=year_of_graduation,
                _studentNumber=student_number,
                _fullName=full_name,
                _ipfsHash=IPFS_hash
            ).build_transaction({
                'chainId': 1337,  # Ganache
                'gas': 500000,
                'gasPrice': web3.to_wei('50', 'gwei'),
                'nonce': web3.eth.get_transaction_count(wallet_address),
            })

            # Render the signing page with the transaction data
            context = {
                'transaction_data': json.dumps(transaction),
                'encrypted_private_key': user_profile.encrypted_private_key if not user_profile.is_web3_user else None,
            }
            return render(request, 'submit_claim.html', context)
    else:
        authorities = CustomUser.objects.filter(is_authority=True)
        return render(request, 'create_claim.html', {'authorities': authorities})

def view_claims(request):
    claims = get_claim()
    return render(request, 'view_claims.html', {'claims': claims})


#### DOUBLE CHECK IF CSRF EXEMPT IS OKAY HERE ####
@csrf_exempt
@login_required
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
    user = request.user
    context = {
        'is_web3_user': True
    }

    if not user.is_web3_user:
        context = {
            'encrypted_private_key': request.user.encrypted_private_key,
            'is_web3_user': False
        }
    return render(request, 'sign_certificate.html', context)


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
        address = request.POST.get('address')
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
            if recovered_address.lower() == address.lower():
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

from django.shortcuts import get_object_or_404
from .models import KeyFragment

def user_claims_view(request):
    user = request.user

    if user.is_authenticated:
        user_address = user.address  # Assuming you store user's Ethereum address in CustomUser model

        # Connect to Ethereum blockchain
        web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

        # Load the contract
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']

        contract_address = settings.CONTRACT_ADDRESS
        verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

        # Call the getClaimsByAddress function
        claim_ids = verify_contract_instance.functions.getClaimsByAddress(user_address).call()

        claims = []
        for claim_id in claim_ids:
            claim = verify_contract_instance.functions.getClaim(claim_id).call()
            claims.append({
                'claim_id': claim_id,
                'requester': claim[0],
                'authority': claim[1],
                'year_of_graduation': claim[2],
                'student_number': claim[3],
                'full_name': claim[4],
                'ipfs_hash': claim[5],
                'signed': claim[6],
            })

        return render(request, 'user_claims.html', {'claims': claims})
    else:
        return render(request, 'user_claims.html', {'error': 'User not authenticated'})

def decrypt_claim(request):
    if request.method == 'POST':
        ipfs_hash = request.POST['ipfs_hash']

        # Assume the user is the requester
        user_profile = request.user

        # Retrieve the encrypted data from IPFS
        ipfs_url = f"http://127.0.0.1:8080/ipfs/{ipfs_hash}"
        response = requests.get(ipfs_url)

        if response.status_code == 200:
            encrypted_data = response.text

            # Get the user's key fragment
            user_fragment = KeyFragment.objects.filter(user=request.user, ipfs_hash=ipfs_hash).first()

            # Get the server's key fragment
            server_user = get_user_by_address(settings.SERVER_OP_ACC_ADDRESS)
            server_fragment = KeyFragment.objects.filter(user=server_user, ipfs_hash=ipfs_hash).first()

            # Combine fragments to decrypt
            shares = [ast.literal_eval(user_fragment.fragment), ast.literal_eval(server_fragment.fragment)]

            # Decrypt the data using the provided shares
            decrypted_data = decrypt_with_shares(encrypted_data, shares)

            # Render the decrypted data on the page
            return render(request, 'decrypted_data.html', {'decrypted_data': decrypted_data})
        else:
            return render(request, 'decrypt_claim.html', {'error': 'Failed to retrieve data from IPFS'})

    return render(request, 'decrypt_claim.html')

def decrypt_claim_DEP(request):
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

            # FUTURE DECRYPTION WITH JS-FE PRIVATE KEY REQUIREMENT
                 # What worked:
                    # 1. use a = repr(share)
                    # 2. import ast; ast.literal_eval(a) to convert back to tuple original form
                    # 3. ???
                    # 4. Profit

            # Decrypt the data using the provided shares
            decrypted_data = decrypt_with_shares(encrypted_data, shares)

            # Render the decrypted data on the page
            return render(request, 'decrypted_data.html', {'decrypted_data': decrypted_data})
        else:
            return render(request, 'decrypt_claim.html', {'error': 'Failed to retrieve data from IPFS'})

    return render(request, 'decrypt_claim.html')


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



class ListClaimsView(APIView):
    def get(self, request):
        claim = get_claim()
        return Response(claim)
