from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
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

from .models import Claim, CustomUser
from .forms import UserRegisterForm

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

#@csrf_exempt
"""def upload_ipfs_view(request):
    if request.method == 'POST':
        # Handle file upload
        uploaded_file = request.FILES.get('file')
        if uploaded_file:
            try:
                # Connect to IPFS running on localhost
                client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')

                # Add file to IPFS
                result = client.add(uploaded_file)
                cid = result['Hash']

                # Return the CID of the uploaded file
                return JsonResponse({'cid': cid})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({'error': 'No file provided'}, status=400)

    # For GET request, render the upload page
    return render(request, 'upload-ipfs.html')"""

@csrf_exempt
def upload_ipfs_view(request):
    """
        ------- ORIGINAL IMPLEMENTATION FOR INFURA -------
            --- may be useful if I migrate to have it all at once place ---
    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        endpoint = "https://ipfs.infura.io:5001/api/v0/add"
        api_key = settings.INFURA_API_KEY
        api_secret = settings.INFURA_API_SECRET
        if uploaded_file:
            try:
                files = {
                    'file': (uploaded_file.name, uploaded_file.read()),
                }

                response = requests.post(
                    endpoint,
                    files=files,
                    auth = (api_key, api_secret)
                )

                if response.status_code == 200:
                    result = response.json()
                    cid = result['Hash']
                    return JsonResponse({'cid': cid})
                else:
                    return JsonResponse({'error': response.text}, status=response.status_code)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({'error': 'No file provided'}, status=500)"""

    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        ipfs_url = "http://127.0.0.1:5001/api/v0"
        ipfs_endpoint_add = "/add"

        check_if_pinned("QmNnVARxwSwCiD5FT7f33cUN1ExtgxNwnk3vKcdyNiH5R9")

        if uploaded_file:
            files = {'file': uploaded_file}
            add_url = ipfs_url + ipfs_endpoint_add
            response = requests.post(add_url, files=files)

            if response.status_code == 200:
                result = response.json()
                if 'Hash' not in result:
                    raise IPFSHashNotReturnedException

                cid = result.get('Hash')
                print("File uploaded successfully, hash: " + cid)

                print("PINNING")
                ipfs_endpoint_pin = f"/pin/add?arg={cid}"
                pin_url = ipfs_url + ipfs_endpoint_pin
                pin_response = requests.post(pin_url)

                if pin_response.status_code == 200:
                    print(f"File {cid} pinned successfully")
                else:
                    print("Error pinning file: ", response.status_code, response.text)

                return JsonResponse(result)
            else:
                return JsonResponse({'error': response.text}, status=response.status_code)


    return render(request, 'upload-ipfs.html')

import requests

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

# Check if file is pinned
cid = 'QmNnVARxwSwCiD5FT7f33cUN1ExtgxNwnk3vKcdyNiH5R9'
#check_if_pinned(cid)


class ListClaimsView(APIView):
    def get(self, request):
        claim = get_claim()
        return Response(claim)

    #queryset = Claim.objects.all()
    #serializer_class = ClaimSerializer