import hashlib
import json
import requests
import ast
from web3 import Web3
import hashlib
import datetime
import json
import os
import base64

from django.contrib.auth import authenticate, login
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from eth_account.messages import encode_defunct
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import Claim, CustomUser, Certificate
from .forms import UserRegisterForm, store_key_fragment, get_user_by_address, get_authority_name_from_address, save_claim_to_django_DB
from .ipfs_functions import get_ipfs_raw_data, parse_json_decrypted_ipfs_data, get_ipfs_decrypted_data, \
    get_decrypted_data_from_ipfs
from .eth_utils import create_claim, sign_claim, get_claim, fund_account
from .encryption_utils import encrypt_private_key, derive_key, decrypt_private_key, encrypt_and_split, \
    decrypt_with_shares, encrypt_with_public_key
from .web3_utils import upload_to_ipfs
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas



def index(request):
    return render(request, "home.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse('home'))
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials. Please try again.'})
    else:
        return render(request, 'login.html')

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

                # Save the claim to the database
                save_claim_to_django_DB(request, txn_hash.hex())

                return JsonResponse({'txn_hash': txn_hash.hex()})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

        elif 'txnHash' in data:
            # MetaMask User Flow: Transaction already sent, just log the transaction hash
            data = json.loads(data)
            txn_hash = data['txnHash']

            # Save the claim to the database
            save_claim_to_django_DB(request, txn_hash)

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

            # Uploading to IPFS and getting hash back
            IPFS_hash = upload_to_ipfs(encrypted_data)

            # Prepare the transaction data
            user_profile = request.user
            wallet_address = Web3.to_checksum_address(user_profile.address)

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

            # Save the IPFS hash in the session for later use
            request.session['ipfs_hash'] = IPFS_hash

            claim_data_for_DB = {
                'authority': authority_address,
                'ipfs_hash': IPFS_hash
            }

            # Render the signing page with the transaction data
            context = {
                'transaction_data': json.dumps(transaction),
                'claim_data': json.dumps(claim_data_for_DB),
                'user': request.user,
                'encrypted_private_key': user_profile.encrypted_private_key if not user_profile.is_web3_user else None,
            }
            return render(request, 'submit_claim.html', context)
    else:
        authorities = CustomUser.objects.filter(is_authority=True)
        return render(request, 'create_claim.html', {'authorities': authorities})


def view_claims(request):
    claims = get_claim()
    return render(request, 'view_claims.html', {'claims': claims})


def prepare_certificate_data(claim):
    """Generate a PDF certificate from the claim data."""

    # Claim data (assuming claim is passed as a dictionary with required fields)
    certificate_data = {
        "year_of_graduation": claim['year_of_graduation'],
        "student_number": claim['student_number'],
        "name": claim['full_name'],
        "course_details": "Bachelor of Science in Computer Science",  # Example course
        "issuer": "University Name",  # Example issuer
        "date_of_issue": datetime.date.today().strftime('%Y-%m-%d')
    }

    # Generate the PDF
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    # Formatting for the PDF (Centered and styled for certificate appearance)
    pdf.setTitle("Certificate of Graduation")
    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawCentredString(300, 770, "Certificate of Graduation")

    pdf.setFont("Helvetica", 18)
    pdf.drawCentredString(300, 700, f"Presented to: {certificate_data['name']}")
    pdf.drawCentredString(300, 660, f"Student Number: {certificate_data['student_number']}")

    pdf.setFont("Helvetica", 16)
    pdf.drawCentredString(300, 620, f"Course: {certificate_data['course_details']}")
    pdf.drawCentredString(300, 580, f"Year of Graduation: {certificate_data['year_of_graduation']}")

    pdf.setFont("Helvetica", 14)
    pdf.drawCentredString(300, 540, f"Issued by: {certificate_data['issuer']}")
    pdf.drawCentredString(300, 500, f"Date of Issue: {certificate_data['date_of_issue']}")

    # Add a line for the signature
    pdf.line(220, 440, 380, 440)  # Signature line
    pdf.setFont("Helvetica", 12)
    pdf.drawCentredString(300, 420, "Signature")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)

    # Return the certificate data and the buffer (PDF file)
    return certificate_data, buffer
    #return FileResponse(buffer, as_attachment=True, filename=f"{certificate_data['name']}_certificate.pdf")

def generate_certificate_hash(certificate_data):
    """Convert certificate data to a hash for signing."""
    certificate_json = json.dumps(certificate_data)
    return hashlib.sha256(certificate_json.encode()).hexdigest()


def sign_certificate_view(request):
    """Handle the certificate signing, generate PDF and certificate hash."""
    if request.method == 'POST':
        claim_id = request.POST.get('claim_id')
        claim = Claim.objects.get(id=claim_id)

        # Fetch the claim data from IPFS (retrieved as a string)
        claim_data_string = get_decrypted_data_from_ipfs(claim.ipfs_hash, request.user)

        if not claim_data_string:
            return JsonResponse({'error': 'Failed to retrieve data from IPFS'}, status=500)

        # Parse the claim data string (assuming it's comma-separated)
        claim_data_parts = claim_data_string.split(',')

        # Adjust the parts to match the required fields (modify this based on the actual structure)
        claim_data = {
            "year_of_graduation": claim_data_parts[0],
            "student_number": claim_data_parts[1],
            "full_name": claim_data_parts[2],
            "course_details": "Bachelor of Science in Computer Science",  # Example course
            "issuer": "University Name",  # Example issuer
            "date_of_issue": datetime.date.today().strftime('%Y-%m-%d')
        }

        # Prepare certificate PDF and data
        certificate_data, certificate_pdf_buffer = prepare_certificate_data(claim_data)

        # Generate a certificate hash
        certificate_hash = generate_certificate_hash(certificate_data)
        certificate_pdf_base64 = base64.b64encode(certificate_pdf_buffer.getvalue()).decode('utf-8')

        # Encode the certificate hash for Ethereum
        message = encode_defunct(hexstr=certificate_hash)

        # Save the generated PDF file to a local directory
        pdf_filename = f"{claim_data['full_name']}_certificate.pdf"
        pdf_path = os.path.join(settings.BASE_DIR, pdf_filename)  # Make sure this path exists
        with open(pdf_path, 'wb') as f:
            f.write(certificate_pdf_buffer.getvalue())

        # Return the certificate file and hash
        return JsonResponse({
            "certificate_hash": Web3.to_hex(message.body),
            "certificate_file": pdf_filename,  # Return the filename for download
            "certificate_pdf_base64": certificate_pdf_base64,
            "selected_claim_id": claim_id
        })

    # Render list of unsigned claims for the authority to choose from
    unsigned_claims = Claim.objects.filter(authority=request.user, signed=False)
    user = request.user
    context = {
        'is_web3_user': True,
        'unsigned_claims': unsigned_claims
    }

    if not user.is_web3_user:
        context = {
            'encrypted_private_key': request.user.encrypted_private_key,
            'is_web3_user': False,
            'unsigned_claims': unsigned_claims
        }

    return render(request, 'sign_certificate.html', context)


def verify_certificate_signature(request):
    """Verify the digital signature of the certificate."""
    if request.method == 'POST':
        address = request.POST.get('address')
        certificate_hash = request.POST.get('certificate_hash')
        signature = request.POST.get('signature')

        try:
            # Create Web3 instance and recover address
            web3 = Web3()
            message = encode_defunct(hexstr=certificate_hash)
            recovered_address = web3.eth.account.recover_message(message, signature=signature)

            if recovered_address.lower() == address.lower():
                return JsonResponse({'status': 'success', 'message': 'Signature is valid and matches the public key.'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Signature does not match the public key.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=500)

    return render(request, 'verify_signature.html')

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
@login_required
def store_signed_certificate(request):
    """Store the signed certificate, upload it to IPFS, and save it in the DB."""
    if request.method == 'POST':
        data = json.loads(request.body)
        certificate_pdf_base64 = data.get('certificate_pdf_base64')  # Get the base64-encoded PDF
        certificate_hash = data.get('certificate_hash')
        signature = data.get('signature')
        user = request.user  # The user requesting the certificate (the student, for example)
        claim_id = data.get('selected_claim_id')  # Get the claim ID passed from the frontend

        # Decode the base64-encoded PDF back to bytes
        certificate_pdf_bytes = base64.b64decode(certificate_pdf_base64)
        certificate_pdf_buffer = BytesIO(certificate_pdf_bytes)

        # Upload the PDF to IPFS
        ipfs_hash = upload_to_ipfs(certificate_pdf_buffer)

        # Get the claim and authority from the database
        claim = Claim.objects.get(id=claim_id)
        authority = claim.authority

        if claim.authority != request.user:
            return JsonResponse({'error': 'Unauthorized: You are not the authority for this claim.'}, status=403)

        # Save the signed certificate to the database
        certificate = Certificate.objects.create(
            user=user,  # The user (recipient of the certificate)
            authority=authority,  # The authority issuing the certificate
            claim=claim,  # Link the claim to the certificate
            ipfs_hash=ipfs_hash,  # IPFS hash of the uploaded PDF
            certificate_hash=certificate_hash, # Certificate hash
            signature=signature  # The digital signature from the signing
        )

        # Mark the claim as signed
        claim.signed = True
        claim.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Certificate signed and stored successfully.',
            'certificate_id': certificate.id
        })

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


def user_profile_view(request):
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

            # Retrieve authority address from the claim
            authority_address = claim[1]

            # Use the function to resolve the authority name
            authority_name = get_authority_name_from_address(authority_address)

            claims.append({
                'claim_id': claim_id,
                'requester': claim[0],
                'authority': authority_name,  # Use the resolved authority name
                'year_of_graduation': claim[2],
                'student_number': claim[3],
                'full_name': claim[4],
                'ipfs_hash': claim[5],
                'signed': claim[6],
            })

        return render(request, 'user_profile.html', {'claims': claims})
    else:
        return render(request, 'user_profile.html', {'error': 'User not authenticated'})


def claim_detail_view(request, claim_id):
    user = request.user

    if user.is_authenticated:
        user_address = user.address

        # Connect to Ethereum blockchain
        web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

        # Load the contract
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']

        contract_address = settings.CONTRACT_ADDRESS
        verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

        # Retrieve the specific claim
        claim = verify_contract_instance.functions.getClaim(claim_id).call()

        ipfs_hash = claim[5]
        decrypted_data = get_decrypted_data_from_ipfs(ipfs_hash, request.user)

        claim_detail = {
            'claim_id': claim_id,
            'requester': claim[0],
            'authority': claim[1],
            'year_of_graduation': claim[2],
            'student_number': claim[3],
            'full_name': claim[4],
            'ipfs_hash': claim[5],
            'decrypted_data': decrypted_data,
            'signed': claim[6],
        }

        return render(request, 'claim_detail.html', {'claim': claim_detail})
    else:
        return render(request, 'claim_detail.html', {'error': 'User not authenticated'})


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
