import hashlib
import json
import uuid

import requests
import ast

from PyPDF2 import PdfReader
from django.core.files.base import ContentFile
from web3 import Web3
import hashlib
import datetime
import json
import os
import base64

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from eth_account.messages import encode_defunct
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import Claim, CustomUser, Certificate, KeyFragment
from .forms import UserRegisterForm, store_key_fragment, get_user_by_address, get_authority_name_from_address, \
    save_claim_to_django_DB, store_and_distribute_key_fragments, embed_metadata
from .ipfs_functions import parse_json_decrypted_ipfs_data, get_decrypted_data_from_ipfs, \
    upload_ipfs_file, get_decrypted_data_from_ipfs_file, upload_to_ipfs, predetermine_ipfs_hash
from .eth_utils import create_claim, sign_claim, get_claim, fund_account, extract_claim_id_from_receipt
from .encryption_utils import encrypt_private_key, derive_key, decrypt_private_key, encrypt_and_split, \
    decrypt_with_shares, encrypt_with_public_key, encrypt_and_split_file
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas



def index(request):
    if request.user.is_authenticated:
        user = request.user

        if user.is_authority:
            # Fetch pending claims for the authority user
            pending_claims_count = Claim.objects.filter(authority=user, signed=False).count()
            return render(request, 'home.html', {
                'pending_claims_count': pending_claims_count,
                'is_authority': True
            })
        else:
            # Fetch institutions that have signed up (authorities)
            institutions = CustomUser.objects.filter(is_authority=True)
            return render(request, 'home.html', {
                'institutions': institutions,
                'is_authority': False
            })
    else:
        # For non-logged-in users, show institutions
        institutions = CustomUser.objects.filter(is_authority=True)
        return render(request, 'home.html', {
            'institutions': institutions,
            'is_authority': False,
            'guest': True
        })

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


def logout_view(request):
    logout(request)
    return redirect('login')

def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.address = request.POST['address']
            user.encrypted_private_key = request.POST['encrypted_private_key']
            user.save()

            ### ----- TEMPORARY user fund initial ----- ###
            #fund_account(user.address)
            ### ----- END TEMP ----- ###

            login(request, user)
            return redirect('index')
        else:
            # If the form is not valid, return the form with errors
            return render(request, 'register.html', {'form_errors': form.errors})
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {'form': form})

def register_authority(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.address = request.POST['address']
            user.encrypted_private_key = request.POST['encrypted_private_key']
            user.institution_name = request.POST['authority_name']  # New field for authority name
            user.is_authority = True  # Mark this user as an authority
            user.save()

            # Optionally, fund the account (for Ethereum-based operations)
            #fund_account(user.address)

            return redirect('index')
        else:
            return render(request, 'register_authority.html', {'form_errors': form.errors})
    else:
        form = UserRegisterForm()
    return render(request, 'register_authority.html', {'form': form})


def transaction_confirmation(request):
    txn_hash = request.GET.get('txn_hash')
    return render(request, 'transaction_confirmation.html', {'txn_hash': txn_hash})

@login_required
@csrf_exempt
def create_claim(request):
    if request.method == 'POST':
        data = request.body.decode('utf-8')
        web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

        if 'signedTransaction' in data:
            # Django User Flow: Send the signed transaction to the blockchain
            try:
                data = json.loads(data)
                txn_hash = web3.eth.send_raw_transaction(data['signedTransaction'])

                # Wait for transaction to be mined
                receipt = web3.eth.wait_for_transaction_receipt(txn_hash)

                # Extract claim ID from event log in receipt
                claim_id = extract_claim_id_from_receipt(receipt)

                # Save the claim to the database with claim ID from receipt
                save_claim_to_django_DB(request, txn_hash.hex(), claim_id)

                return JsonResponse({'txn_hash': txn_hash.hex(), 'claim_id': claim_id})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

        elif 'txnHash' in data:
            # MetaMask User Flow: Transaction already sent, just log the transaction hash
            data = json.loads(data)
            txn_hash = data['txnHash']

            # Wait for transaction to be mined
            receipt = web3.eth.wait_for_transaction_receipt(txn_hash)

            # Extract claim ID from event log in receipt
            claim_id = extract_claim_id_from_receipt(receipt)

            # Save the claim to the database with claim ID from receipt
            save_claim_to_django_DB(request, txn_hash, claim_id)

            return JsonResponse({'txn_hash': txn_hash, 'claim_id': claim_id})

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

            # Distributing Shamir keys to local profiles
            store_and_distribute_key_fragments(shares, user_profile, authority_address, IPFS_hash)

            gas_estimate = verify_contract_instance.functions.createClaim(
                _requester=wallet_address,
                _authority=authority_address,
                _ipfsHash=IPFS_hash
            ).estimate_gas({
                'from': wallet_address,
                'value': 0
            })

            transaction = verify_contract_instance.functions.createClaim(
                _requester=wallet_address,
                _authority=authority_address,
                _ipfsHash=IPFS_hash
            ).build_transaction({
                'chainId': 1337,  # Ganache
                'gas': gas_estimate,
                'gasPrice': web3.eth.gas_price,
                'nonce': web3.eth.get_transaction_count(wallet_address),
                'value': 0 # Ensure no ETH is sent this cost me too many hours to discover... SC calls dont' work without it
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

def generate_certificate_hash(certificate_bytes):
    """Convert certificate data to a hash for signing."""
    return hashlib.sha256(certificate_bytes).hexdigest()


def sign_certificate_view(request):
    """Handle the certificate signing, generate PDF and certificate hash."""
    if request.method == 'POST':
        claim_id = request.POST.get('claim_id')
        try:
            claim = Claim.objects.get(claim_id=claim_id)
        except Claim.DoesNotExist:
            return JsonResponse({'error': f'No entry found for claim ID: {claim_id}'}, status=404)

        # Fetch claim data from IPFS (retrieved as a string)
        claim_data_string = get_decrypted_data_from_ipfs(claim.ipfs_hash, request.user)
        if not claim_data_string:
            return JsonResponse({'error': 'Failed to retrieve data from IPFS'}, status=500)

        # Prepare claim data (adjust this to match actual structure)
        claim_data_parts = claim_data_string.split(',')
        claim_data = {
            "year_of_graduation": claim_data_parts[0],
            "student_number": claim_data_parts[1],
            "full_name": claim_data_parts[2],
            "course_details": "Bachelor of Science in Computer Science",
            "issuer": "University Name",
            "date_of_issue": datetime.date.today().strftime('%Y-%m-%d')
        }

        # Prepare certificate PDF and data
        certificate_data, certificate_pdf_buffer = prepare_certificate_data(claim_data)

        # Embed claim ID and authority address into the certificate PDF
        embedded_certificate_pdf_bytes = embed_metadata(certificate_pdf_buffer.getvalue(), claim_id, request.user.address)

        # Encrypt the certificate and split the encryption key
        encrypted_data, shares = encrypt_and_split_file(embedded_certificate_pdf_bytes)

        # Upload the encrypted certificate to IPFS
        ipfs_hash = upload_ipfs_file(encrypted_data)

        # Generate a certificate hash
        certificate_hash = generate_certificate_hash(embedded_certificate_pdf_bytes)
        message = encode_defunct(hexstr=certificate_hash)

        # Store and distribute key fragments
        store_and_distribute_key_fragments(shares, claim.requester, claim.authority.address, ipfs_hash)


        # Prepare the transaction data for blockchain signing
        web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))
        contract_address = settings.CONTRACT_ADDRESS
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']
        verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

        user_profile = request.user
        wallet_address = Web3.to_checksum_address(user_profile.address)

        user_profile = request.user
        wallet_address = Web3.to_checksum_address(user_profile.address)

        # Estimate gas for the transaction
        gas_estimate = verify_contract_instance.functions.signClaim(
            int(claim_id),
            "MEUCIQC03/JJpUtxqeju5oVFP1QVsVNOA4Oet7HCqEAqhPBFuMchAiEAUZtCPXFfjIUnKCLvrACVgR723/WuMdZxepsy00tItmzP",  # Placeholder for the signature, to be replaced in the frontend
            ipfs_hash
        ).estimate_gas({
            'from': wallet_address
        })

        transaction = verify_contract_instance.functions.signClaim(
            int(claim_id),
            "0x",  # Placeholder for the signature, to be replaced in the frontend
            ipfs_hash
        ).build_transaction({
            'chainId': 1337,
            'gas': gas_estimate + 50000,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(request.user.address),
            'value': 0
        })

        # Return the certificate data, certificate hash, CID, and transaction for signing in the frontend
        return JsonResponse({
            "transaction": json.dumps(transaction),
            "certificate_hash": Web3.to_hex(message.body),
            "certificate_pdf_base64": base64.b64encode(embedded_certificate_pdf_bytes).decode('utf-8'),
            "selected_claim_id": claim_id,
            "contract_abi": contract_abi,
            "contract_address": contract_address,
            "ipfs_cid": ipfs_hash,  # Return the CID to the frontend,
            "web3_url": settings.WEB3_URL
        })

    # Render list of unsigned claims
    unsigned_claims = Claim.objects.filter(authority=request.user, signed=False)
    context = {
        'unsigned_claims': unsigned_claims,
        'is_web3_user': request.user.is_web3_user,
    }
    if not request.user.is_web3_user:
        context['encrypted_private_key'] = request.user.encrypted_private_key

    return render(request, 'sign_certificate.html', context)


@csrf_exempt
@login_required
def store_signed_certificate(request):
    """Store the signed certificate, save a copy for user and authority, and embed claim ID and authority address."""
    if request.method == 'POST':
        data = json.loads(request.body)
        signature = data.get('signature')
        ipfs_hash = data.get('expected_cid')  # CID passed from frontend
        txn_hash = data.get('txn_hash')
        claim_id = data.get('selected_claim_id')

        claim = Claim.objects.get(claim_id=claim_id)
        claimant = claim.requester
        authority = claim.authority

        # Save certificate for user along with IPFS hash
        user_certificate = Certificate.objects.create(
            user=claimant,
            authority=authority,
            claim=claim,
            ipfs_hash=ipfs_hash,
            signature=signature,
            txn_hash=txn_hash,
        )

        # Mark the claim as signed
        claim.signed = True
        claim.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Certificate signed, encrypted, and uploaded to IPFS successfully.',
            'certificate_id': user_certificate.id,
            'ipfs_hash': ipfs_hash
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

def view_certificate(request):
    """
    Display the signed certificate for the user and provide a download option.
    """
    user = request.user
    certificates = Certificate.objects.filter(user=user)

    return render(request, 'view_certificate.html', {'certificates': certificates})


def verify_signature(request):
    """
    Verify the signature of the uploaded certificate using the claim ID and authority address.
    Fetch claim data and signature directly from the blockchain.
    """
    if request.method == 'POST':
        uploaded_file = request.FILES.get('uploaded_certificate')

        if not uploaded_file:
            return JsonResponse({'error': 'No certificate provided'}, status=400)

        # Read the uploaded PDF file
        pdf_file = uploaded_file.read()

        # Extract claim ID and authority address from the certificate metadata
        pdf_reader = PdfReader(BytesIO(pdf_file))
        metadata = pdf_reader.metadata

        try:
            claim_id = int(metadata.get('/ClaimID'))
            authority_address = Web3.to_checksum_address(metadata.get('/AuthorityAddress'))
        except Exception as e:
            return JsonResponse({
                'status': 'Error: Certificate metadata is invalid or incomplete',
                'verified': False,
                'verified_by': 'N/A'
            })

        web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

        # Load the contract ABI and address
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']

        contract_address = settings.CONTRACT_ADDRESS
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)

        try:
            # Fetch claim data from the blockchain by claim ID
            claim_data = contract.functions.getClaim(claim_id).call()

            # Verify that the authority matches the one stored on-chain
            if authority_address.lower() != claim_data[1].lower():
                return JsonResponse({
                    'status': 'Error: The authority address does not match the one on the blockchain',
                    'verified': False,
                    'verified_by': 'N/A'
                })

            # Hash the file to compare it to the on-chain data
            file_hash = hashlib.sha256(pdf_file).hexdigest()

            # Fetch the certificate signature from the blockchain
            on_chain_signature = contract.functions.getCertSignature(claim_id).call()

            # Verify the on-chain signature with the recovered address
            message = encode_defunct(hexstr=file_hash)
            recovered_address = web3.eth.account.recover_message(message, signature=on_chain_signature)

            # Fetch the transaction hash directly from the blockchain logs
            logs = contract.events.ClaimSigned.create_filter(
                fromBlock=0,
                argument_filters={'claimId': claim_id}
            ).get_all_entries()

            if not logs:
                return JsonResponse({
                    'status': 'Error: No transaction log found for the claim ID',
                    'verified': False,
                    'verified_by': 'N/A'
                })

            # Get the transaction hash from the first matching log
            txn_hash = logs[0].transactionHash.hex()

            # Compare the recovered address with the authority's address on-chain
            if recovered_address.lower() == authority_address.lower():
                authority = CustomUser.objects.get(address=authority_address)
                return JsonResponse({
                    'status': 'success',
                    'verified': True,
                    'verified_by': authority.institution_name,
                    'transaction_hash': txn_hash,
                    'etherscan_url': f"https://sepolia.etherscan.io/tx/{txn_hash}"
                })
            else:
                return JsonResponse({
                    'status': 'Error: Signature mismatch',
                    'verified': False,
                    'verified_by': 'N/A'
                })

        except Exception as e:
            return JsonResponse({
                'status': f"Error: {str(e)}",
                'verified': False,
                'verified_by': 'N/A'
            })

    return render(request, 'verify_certificate.html')





def user_profile_view(request):
    user = request.user

    if user.is_authenticated:
        user_address = user.address  # Assuming you store user's Ethereum address in CustomUser model

        # Connect to Ethereum blockchain
        web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

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
            claim_created_at = 'Error'
            try:
                claim_db = Claim.objects.get(claim_id=claim_id)
                claim_created_at = claim_db.created_at
            except Exception as e:
                # LOG #
                pass

            # Retrieve authority address from the claim
            authority_address = claim[1]

            # Use the function to resolve the authority name
            authority_name = get_authority_name_from_address(authority_address)

            claims.append({
                'claim_id': claim_id,
                'requester': claim[0],
                'authority': authority_name,  # Use the resolved authority name
                'ipfs_hash': claim[2],
                'created_at': claim_created_at,
                'signed': claim[3],
            })

        return render(request, 'user_profile.html', {'claims': claims})
    else:
        return render(request, 'user_profile.html', {'error': 'User not authenticated'})


def authority_profile_view(request):
    user = request.user

    if user.is_authenticated and user.is_authority:
        # Fetch pending claims (i.e., claims that are not signed yet) for the logged-in authority
        pending_claims = Claim.objects.filter(authority=user, signed=False)

        # Fetch signed claims for the logged-in authority
        signed_claims = Claim.objects.filter(authority=user, signed=True)

        return render(request, 'authority_profile.html', {
            'pending_claims': pending_claims,
            'signed_claims': signed_claims
        })
    else:
        return render(request, 'authority_profile.html', {'error': 'User not authenticated or not an authority'})



def decrypt_certificate_view(request, ipfs_hash):
    """
    View to retrieve and decrypt an encrypted certificate from IPFS using the user's and server's key fragments.
    """
    try:
        # Retrieve the decrypted certificate data
        decrypted_pdf_bytes = get_decrypted_data_from_ipfs_file(ipfs_hash, request.user)

        if decrypted_pdf_bytes is None:
            return HttpResponse("Decryption failed or data not found.", status=400)

        # Convert the decrypted file bytes into a downloadable/displayable file
        pdf_file = BytesIO(decrypted_pdf_bytes)

        # Render the decrypted PDF in the HTML template
        response = HttpResponse(pdf_file.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename="decrypted_certificate.pdf"'
        return response

    except Certificate.DoesNotExist:
        return HttpResponse("No certificate found for this IPFS hash.", status=404)
    except Exception as e:
        return HttpResponse(f"An error occurred: {str(e)}", status=500)


def claim_detail_view(request, claim_id):
    user = request.user

    if user.is_authenticated:
        # Connect to Ethereum blockchain
        web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

        # Load the contract
        with open('build/contracts/Verify.json') as f:
            contract_data = json.load(f)
            contract_abi = contract_data['abi']

        contract_address = settings.CONTRACT_ADDRESS
        verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)

        # Retrieve the specific claim
        claim = verify_contract_instance.functions.getClaim(claim_id).call()

        ipfs_hash = claim[2]

        # If the claim is signed, retrieve and decrypt the IPFS data
        if claim[3] == True:  # Assuming claim[3] is the 'signed' status
            decrypted_data = get_decrypted_data_from_ipfs_file(ipfs_hash, request.user)
            decrypted_data = base64.b64encode(decrypted_data).decode('utf-8')
        else:
            decrypted_data = get_decrypted_data_from_ipfs(ipfs_hash, request.user)

        claim_detail = {
            'claim_id': claim_id,
            'requester': claim[0],
            'authority': claim[1],
            'ipfs_hash': claim[2],
            'decrypted_data': decrypted_data,
            'signed': claim[3],
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


@login_required
def decrypt_private_key_view(request):
    """View to handle decrypting and displaying the private key."""

    user_profile = request.user
    encrypted_private_key = user_profile.encrypted_private_key

    if not encrypted_private_key:
        return JsonResponse({'error': 'No private key found for this user'}, status=404)


    context = {
        'encrypted_private_key': encrypted_private_key
    }
    return render(request, 'decrypt_private_key.html', context)


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
