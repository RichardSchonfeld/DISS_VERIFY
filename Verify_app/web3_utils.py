import json
import string
import random
import time

import requests
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login
from django.contrib.auth.models import User
from web3 import Web3
from eth_account.messages import encode_defunct
from .models import CustomUser, Claim

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
            user = CustomUser.objects.get(address=account)
        except CustomUser.DoesNotExist:
            # Create a new Web3 user if it doesn't exist
            user = CustomUser(
                username=account,
                address=account,
                is_web3_user=True,
            )
            user.save()

        # Log the user in
        login(request, user)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Signature verification failed'}, status=400)


def verify_signature_login_metamask_authority_creation(request):
    """Verify the signature and authenticate the user as an authority."""
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
        try:
            # Check if the authority account already exists
            user = CustomUser.objects.get(address=account)
        except CustomUser.DoesNotExist:
            # Create a new Web3 user if it doesn't exist
            user = CustomUser(
                username=account,
                address=account,
                institution_name=data.get('authority_name'),  # Add authority name
                is_web3_user=True,
                is_authority=True  # Mark the user as an authority
            )
            user.save()

        # Log the user in
        login(request, user)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Signature verification failed'}, status=400)


def process_claim_transaction(txn_hash):
    """Process a claim transaction, extract the claim ID, and update the claim status for both ClaimCreated and ClaimSigned events."""
    web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

    try:
        # Wait for the transaction receipt with a timeout
        timeout = 120  # seconds
        poll_interval = 5  # seconds
        start_time = time.time()
        receipt = None

        while True:
            try:
                receipt = web3.eth.get_transaction_receipt(txn_hash)
                break  # Receipt found
            except:
                # Receipt not yet available
                if time.time() - start_time > timeout:
                    print(f"Timeout waiting for transaction receipt: {txn_hash}")
                    return
                time.sleep(poll_interval)

        # Check transaction status
        if receipt.status == 1:
            # Transaction succeeded
            # Load contract ABI and address
            contract_address = settings.CONTRACT_ADDRESS
            with open('build/contracts/Verify.json') as f:
                contract_data = json.load(f)
                contract_abi = contract_data['abi']
            verify_contract = web3.eth.contract(address=contract_address, abi=contract_abi)

            # Process receipt logs for ClaimCreated and ClaimSigned events
            claim_created_events = verify_contract.events.ClaimCreated().process_receipt(receipt)
            claim_signed_events = verify_contract.events.ClaimSigned().process_receipt(receipt)

            if claim_created_events:
                # Process ClaimCreated event
                event = claim_created_events[0]
                claim_id = event.args.claimId

                # Update the Claim object in the database for the ClaimCreated event
                claim = Claim.objects.get(transaction_hash=txn_hash)
                claim.claim_id = claim_id
                claim.tx_status = 'pending signature'
                claim.tx_timestamp = timezone.now()
                claim.save()

                print(f"Transaction {txn_hash} succeeded. Claim ID: {claim_id}")

            if claim_signed_events:
                # Process ClaimSigned event
                signed_event = claim_signed_events[0]
                claim_id_signed = signed_event.args.claimId
                signer_address = signed_event.args.authority

                # Update the Claim object in the database for the ClaimSigned event
                claim = Claim.objects.get(claim_id=claim_id_signed)
                claim.signed = True
                claim.signer = signer_address
                claim.tx_status = 'signed'
                claim.tx_timestamp = timezone.now()
                claim.save()

                print(f"Transaction {txn_hash} succeeded. Claim signed by: {signer_address}")

            if not claim_created_events and not claim_signed_events:
                # No relevant events found in the transaction
                print(f"No ClaimCreated or ClaimSigned events found in transaction {txn_hash}")
                claim = Claim.objects.get(transaction_hash=txn_hash)
                claim.tx_status = 'failed'
                claim.tx_timestamp = timezone.now()
                claim.save()
        else:
            # Transaction failed
            print(f"Transaction {txn_hash} failed.")
            # Attempt to get the failure reason
            try:
                tx = web3.eth.get_transaction(txn_hash)
                tx_input = tx['input']

                # Re-execute the transaction via eth_call to get the revert reason
                tx_dict = {
                    'from': tx['from'],
                    'to': tx['to'],
                    'gas': tx['gas'],
                    'gasPrice': tx['gasPrice'],
                    'data': tx_input,
                    'value': tx['value']
                }

                result = web3.eth.call(tx_dict, tx.blockNumber)
                # If no exception, the transaction should have succeeded (which is not the case here)
                error_message = "Transaction failed without an error message."
            except Exception as e:
                # Extract error message from the exception
                error_message = str(e)
                print(f"Transaction {txn_hash} failed with error: {error_message}")

            # Update the Claim object in the database
            claim = Claim.objects.get(transaction_hash=txn_hash)
            claim.tx_status = 'failed'
            claim.tx_timestamp = timezone.now()
            # claim.error_message = error_message
            claim.save()
    except Exception as e:
        print(f"Error processing transaction {txn_hash}: {str(e)}")
        # Update the Claim object in the database
        claim = Claim.objects.get(transaction_hash=txn_hash)
        claim.tx_status = 'error'
        claim.tx_timestamp = timezone.now()
        # claim.error_message = str(e)
        claim.save()


def process_claim_transaction_dep(txn_hash):
    """Process a claim transaction, extract the claim ID, and update the claim status."""
    web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))

    try:
        # Wait for the transaction receipt with a timeout
        timeout = 120  # seconds
        poll_interval = 5  # seconds
        start_time = time.time()
        receipt = None

        while True:
            try:
                receipt = web3.eth.get_transaction_receipt(txn_hash)
                break  # Receipt found
            except:
                # Receipt not yet available
                if time.time() - start_time > timeout:
                    print(f"Timeout waiting for transaction receipt: {txn_hash}")
                    return
                time.sleep(poll_interval)

        # Check transaction status
        if receipt.status == 1:
            # Transaction succeeded
            # Load contract ABI and address
            contract_address = settings.CONTRACT_ADDRESS
            with open('build/contracts/Verify.json') as f:
                contract_data = json.load(f)
                contract_abi = contract_data['abi']
            verify_contract = web3.eth.contract(address=contract_address, abi=contract_abi)

            # Process receipt logs to find the 'ClaimCreated' event
            claim_created_events = verify_contract.events.ClaimCreated().process_receipt(receipt)

            if claim_created_events:
                # Assuming only one ClaimCreated event per transaction
                event = claim_created_events[0]
                claim_id = event.args.claimId  # Adjust according to your event's argument names

                # Update the Claim object in the database
                claim = Claim.objects.get(transaction_hash=txn_hash)
                claim.claim_id = claim_id
                claim.tx_status = 'pending signature'
                claim.tx_timestamp = timezone.now()
                claim.save()

                print(f"Transaction {txn_hash} succeeded. Claim ID: {claim_id}")
            else:
                # No ClaimCreated event found
                print(f"No ClaimCreated event found in transaction {txn_hash}")
                claim = Claim.objects.get(transaction_hash=txn_hash)
                claim.tx_status = 'failed'
                claim.tx_timestamp = timezone.now()
                claim.save()
        else:
            # Transaction failed
            print(f"Transaction {txn_hash} failed.")
            # Attempt to get the failure reason
            try:
                tx = web3.eth.get_transaction(txn_hash)
                tx_input = tx['input']

                # Re-execute the transaction via eth_call to get the revert reason
                tx_dict = {
                    'from': tx['from'],
                    'to': tx['to'],
                    'gas': tx['gas'],
                    'gasPrice': tx['gasPrice'],
                    'data': tx_input,
                    'value': tx['value']
                }

                result = web3.eth.call(tx_dict, tx.blockNumber)
                # If no exception, the transaction should have succeeded (which is not the case here)
                error_message = "Transaction failed without an error message."
            except Exception as e:
                # Extract error message from the exception
                error_message = str(e)
                print(f"Transaction {txn_hash} failed with error: {error_message}")

            # Update the Claim object in the database
            claim = Claim.objects.get(transaction_hash=txn_hash)
            claim.tx_status = 'failed'
            claim.tx_timestamp = timezone.now()
            # If you have a field to store the error message, you can add it here
            # claim.error_message = error_message
            claim.save()
    except Exception as e:
        print(f"Error processing transaction {txn_hash}: {str(e)}")
        # Update the Claim object in the database
        claim = Claim.objects.get(transaction_hash=txn_hash)
        claim.tx_status = 'error'
        claim.tx_timestamp = timezone.now()
        # claim.error_message = str(e)
        claim.save()