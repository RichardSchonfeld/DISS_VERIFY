from django.conf import settings
from web3 import Web3
import json
import os

# Load contract ABI and address
with open('build/contracts/Verify.json') as f:
    contract_data = json.load(f)
    contract_abi = contract_data['abi']

# Update the contract address here after migration
contract_address = settings.CONTRACT_ADDRESS

# Connect to local Ganache
web3 = Web3(Web3.HTTPProvider(settings.WEB3_URL))
#web3 = Web3(Web3.HTTPProvider(settings.INFURA_TEST_URL))

# Initialize the contract
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

def create_claim(authority_address, year_of_graduation, student_number, full_name):
    """requester_address = web3.eth.accounts[0]
    nonce = web3.eth.get_transaction_count(requester_address)
    txn = contract.functions.createClaim(
        requester_address, authority_address, year_of_graduation, student_number, full_name, #ipfs_hash
    ).build_transaction({
        'from': requester_address,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
    })
    private_key = settings.PRIVATE_KEY
    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return tx_hash.hex()"""
    return None

def sign_claim(claim_id, authority_address, signature):
    """nonce = web3.eth.get_transaction_count(authority_address)
    txn = contract.functions.signClaim(claim_id, signature).build_transaction({
        'from': authority_address,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
    })
    private_key = settings.PRIVATE_KEY
    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    return tx_hash.hex()"""
    return None


def get_claim():
    claims = []

    claim_count = contract.functions.claimCount().call()

    for claim_id in range(1, claim_count + 1):
        claim = contract.functions.getClaim(claim_id).call()
        claims.append({
            'requester': claim[0],
            'authority': claim[1],
            'ipfs_hash': claim[2],
            'signed': claim[3],
        })

    return claims



def fund_account(new_account_address):
    preset_account_address = '0x0dAD17E4C8E3d3290073b69971B5b11988AAdc62'
    preset_private_key = os.getenv('FUND_TEST_PRIVATE_KEY')

    # Define the amount of Ether to send (in Wei)
    initial_balance = web3.to_wei(0.25, 'ether')  # Sending 0.01 Ether to the new account

    # Get the nonce for the transaction
    nonce = web3.eth.get_transaction_count(Web3.to_checksum_address(preset_account_address))

    # Create the transaction
    tx = {
        'nonce': nonce,
        'to': new_account_address,
        'value': initial_balance,
        'gas': 21000,  # Standard gas limit for a simple ETH transfer
        'gasPrice': web3.to_wei('50', 'gwei')
    }

    # Sign the transaction
    signed_tx = web3.eth.account.sign_transaction(tx, preset_private_key)

    # Send the transaction
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

    # Wait for the transaction to be mined
    web3.eth.wait_for_transaction_receipt(tx_hash)

    # Return the transaction hash
    return tx_hash.hex()

def create_new_eth_account():
    web3 = Web3()
    account = web3.eth.account.create()
    return account.address, account.private_key.hex()

    # We encrypt using their wallet keys if they have a wallet (the key fragments themselves)
        # Otherwise we use auto-generated keys encrypted with user passwords


def mint_nft(claim_id, user_address, token_uri):
    """
    Function to mint an NFT using the VerifyNFT contract.
    """
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.getTransactionCount(account.address)

    transaction = verify_nft_contract.functions.mintNFT(
        claim_id,
        Web3.toChecksumAddress(user_address),
        token_uri
    ).buildTransaction({
        'chainId': 1,  # Replace with your network chain ID
        'gas': 500000,
        'gasPrice': web3.toWei('20', 'gwei'),
        'nonce': nonce
    })

    signed_txn = web3.eth.account.signTransaction(transaction, private_key=private_key)
    txn_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)

    return txn_hash.hex()


def extract_claim_id_from_receipt(receipt):
    # Assuming the event 'ClaimCreated' is emitted by your contract when a claim is created
    claim_created_event_abi = {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "_claimId", "type": "bytes32"},
            {"indexed": True, "name": "_requester", "type": "address"},
            {"indexed": True, "name": "_authority", "type": "address"},
            {"indexed": False, "name": "_ipfsHash", "type": "string"}
        ],
        "name": "ClaimCreated",
        "type": "event"
    }

    event_signature_hash = web3.keccak(text='ClaimCreated(uint256,address,address,string)')

    for log in receipt['logs']:
        if log['topics'][0] == event_signature_hash:
            claim_id = Web3.to_hex(log['topics'][1])  # Extract the claim ID from the first topic
            return claim_id.lstrip('0x').lstrip('0')

    raise Exception("ClaimCreated event not found in transaction receipt")


"""def prepare_transaction_data(request):
    web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    # Extract necessary form data
    year_of_graduation = request.POST.get('year_of_graduation')
    student_number = request.POST.get('student_number')
    full_name = request.POST.get('full_name')
    authority_address = request.POST.get('authority')

    # Encrypt the claim data
    claim_data = f"{year_of_graduation},{student_number},{full_name}"
    encrypted_data, shares = encrypt_and_split(claim_data)

    # Upload encrypted data to IPFS and get IPFS hash
    ipfs_hash = upload_to_ipfs(encrypted_data)

    # Prepare the transaction for the blockchain
    wallet_address = Web3.to_checksum_address(request.user.address)

    with open('build/contracts/Verify.json') as f:
        contract_data = json.load(f)
        contract_abi = contract_data['abi']
    contract_address = settings.CONTRACT_ADDRESS
    verify_contract_instance = web3.eth.contract(address=contract_address, abi=contract_abi)


    transaction = verify_contract_instance.functions.createClaim(
        _requester=wallet_address,
        _authority=authority_address,
        _yearOfGraduation=year_of_graduation,
        _studentNumber=student_number,
        _fullName=full_name,
        _ipfsHash=ipfs_hash
    ).build_transaction({
        'chainId': 1337,  # Ganache chain ID
        'gas': 500000,
        'gasPrice': Web3.to_wei('50', 'gwei'),
        'nonce': web3.eth.get_transaction_count(wallet_address),
    })

    return transaction"""
