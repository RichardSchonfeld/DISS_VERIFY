from django.conf import settings
from web3 import Web3
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
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

def create_claim(requester_address, authority_address, year_of_graduation, student_number, full_name, ipfs_hash):
    nonce = web3.eth.getTransactionCount(requester_address)
    txn = contract.functions.createClaim(
        requester_address, authority_address, year_of_graduation, student_number, full_name, ipfs_hash
    ).buildTransaction({
        'from': requester_address,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
    })
    private_key = settings.PRIVATE_KEY
    signed_txn = web3.eth.account.signTransaction(txn, private_key=private_key)
    tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return tx_hash.hex()

def sign_claim(claim_id, authority_address, signature):
    nonce = web3.eth.getTransactionCount(authority_address)
    txn = contract.functions.signClaim(claim_id, signature).buildTransaction({
        'from': authority_address,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
    })
    private_key = settings.PRIVATE_KEY
    signed_txn = web3.eth.account.signTransaction(txn, private_key=private_key)
    tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return tx_hash.hex()
