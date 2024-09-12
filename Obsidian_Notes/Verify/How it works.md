
It works as such:

There are 3 roles: Dapp, Claimant, Authority

The dapp handles the communication between the claimant and authority
There is also a smart contract residing on ETH chain

The claimant submits a claim to the authority (in this iteration, the claimant is a graduate of a university and the authority is a university), the claimant uploads a chunk of data to the server, information the authority needs to verify the claimant's legitimacy to the claim, this then gets encrypted using shamir 2-of-3, and fragments are distributed as such:
1:1:1 claimant:authority:dapp

The encrypted file is then uploaded to IPFS, the hash of the file is recorded on the blockchain along with some metadata

The authority then picks this up, decrypts it, runs the smart contract again to provide a digital signature and this then gets minted into an NFT

The key here is - I have 2 types of profiles
1 is metamask wallet holders that are able to sign things on their own
1 are django users that make account using uname/psswd combo

First of all - posit on ways that I can allow the django users to utilize my platform and with that the blockchain if they don't have a wallet (initially or at all)