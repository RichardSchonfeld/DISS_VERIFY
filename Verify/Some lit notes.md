
A trusted Approach for Decentralised and Privacy-Preserving Identity Management [source](https://ieeexplore.ieee.org/abstract/document/9495805)

Blockchain Credential repository https://arxiv.org/pdf/1904.00315




Key points:
1. What is a user loses their Pk, this is a problem, A could pretend to be someone who lost their key and more problem (like with X.509 certs)
2. Centralized issues IdPs like SAML if compromised leak all private information



Related otherwise:
- Why ethereum? We already have a blockchain! BTC!



# GPT future -proofing security

I'm a little concerned about some privacy aspects, like for instance, say that I expand this into the future inot something that is less related to university diplomas and more related to CVs and their signing: I want to mitigate a possibility where someone who doesn't want others to knowthey've worked at a particular employed publically unless they decide that they want others to know could have this exposed because public keys are public and the system is one that is pseudonymous meaning if you know the public key of a particular entity and someone requests to have something siged there you could know that that person has likely had some affiliation with the entity

ChatGPT

To address your concerns about privacy and the possibility of sensitive information being exposed, especially in a system that involves pseudonymous identities and public keys, here are some strategies you could consider:

### 1. **Private Verification Mechanism**

- **Zero-Knowledge Proofs (ZKPs)**:
    - **What It Is**: ZKPs allow one party to prove to another that a statement is true without revealing any specific information beyond the validity of the statement itself.
    - **Application**: You could implement a system where a user’s affiliation with a particular entity (e.g., employer) is verified via ZKP, without revealing the entity's identity to the public. The proof would confirm the validity of the claim without exposing the public key of the entity or the specific details of the relationship.
    - **Benefit**: This method ensures that only the relevant parties know about the affiliation, protecting user privacy while maintaining the integrity of the verification process.

### 2. **Selective Disclosure Using Encryption**

- **Encrypted Affiliation**:
    - **How It Works**: The information about a user’s affiliation with an entity (e.g., employment at a company) could be encrypted using the public key of the entity. Only the entity or authorized parties can decrypt and verify this information.
    - **Controlled Access**: Users can choose who to share the decryption key with, allowing them to control who knows about their affiliation.
    - **Benefit**: This ensures that even if the NFT or CV is public, the sensitive affiliation details are not disclosed unless the user decides to share the decryption key.

### 3. **Pseudonymous Identity Layer**

- **Use of Identity Providers**:
    - **What It Is**: Implement a system where the entity (e.g., employer) uses an identity provider to handle signatures and verifications. The identity provider could issue pseudonymous credentials that do not directly reveal the entity’s identity.
    - **Implementation**: The user’s public key is linked to a pseudonymous identifier rather than the actual entity, masking the true identity unless the user decides to disclose it.
    - **Benefit**: This approach adds an additional layer of privacy by separating the user’s public identity from their affiliations.

### 4. **Decentralized Identity (DID) and Verifiable Credentials**

- **DID Systems**:
    - **How It Works**: Decentralized Identifiers (DIDs) allow for verifiable, self-sovereign identities that are not tied to a specific entity or public key. Verifiable credentials linked to a DID can be used to assert claims (e.g., employment) without exposing the underlying details publicly.
    - **Selective Disclosure**: Users can control which aspects of their credentials are shared and with whom, allowing them to prove certain claims (like employment history) without revealing sensitive information.
    - **Benefit**: This method allows for strong privacy controls, giving users the power to manage how much information is disclosed.

### 5. **Anonymous Credential Systems**

- **Blind Signatures**:
    - **How It Works**: Blind signatures allow an entity to sign a document or credential without knowing the content of what they are signing. This could be used to issue anonymous credentials that can later be verified without revealing the relationship between the user and the entity.
    - **Application**: Users could request a blind signature from an employer, proving their employment without exposing their identity or the employer's identity in the public domain.
    - **Benefit**: This ensures privacy in the signing process and reduces the risk of exposing affiliations.

### Summary

- **Zero-Knowledge Proofs** and **Selective Disclosure** using encryption are advanced methods to ensure that sensitive affiliations are not publicly exposed unless explicitly chosen by the user.
- **Pseudonymous Identity Layers** and **Decentralized Identity Systems** provide frameworks where identities and credentials can be managed privately and securely, giving users more control over their personal information.
- **Anonymous Credential Systems** offer an additional layer of privacy by allowing entities to verify or sign credentials without fully understanding or exposing the content.

These approaches help mitigate the risk of unwanted exposure in a system that manages sensitive information like employment history or other affiliations, while still maintaining the integrity and verifiability of the information when necessary.


# Shamir approaches
### 1. **Direct Distribution to Stakeholders**

- **How:** Each share is directly given to the user (via MetaMask or email), the authority (university), and the dApp (smart contract).
- **Pros:** Simple and secure.
- **Cons:** Risk if any party loses their share.

### 2. **Multi-Signature Contract**

- **How:** A smart contract holds the shares, requiring both user and authority to sign off before releasing them.
- **Pros:** High security and transparency.
- **Cons:** More complex and higher gas costs.

### 3. **Decentralized Storage with Redundancy**

- **How:** Store shares in decentralized storage like IPFS, with multiple nodes for redundancy.
- **Pros:** Decentralized and resilient.
- **Cons:** Can be slower and more complex.

### 4. **Threshold-Based DAO**

- **How:** A DAO holds the shares and releases them only after a majority vote.
- **Pros:** Highly decentralized and secure.
- **Cons:** Complex governance and coordination required.