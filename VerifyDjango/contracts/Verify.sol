pragma solidity ^0.8.0;

contract Verify {
    struct ClaimData {
        address requester;
        address authority;
        string ipfsHash;
        string signature;
        bool signed;
    }

    mapping(uint256 => ClaimData) public claims;
    mapping(address => uint256[]) public claimsByAddress;
    uint256 public claimCount;

    event ClaimCreated(uint256 indexed claimId, address indexed initiator, address indexed authority, string ipfsHash);
    event ClaimSigned(uint256 indexed claimId, address indexed authority, string signature, string ipfsHash);

    function createClaim(
        address _requester,
        address _authority,
        string memory _ipfsHash
    ) public {
        claimCount += 1;

        // Log the claim data being created
        claims[claimCount] = ClaimData({
            requester: _requester,
            authority: _authority,
            ipfsHash: _ipfsHash,
            signature: "",
            signed: false
        });

        // Push claim ID to claimsByAddress and emit them
        claimsByAddress[_requester].push(claimCount);
        claimsByAddress[_authority].push(claimCount);

        // Emit the final ClaimCreated event
        emit ClaimCreated(claimCount, _requester, _authority, _ipfsHash);
    }

    function signClaim(
        uint256 _claimId,
        string memory _signature,
        string memory _ipfsHash  // Add ipfsHash parameter
    ) public {
        ClaimData storage claim = claims[_claimId];
        require(msg.sender == claim.authority, "Only the designated authority can sign this claim");
        require(!claim.signed, "Claim is already signed");

        // Update the claim data with the signature and new IPFS hash
        claim.signed = true;
        claim.signature = _signature;
        claim.ipfsHash = _ipfsHash;  // Overwrite the existing IPFS hash

        // Emit event for the signed claim
        emit ClaimSigned(_claimId, msg.sender, _signature, _ipfsHash);
    }

    function getCertSignature(uint256 _claimId) public view returns (string memory) {
        ClaimData storage claim = claims[_claimId];
        require(claim.signed, "Claim not signed");

        return claim.signature;
    }

    function getClaim(uint256 _claimId) public view returns (
        address requester,
        address authority,
        string memory ipfsHash,
        bool signed
    ) {
        ClaimData storage claim = claims[_claimId];
        return (
            claim.requester,
            claim.authority,
            claim.ipfsHash,
            claim.signed
        );
    }

    function getClaimsByAddress(address _address) public view returns (uint256[] memory) {
        return claimsByAddress[_address];
    }
}
