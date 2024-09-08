pragma solidity ^0.5.4;

contract Verify {
    struct ClaimData {
        address requester;
        address authority;
        string ipfsHash;
        string certHash;        // Changed from bytes32 to string
        string signature;       // Changed from bytes to string
        bool signed;
    }

    mapping(uint256 => ClaimData) public claims;
    mapping(address => uint256[]) public claimsByAddress;
    uint256 public claimCount;

    event ClaimCreated(uint256 indexed claimId, address indexed initiator, address indexed authority, string ipfsHash);
    event ClaimSigned(uint256 indexed claimId, address indexed authority, string certHash, string signature);  // Adjusted event types

    function createClaim(
        address _requester,
        address _authority,
        string memory _ipfsHash
    ) public {
        claimCount++;
        claims[claimCount] = ClaimData({
            requester: _requester,
            authority: _authority,
            ipfsHash: _ipfsHash,
            certHash: "",               // Initialize to empty string
            signature: "",               // Initialize to empty string
            signed: false
        });

        claimsByAddress[_requester].push(claimCount);
        claimsByAddress[_authority].push(claimCount);

        emit ClaimCreated(claimCount, _requester, _authority, _ipfsHash);
    }

    function signClaim(
        uint256 _claimId,
        string memory _certificateHash,    // Changed to string
        string memory _signature           // Changed to string
    ) public {
        ClaimData storage claim = claims[_claimId];
        require(msg.sender == claim.authority, "Only the designated authority can sign this claim");
        require(!claim.signed, "Claim is already signed");

        // Update the claim data with the certificate hash and signature
        claim.signed = true;
        claim.certHash = _certificateHash;  // Set string value
        claim.signature = _signature;       // Set string value

        // Emit event for the signed claim with the string values
        emit ClaimSigned(_claimId, msg.sender, _certificateHash, _signature);
    }

    function getCertHashAndSignature(uint256 _claimId) public view returns (string memory, string memory) {
        ClaimData storage claim = claims[_claimId];
        require(claim.signed, "Claim not signed");

        return (claim.certHash, claim.signature);  // Return string values
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
