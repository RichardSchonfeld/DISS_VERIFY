pragma solidity ^0.5.4;

contract Verify {
    struct ClaimData {
        address requester;
        address authority;
        string yearOfGraduation;
        string studentNumber;
        string fullName;
        string ipfsHash;
        bool signed;
    }

    mapping(uint256 => ClaimData) public claims;
    uint256 public claimCount;

    event ClaimCreated(uint256 indexed claimId, address indexed initiator, address indexed authority, string ipfsHash);
    event ClaimSigned(uint256 indexed claimId, address indexed authority);

    function createClaim(
        address _requester,
        address _authority,
        string memory _yearOfGraduation,
        string memory _studentNumber,
        string memory _fullName,
        string memory _ipfsHash
    ) public {
        claimCount++;
        claims[claimCount] = ClaimData({
            requester: _requester,
            authority: _authority,
            yearOfGraduation: _yearOfGraduation,
            studentNumber: _studentNumber,
            fullName: _fullName,
            ipfsHash: _ipfsHash,
            signed: false
        });
        emit ClaimCreated(claimCount, _requester, _authority, _ipfsHash);
    }

    function signClaim(uint256 _claimId) public {
        ClaimData storage claim = claims[_claimId];
        require(msg.sender == claim.authority, "Only the designated authority can sign this claim");
        require(!claim.signed, "Claim is already signed");
        claim.signed = true;
        emit ClaimSigned(_claimId, msg.sender);
    }

    function getClaim(uint256 _claimId) public view returns (
        address requester,
        address authority,
        string memory yearOfGraduation,
        string memory studentNumber,
        string memory fullName,
        string memory ipfsHash,
        bool signed
    ) {
        ClaimData storage claim = claims[_claimId];
        return (
            claim.requester, claim.authority, claim.yearOfGraduation,
            claim.studentNumber, claim.fullName, claim.ipfsHash, claim.signed
        );
    }
}
