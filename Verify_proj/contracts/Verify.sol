pragma solidity ^0.5.4;

contract Verify {
    struct ClaimData {
        address requester;
        address authority;
        string yearOfGraduation;
        string studentNumber;
        string fullName;
        bool signed;
    }

    mapping(uint256 => ClaimData) public claims;
    uint256 public claimCount;

    event ClaimCreated(uint256 indexed claimId, address indexed initiator, address indexed authority);
    event ClaimSigned(uint256 indexed claimId, address indexed authority);

    function createClaim(address _requester, address _authority, string memory _yearOfGraduation, string memory _studentNumber, string memory _fullName) public {
        claimCount++;
        claims[claimCount] = ClaimData({
            requester: msg.sender,
            authority: _authority,
            yearOfGraduation: _yearOfGraduation,
            studentNumber: _studentNumber,
            fullName: _fullName,
            signed: false
        });
        emit ClaimCreated(claimCount, msg.sender, _requester);
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
        bool signed
    ) {
        ClaimData storage claim = claims[_claimId];
        return (
            claim.requester, claim.authority, claim.yearOfGraduation,
            claim.studentNumber, claim.fullName, claim.signed
        );
    }

    function claimCount() public {
        for
    }
}