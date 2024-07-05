pragma solidity ^0.5.16;

// We're writing a VOTING PLATFORM as demo/training :)

contract DEP_Election {
    // Model candidate
    struct Candidate {
        uint id;
        string name;
        uint voteCount;
    }
    // Store candidate

    // Fetch candidate
     // Key here corresponds to candidate's ID
        // Returns blank candidate for any non-existing mapping request
        // Makes it impossible to determine how big the mapping is
    mapping(uint => Candidate) public candidates;

    // Store accs that already voted
    // Takes account key (address) and rets a Bool value
    mapping(address => bool) public voters;

    // Store candidate count
    uint public candidatesCount;

    /* CONSTRUCTOR */
    constructor() public {
        addCandidate("Candidate 1");
        addCandidate("Candidate 2");
    }

    /* FUNCTIONS */

    function addCandidate(string memory _name) private {
        candidatesCount++;
        candidates[candidatesCount] = Candidate(candidatesCount, _name, 0);
    }

    function vote(uint _candidateId) public { // Public - external accounts can call this function
        // Not just available to the contract account, others can call aswell
        // Yes, now process below:

        // 1. Record voter has voted
            // How do we know which acc has voted?
            // Solidity passes metadata above defined args, part of which can be person sending function

        require(!voters[msg.sender]);
        //require a valid candidate
        require(_candidateId > 0 && _candidateId <= candidatesCount);
        voters[msg.sender] = true;
        candidates[_candidateId].voteCount++;
            // https://coinsbench.com/how-to-deploy-and-interact-with-solidity-contracts-with-python-and-ganache-be63334323e6
    }
}