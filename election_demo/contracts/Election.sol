pragma solidity ^0.5.16;

// We're writing a VOTING PLATFORM as demo/training :)

contract Election {
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
}