pragma solidity ^0.5.16;

// We're writing a VOTING PLATFORM as demo/training :)

contract Election {
    // Store Candidate

    // Read Candidate
    string public candidate;

    // Constructor - used to deploy SM to BC so needs public scope
     constructor() public {
        candidate = "Candidate 1"; //No underscore = state variable

    }

}