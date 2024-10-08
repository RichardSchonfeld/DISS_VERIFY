// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Used to deploy smart contract to a local BC n make it interactable

contract Migrations {
  address public owner = msg.sender;
  uint public last_completed_migration;

  modifier restricted() {
    require(
      msg.sender == owner,
      "This function is restricted to the contract's owner"
    );
    _;
  }

  function setCompleted(uint completed) public restricted {
    last_completed_migration = completed;
  }
}
