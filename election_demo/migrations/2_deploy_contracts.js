var Election = artifacts.require("./Election.sol");

/*
Artifact = contract abstraction specific to truffle, exposes it as interactable
1. Migrations read from project directory
2. Assign to a variable called migrations
3. Refrence variable
 */

module.exports = function(deployer) {
  deployer.deploy(Election);
};
// Look into JS promises :
// I.e. Election.deployed().then(function(instance) { app = instance })
  // Async so JS promises required for requests
  // Promises handle eventual results of asyncs operations
  // Returns a promise, we then call .then(..) function on the promise
    // Gets executed once the promise finishes
    // Promise takes a callback function where we inject instance of the app
    // Assign instance to an app variable - aka store the app into a variable