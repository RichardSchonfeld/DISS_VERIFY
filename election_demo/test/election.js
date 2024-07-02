// Uses MochaJS and Chai
var Election = artifacts.require("./Election.sol");

contract("Election", function(accounts) {
  it("initializes with two candidates", function() {
      return Election.deployed().then(function(instance) {
          return instance.candidatesCount();

      }).then(function(count) {
          assert.equal(count, 2);
      });
  });

  it("initializes with a candidate and displays name", function() {
      return Election.deployed().then(function(instance) {
          return instance.candidates(1);
      }).then(function(candidate) {
          assert.equal("Candidate 1", candidate.name);
      });
  });
});