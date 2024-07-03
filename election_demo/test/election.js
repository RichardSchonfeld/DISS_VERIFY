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

  it("votes for an account and test if account has been marked as voted", function() {
      return Election.deployed().then(function(_instance) {
          instance = _instance;
          candidateId = 1;
          return instance.vote(candidateId, {from: accounts[1] });
      }).then(function(receipt) {
          return instance.voters(accounts[1]);
      }).then(function(voted) {
          assert(voted, "Acc marked as voted");
          return instance.candidates(candidateId);
      }).then(function(candidate) {
          var voteCount = candidate[2];
          assert.equal(voteCount, 1, "vote count incremented successfully");
      }).then(function() {
          return instance.vote(candidateId, {from: accounts[1] });
      }).then(function() {
          return instance.candidates(candidateId)
      }).then(function(candidate) {
          var voteCount = candidate[2];
          assert.equal(voteCount, 1, "second vote attempt blocked successfully!");
      });
    });
});