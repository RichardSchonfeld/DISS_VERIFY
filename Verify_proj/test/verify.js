// Uses MochaJS and Chai
var Verify = artifacts.require("./Verify.sol");
/*
contract("Election", function(accounts) {
  it("initializes with two candidates", function() {
      return Verify.deployed().then(function(instance) {
          return instance.candidatesCount();

      }).then(function(count) {
          assert.equal(count, 2);
      });
  });
*/
contract("Verify", function(accounts) {
    it("create a new claim", function() {
        return Verify.deployed().then(function(_instance) {
            instance = _instance;
            account_requester = accounts[0];
            account_authority = accounts[1];
            console.log(account_requester);
            console.log(account_authority);
            return instance.createClaim(account_requester, account_authority, "1999", "26", "Richard Sch.");
        }).then(async function(claim) {
            console.log("BLABLABLBLABLALALALBALABLABLLBALABLABLA");
            console.log(claim);
            claimCreated = await instance.getClaim(1);
            console.log("CLAIM CREATED CLAIM CREATED CLAIM CREATED CLAIM CRETED");
            console.log("-----------------------A");
            console.log(claimCreated);
            console.log("-----------------------B");
            assert.equal(claimCreated["requester"], account_requester);
            assert.equal(claimCreated["authority"], account_authority);
            assert.equal(claimCreated["studentNumber"], 26);
        });
    })
});
/*
  it("initializes with a candidate and displays name", function() {
      return Verify.deployed().then(function(instance) {
          return instance.candidates(1);
      }).then(function(candidate) {
          assert.equal("Candidate 1", candidate.name);
      });
  });

  it("votes for an account and test if account has been marked as voted", function() {
      return Verify.deployed().then(function(_instance) {
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
});*/