App = {
  web3Provider: null,
  contracts: {},
  account: '0x0',
  hasVoted: false,

  init: async function() {
    console.log("Initializing app...");
    return await App.initWeb3();
  },

  initWeb3: async function() {
    console.log("Initializing web3...");
    if (window.ethereum) {
      App.web3Provider = window.ethereum;
      try {
        // Request account access
        await window.ethereum.request({ method: "eth_requestAccounts" });
        web3 = new Web3(window.ethereum);
        console.log("Ethereum provider detected and accessed.");
      } catch (error) {
        console.error("User denied account access");
      }
    } else if (window.web3) { // Legacy dapp browsers...
      App.web3Provider = window.web3.currentProvider;
      web3 = new Web3(window.web3.currentProvider);
      console.log("Legacy web3 provider detected.");
    } else { // Non-dapp browsers...
      console.log('Non-Ethereum browser detected. You should consider trying MetaMask!');
      App.web3Provider = new Web3.providers.HttpProvider('http://localhost:8545');
      web3 = new Web3(App.web3Provider);
    }
    return App.initContract();
  },

  /*initContract: function() {
    console.log("Initializing contract...");
    $.getJSON("Election.json", function(election) {
      App.contracts.Election = TruffleContract(election);
      App.contracts.Election.setProvider(App.web3Provider);
      console.log("Contract initialized.");
      App.listenForEvents();
      return App.render();
    });
  },*/

  initContract: function() {
    console.log("Initializing contract...");
    $.getJSON("Verify.json", function(election) {
      App.contracts.Verify = TruffleContract(verify);
      App.contracts.Verify.setProvider(App.web3Provider);
      console.log("Contract initialized");
      App.listenForEvents();
      return App.render();
    });
  },

  /*listenForEvents: function() {
    console.log("Setting up event listeners...");
    App.contracts.Election.deployed().then(function(instance) {
      instance.VotedEvent({}, {
        fromBlock: 0,
        toBlock: 'latest'
      }).on('data', function(event) {
        console.log("event triggered", event);
        App.render();
      }).on('error', console.error);
    });
  },*/

  listenForEvents: function() {
    console.log("Setting up event listeners...");
    App.contracts.Verify.deployed().then(function(instance) {
      instance.getClaim({}, {
        fromBlock: 0,
        toBlock: 'latest'
      }).on('data', function(event) {
        console.log("event triggered", claim);
        App.render();
      }).on('error', console.error);
    });
  },

  // NEW FUNC
  /*listenForEvents: function() {
    console.log("Seting up event listeners...");
    App.contracts.Verify.deployed().then(function(instance) {
      instance.
    })
  }*/

  /*render: function() {
    console.log("Rendering app...");
    var electionInstance;
    var loader = $("#loader");
    var content = $("#content");

    loader.show();
    //content.hide();
    content.show();

    // Load account data
    web3.eth.getCoinbase(function(err, account) {
      if (err === null) {
        App.account = account;
        $("#accountAddress").html("Your Account: " + account);
        console.log("Account loaded: " + account);
      } else {
        console.error("Error getting coinbase account", err);
      }
    });*/

    render: function() {
      console.log("Rendering app...");
      var verityInstance;
      var loader = $("#loader");
      var content = $("#content");

      loader.show();
      content.show();
      web3.eth.getCoinbase(function(err, account) {
        if(err === null) {
          App.account = account;
          $("#accountAddress").html("Your Account: " + account);
          console.log("Account loaded: " + account);
        } else {
          console.error("Error getting coinbase account", err);
        }
      });
    },

    /* Load contract data
    App.contracts.Election.deployed().then(function(instance) {
      electionInstance = instance;
      return electionInstance.candidatesCount();
    }).then(function(candidatesCount) {
      console.log("Candidates count: " + candidatesCount);
      var candidatesResults = $("#candidatesResults");
      candidatesResults.empty();

      var candidatesSelect = $('#candidatesSelect');
      candidatesSelect.empty();

      for (var i = 1; i <= candidatesCount; i++) {
        electionInstance.candidates(i).then(function(candidate) {
          var id = candidate[0];
          var name = candidate[1];
          var voteCount = candidate[2];

          // Render candidate Result
          var candidateTemplate = "<tr><th>" + id + "</th><td>" + name + "</td><td>" + voteCount + "</td></tr>"
          candidatesResults.append(candidateTemplate);

          // Render candidate ballot option
          var candidateOption = "<option value='" + id + "'>" + name + "</option>"
          candidatesSelect.append(candidateOption);
        });
      }
      return electionInstance.voters(App.account);
    }).then(function(hasVoted) {
      console.log("Has voted: " + hasVoted);
      if (hasVoted) {
        $('form').hide();
      }
      loader.hide();
      content.show();
    }).catch(function(error) {
      console.warn(error);
    })
  },*/

  App.contracts.Verify.deployed().then(function(_instance) {
    instance = _instance;
    return instance.claimCount();
  }).then(function(claimCount) {
    console.log("Claim count: " + claimCount);
    var claimResults = $("#claimResults");
    claimResults.empty();

    for (var i = 1; i <= claimCount; i++) {
      instance.getClaim(i).then(function(claim) {
        var requester = claim["requester"];
        var authority = claim["authority"];
        var yearOfGraduation = claim["yearOfGraduation"];
        var studentNumber = claim["studentNumber"];
        var fullName = claim["fullName"];
        var signed = claim["signed"];

        // Render claim result
        var claimTemplate = "<tr><th>" + requester + "</th><td>" + authority + "</td>" + "<th><td>" + yearOfGraduation + "</td></th>"


      });
    }
  }),
/*
  castVote: function() {
    var candidateId = $('#candidatesSelect').val();
    console.log("Casting vote for candidate ID: " + candidateId);
    App.contracts.Election.deployed().then(function(instance) {
      return instance.vote(candidateId, { from: App.account });
    }).then(function(result) {
      console.log("Vote casted, waiting for confirmation...");
      $("#content").hide();
      $("#loader").show();
    }).catch(function(err) {
      console.error("Error casting vote", err);
    });
  }
};*/

$(function() {
  $(window).load(function() {
    App.init();
  });
});
