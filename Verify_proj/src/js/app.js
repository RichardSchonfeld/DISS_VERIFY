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

  initContract: function() {
    console.log("Initializing contract...");
    // **Edited Section**
    $.getJSON("Verify.json", function(verify) {
      App.contracts.Verify = TruffleContract(verify);
      App.contracts.Verify.setProvider(App.web3Provider);
      console.log("Contract initialized");
      App.listenForEvents();
      return App.render();
    });
  },

  listenForEvents: function() {
    console.log("Setting up event listeners...");
    App.contracts.Verify.deployed().then(function(instance) {
      // **Edited Section**
      instance.ClaimEvent({}, {
        fromBlock: 0,
        toBlock: 'latest'
      }).on('data', function(event) {
        console.log("event triggered", event);
        App.render();
      }).on('error', console.error);
    });
  },

  render: function() {
    console.log("Rendering app...");
    var verifyInstance;
    var loader = $("#loader");
    var content = $("#content");

    loader.show();
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
    });

    // **Edited Section**
    // Load contract data
    App.contracts.Verify.deployed().then(function(instance) {
      verifyInstance = instance;
      return verifyInstance.claimCount();
    }).then(function(claimCount) {
      console.log("Claim count: " + claimCount);
      var claimResults = $("#claimResults");
      claimResults.empty();

      for (var i = 1; i <= claimCount; i++) {
        verifyInstance.getClaim(i).then(function(claim) {
          /*var requester = claim["requester"];
          var authority = claim["authority"];
          var yearOfGraduation = claim["yearOfGraduation"];
          var studentNumber = claim["studentNumber"];
          var fullName = claim["fullName"];
          var signed = claim["signed"];*/

          var requester = claim[0];
          var authority = claim[1];
          var yearOfGraduation = claim[2];
          var studentNumber = claim[3];
          var fullName = claim[4];
          var signed = claim[5];


          // Render claim result
          // **Edited Section**
          var claimTemplate = "<tr><th>" + requester + "</th><td>" + authority + "</td><td>" + yearOfGraduation + "</td></tr>";
          claimResults.append(claimTemplate);
        });
      }
      loader.hide();
      content.show();
    }).catch(function(error) {
      console.warn(error);
    });
  }
};

$(function() {
  $(window).load(function() {
    App.init();
  });
});
