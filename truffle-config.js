const HDWalletProvider = require('@truffle/hdwallet-provider');
require('dotenv').config(); // Load environment variables from .env file

const mnemonic = process.env.MNEMONIC;
const infuraProjectId = process.env.INFURA_PROJECT_ID;

module.exports = {
  networks: {
    sepolia: {
      provider: () => new HDWalletProvider(mnemonic, 'https://sepolia.infura.io/v3/813a1ccfc5874e07956829e7876fd311'),
      network_id: 11155111, // Sepolia network ID
      chain_id: 11155111,
      gas: 6000000, // Gas limit
      gasPrice: 10000000000, // 10 Gwei
    },
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*" // Match any network id
    },
    develop: {
      port: 8545
    }
  },
  compilers: {
    solc: {
      version: '0.8.0', // Solidity version
    },
  },
};
