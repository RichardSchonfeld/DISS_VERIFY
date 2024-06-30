const Web3 = require('web3');
const web3 = new Web3('http://127.0.0.1:8545');

contract('Accounts', () => {
    it('should print accounts and labances', async () => {
        const accounts = await web3.eth.getAccounts();
        for (let account of accounts) {
            let balance = await web.eth.getBalance(account);
            console.log('Account: ${account}, Balance: ${web3.utils.fromWei(balance, "ether")}');
        }
    })
});