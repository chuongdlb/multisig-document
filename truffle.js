require('babel-register')({
  ignore: /node_modules\/(?!openzeppelin-solidity)/
});
require('babel-polyfill');

module.exports = {
  networks: {
   development: {
     host: "127.0.0.1",
     port: 8545,
     network_id: "5",// Match any network id


   }
  }
};
