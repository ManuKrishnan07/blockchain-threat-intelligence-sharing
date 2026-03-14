require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.0",
  networks: {
    ganache: {
      url:      "http://127.0.0.1:7545",
      chainId:  1337,
      accounts: {
        mnemonic: "test test test test test test test test test test test junk"
      }
    }
  }
};