require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: "../.env" });

module.exports = {
  solidity: {
    version: "0.8.19",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    // Hardhat built-in node  →  npx hardhat node
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    // Ganache GUI / CLI  →  ganache --port 7545
    ganache: {
      url: process.env.BLOCKCHAIN_URL || "http://127.0.0.1:7545",
      chainId: 1337,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : undefined,
    },
  },
  paths: {
    artifacts: "./artifacts",
    cache:     "./cache",
  },
};



