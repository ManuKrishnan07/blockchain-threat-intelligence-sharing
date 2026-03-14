import json
import os
from solcx import compile_standard, install_solc
from web3 import Web3

GANACHE_URL          = os.getenv("GANACHE_URL", "http://ganache:8545")
CONTRACT_CONFIG_PATH = os.getenv("CONTRACT_CONFIG_PATH", "/app/contract_config.json")
SOLC_VERSION         = "0.8.0"

# Contract source embedded so deploy.py works standalone inside the container
CONTRACT_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ThreatIntelRegistry {

    struct ThreatIndicator {
        string   dataHash;
        address  reporter;
        string   indicatorType;
        string   threatCategory;
        uint256  timestamp;
        bool     exists;
    }

    mapping(string => ThreatIndicator) private indicators;
    string[] public indicatorHashes;
    address  public owner;

    event IndicatorAdded(
        string  indexed dataHash,
        address indexed reporter,
        uint256         timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function addThreatIndicator(
        string memory _dataHash,
        string memory _indicatorType,
        string memory _threatCategory,
        uint256       _timestamp
    ) public {
        require(!indicators[_dataHash].exists, "Indicator already exists");

        indicators[_dataHash] = ThreatIndicator({
            dataHash:      _dataHash,
            reporter:      msg.sender,
            indicatorType: _indicatorType,
            threatCategory:_threatCategory,
            timestamp:     _timestamp,
            exists:        true
        });

        indicatorHashes.push(_dataHash);
        emit IndicatorAdded(_dataHash, msg.sender, _timestamp);
    }

    function verifyIndicator(string memory _dataHash)
        public view
        returns (bool exists, address reporter, uint256 timestamp)
    {
        require(indicators[_dataHash].exists, "Indicator not found");
        ThreatIndicator memory ind = indicators[_dataHash];
        return (true, ind.reporter, ind.timestamp);
    }

    function getTotalIndicators() public view returns (uint256) {
        return indicatorHashes.length;
    }
}
"""


def main():
    print("Step 1/5 — Installing Solidity compiler v0.8.0 ...")
    install_solc(SOLC_VERSION)
    print("           Compiler ready.")

    print("Step 2/5 — Compiling ThreatIntelRegistry ...")
    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {
                "ThreatIntelRegistry.sol": {"content": CONTRACT_SOURCE}
            },
            "settings": {
                "outputSelection": {
                    "*": {"*": ["abi", "evm.bytecode"]}
                }
            },
        },
        solc_version=SOLC_VERSION,
    )

    contract_data = compiled["contracts"]["ThreatIntelRegistry.sol"]["ThreatIntelRegistry"]
    abi      = contract_data["abi"]
    bytecode = contract_data["evm"]["bytecode"]["object"]
    print("           Compilation successful.")

    print(f"Step 3/5 — Connecting to blockchain at {GANACHE_URL} ...")
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {GANACHE_URL} — is Ganache running?")
        return

    deployer = w3.eth.accounts[0]
    w3.eth.default_account = deployer
    print(f"           Connected. Deployer: {deployer}")

    print("Step 4/5 — Deploying contract ...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash  = Contract.constructor().transact({"from": deployer})
    receipt  = w3.eth.wait_for_transaction_receipt(tx_hash)

    address = receipt.contractAddress
    print(f"           ✅ Contract deployed to: {address}")

    print(f"Step 5/5 — Saving config to {CONTRACT_CONFIG_PATH} ...")
    config = {"contract_address": address, "abi": abi}
    with open(CONTRACT_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    print(f"           ✅ Config saved.")
    print("\n🎉 Deployment complete! The backend will use this contract automatically.")


if __name__ == "__main__":
    main()