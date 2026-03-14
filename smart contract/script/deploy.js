const { ethers, network } = require("hardhat");
const fs   = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`\nDeploying ThreatIntelRegistry on "${network.name}"`);
  console.log(`Deployer : ${deployer.address}`);
  console.log(`Balance  : ${ethers.utils.formatEther(await deployer.getBalance())} ETH\n`);

  const Factory  = await ethers.getContractFactory("ThreatIntelRegistry");
  const contract = await Factory.deploy();
  await contract.deployed();

  console.log(`✔  Contract deployed at : ${contract.address}`);
  console.log(`   Transaction hash      : ${contract.deployTransaction.hash}\n`);

  // ── Write deployment artefacts to backend ──────────────────────────────
  const abi        = JSON.parse(contract.interface.format("json"));
  const deployInfo = {
    contractAddress : contract.address,
    deployer        : deployer.address,
    network         : network.name,
    chainId         : (await ethers.provider.getNetwork()).chainId,
    deployedAt      : new Date().toISOString(),
    abi,
  };

  const backendDir = path.join(__dirname, "../../backend");
  if (!fs.existsSync(backendDir)) fs.mkdirSync(backendDir, { recursive: true });

  const infoPath = path.join(backendDir, "contract_info.json");
  fs.writeFileSync(infoPath, JSON.stringify(deployInfo, null, 2));
  console.log(`✔  Contract info saved → ${infoPath}`);

  // ── Update .env with contract address ──────────────────────────────────
  const envPath = path.join(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    let env = fs.readFileSync(envPath, "utf8");
    if (env.includes("CONTRACT_ADDRESS=")) {
      env = env.replace(/CONTRACT_ADDRESS=.*/g, `CONTRACT_ADDRESS=${contract.address}`);
    } else {
      env += `\nCONTRACT_ADDRESS=${contract.address}`;
    }
    fs.writeFileSync(envPath, env);
    console.log(`✔  CONTRACT_ADDRESS written to .env`);
  }

  console.log("\n🚀 Deployment complete.\n");
}
