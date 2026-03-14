const fs   = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying from: ${deployer.address}`);
  console.log(`Balance: ${ethers.formatEther(await deployer.provider.getBalance(deployer.address))} ETH`);

  const Factory  = await ethers.getContractFactory("ThreatIntelRegistry");
  const contract = await Factory.deploy();

  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log(`ThreatIntelRegistry deployed to: ${address}`);

  // Save ABI and address for the Python backend
  const artifact = require(`../artifacts/contracts/ThreatIntelRegistry.sol/ThreatIntelRegistry.json`);
  const config   = { contract_address: address, abi: artifact.abi };

  const outPath = path.join(__dirname, "../../backend/contract_config.json");
  fs.writeFileSync(outPath, JSON.stringify(config, null, 2));
  console.log(`Config saved to: ${outPath}`);
}

main().catch((e) => { console.error(e); process.exit(1); });