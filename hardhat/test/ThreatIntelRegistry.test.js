const { expect } = require("chai");
const { ethers }  = require("hardhat");

describe("ThreatIntelRegistry", function () {
  let contract;
  let owner;

  beforeEach(async function () {
    [owner]   = await ethers.getSigners();
    const F   = await ethers.getContractFactory("ThreatIntelRegistry");
    contract  = await F.deploy();
    await contract.waitForDeployment();
  });

  it("Should deploy with correct owner", async function () {
    expect(await contract.getAddress()).to.be.properAddress;
  });

  it("Should store a new indicator", async function () {
    const hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
    await expect(
      contract.addThreatIndicator(hash, "ip", "botnet", Math.floor(Date.now() / 1000))
    ).to.emit(contract, "IndicatorAdded").withArgs(hash, owner.address, anyValue);
  });

  it("Should verify an existing indicator", async function () {
    const hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
    const ts   = Math.floor(Date.now() / 1000);
    await contract.addThreatIndicator(hash, "ip", "botnet", ts);
    const [verified, reporter, timestamp] = await contract.verifyIndicator(hash);
    expect(verified).to.equal(true);
    expect(reporter).to.equal(owner.address);
  });

  it("Should reject duplicate indicator", async function () {
    const hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
    const ts   = Math.floor(Date.now() / 1000);
    await contract.addThreatIndicator(hash, "ip", "botnet", ts);
    await expect(
      contract.addThreatIndicator(hash, "ip", "botnet", ts)
    ).to.be.revertedWith("Indicator already exists");
  });

  it("Should revert verifyIndicator for unknown hash", async function () {
    await expect(
      contract.verifyIndicator("unknownhash")
    ).to.be.revertedWith("Indicator not found");
  });
});

// Helper for anyValue
const anyValue = require("@nomicfoundation/hardhat-chai-matchers/withArgs").anyValue;