import json
import os
from web3 import Web3

GANACHE_URL          = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
CONTRACT_CONFIG_PATH = os.getenv("CONTRACT_CONFIG_PATH", "contract_config.json")

# ── Load contract config ──────────────────────────────────
CONTRACT_ADDRESS = None
CONTRACT_ABI     = []

try:
    with open(CONTRACT_CONFIG_PATH, "r") as f:
        raw = f.read().strip()
        if raw and raw != "{}":
            config           = json.loads(raw)
            CONTRACT_ADDRESS = config.get("contract_address")
            CONTRACT_ABI     = config.get("abi", [])
            print(f"Contract config loaded: {CONTRACT_ADDRESS}")
        else:
            print("contract_config.json is empty — run deploy.py after startup")
except FileNotFoundError:
    print("contract_config.json not found — run deploy.py after startup")
except Exception as e:
    print(f"Config load error: {e}")

# ── Connect to blockchain ─────────────────────────────────
w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

if w3.is_connected():
    print(f"Blockchain connected: {GANACHE_URL}")
    if w3.eth.accounts:
        w3.eth.default_account = w3.eth.accounts[0]
else:
    print(f"Blockchain not reachable at {GANACHE_URL} — will retry on use")

# ── Contract handle ───────────────────────────────────────
contract = None
if CONTRACT_ADDRESS and CONTRACT_ABI:
    try:
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        print(f"Contract loaded at {CONTRACT_ADDRESS}")
    except Exception as e:
        print(f"Contract load error: {e}")


def store_hash_on_chain(data_hash: str, i_type: str, category: str, timestamp: str):
    if not contract:
        print("store_hash_on_chain: contract not loaded yet")
        return None
    try:
        tx = contract.functions.addThreatIndicator(
            data_hash, i_type, category, int(timestamp)
        ).transact({"from": w3.eth.accounts[0]})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        return receipt.transactionHash.hex()
    except Exception as e:
        print(f"Blockchain write error: {e}")
        return None


def verify_hash_on_chain(data_hash: str) -> dict:
    if not contract:
        return {"verified": False, "error": "Contract not deployed — run deploy.py"}
    try:
        exists, reporter, timestamp = contract.functions.verifyIndicator(data_hash).call()
        return {"verified": exists, "reporter": reporter, "timestamp": timestamp}
    except Exception as e:
        return {"verified": False, "error": str(e)}