"""
Run this script to populate the platform with test threat data.
Usage: python seed_data.py
"""
import asyncio
import time
from database import indicator_collection
from hash_utils import generate_indicator_hash
from blockchain import store_hash_on_chain
from reputation import update_reputation_on_submit

SAMPLE_INDICATORS = [
    {
        "indicator_type": "ip",
        "indicator_value": "185.220.101.45",
        "threat_category": "botnet",
        "severity": "critical",
        "description": "Tor exit node used as C2 server for Emotet botnet. Observed in honeypot traffic.",
        "reporter_id": "org_alpha",
    },
    {
        "indicator_type": "domain",
        "indicator_value": "secure-login-microsoft.ru",
        "threat_category": "phishing",
        "severity": "high",
        "description": "Spoofing Microsoft login page. Credential harvesting kit detected.",
        "reporter_id": "org_beta",
    },
    {
        "indicator_type": "hash",
        "indicator_value": "44d88612fea8a8f36de82e1278abb02f",
        "threat_category": "ransomware",
        "severity": "critical",
        "description": "EICAR-based ransomware variant. SHA256 of dropper payload.",
        "reporter_id": "org_gamma",
    },
    {
        "indicator_type": "ip",
        "indicator_value": "91.108.4.218",
        "threat_category": "scanning",
        "severity": "medium",
        "description": "Mass scanning activity across port 22 and 3389. Attributed to GandCrab affiliate.",
        "reporter_id": "org_alpha",
    },
    {
        "indicator_type": "domain",
        "indicator_value": "paypa1-secure.co",
        "threat_category": "phishing",
        "severity": "high",
        "description": "Typosquatted PayPal domain. Used to redirect users to credential harvest page.",
        "reporter_id": "org_delta",
    },
    {
        "indicator_type": "ip",
        "indicator_value": "45.142.212.100",
        "threat_category": "malware-distribution",
        "severity": "high",
        "description": "Serves malware over port 80. Part of a bulletproof hosting cluster.",
        "reporter_id": "org_beta",
    },
    {
        "indicator_type": "hash",
        "indicator_value": "5d41402abc4b2a76b9719d911017c592",
        "threat_category": "trojan",
        "severity": "medium",
        "description": "Suspicious DLL injected into explorer.exe. Low detection ratio on VirusTotal.",
        "reporter_id": "org_gamma",
    },
    {
        "indicator_type": "domain",
        "indicator_value": "update-flashplayer-now.info",
        "threat_category": "drive-by-download",
        "severity": "medium",
        "description": "Serves fake Flash Player update that installs adware and info-stealer.",
        "reporter_id": "org_alpha",
    },
]


async def seed():
    print("🌱 Seeding threat intelligence data...")
    count = 0
    for item in SAMPLE_INDICATORS:
        timestamp = str(int(time.time()) - count * 3600)  # Stagger by 1 hour each

        data_hash = generate_indicator_hash(
            item["indicator_type"],
            item["indicator_value"],
            timestamp,
            item["reporter_id"]
        )

        # Skip if exists
        existing = await indicator_collection.find_one({"data_hash": data_hash})
        if existing:
            print(f"  ⏭  Skipping (exists): {item['indicator_value']}")
            count += 1
            continue

        # Blockchain
        tx = store_hash_on_chain(data_hash, item["indicator_type"], item["threat_category"], timestamp)
        if not tx:
            print(f"  ❌ Blockchain failed for: {item['indicator_value']}")
            count += 1
            continue

        # DB
        record = dict(item)
        record["timestamp"]     = timestamp
        record["data_hash"]     = data_hash
        record["blockchain_tx"] = tx
        await indicator_collection.insert_one(record)

        # Reputation
        await update_reputation_on_submit(item["reporter_id"], item["severity"])

        print(f"  ✅ Added: {item['indicator_value']} [{item['severity']}] | Hash: {data_hash[:12]}...")
        count += 1

    print(f"\n✅ Seeded {count} indicators.")


if __name__ == "__main__":
    asyncio.run(seed())