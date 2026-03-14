from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URI)
database = client.threat_intel_db
indicator_collection = database.get_collection("indicators")
reporter_collection  = database.get_collection("reporters")

async def create_indexes():
    """Called on startup to ensure fast queries and uniqueness."""
    await indicator_collection.create_index([("data_hash", ASCENDING)],  unique=True)
    await indicator_collection.create_index([("indicator_value", ASCENDING)])
    await indicator_collection.create_index([("timestamp", DESCENDING)])
    await indicator_collection.create_index([("severity", ASCENDING)])
    await reporter_collection.create_index([("reporter_id", ASCENDING)], unique=True)

def indicator_helper(indicator) -> dict:
    return {
        "id":               str(indicator["_id"]),
        "indicator_type":   indicator.get("indicator_type"),
        "indicator_value":  indicator.get("indicator_value"),
        "threat_category":  indicator.get("threat_category"),
        "severity":         indicator.get("severity"),
        "description":      indicator.get("description"),
        "reporter_id":      indicator.get("reporter_id"),
        "timestamp":        indicator.get("timestamp"),
        "data_hash":        indicator.get("data_hash"),
        "blockchain_tx":    indicator.get("blockchain_tx"),
    }

def reporter_helper(reporter) -> dict:
    return {
        "reporter_id":         reporter.get("reporter_id"),
        "submissions":         reporter.get("submissions", 0),
        "verified_count":      reporter.get("verified_count", 0),
        "reputation_score":    reporter.get("reputation_score", 0.0),
        "last_submission":     reporter.get("last_submission"),
    }