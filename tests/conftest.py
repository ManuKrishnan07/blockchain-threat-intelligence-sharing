import pytest
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from httpx import AsyncClient, ASGITransport
import sys
import os

# Make sure imports resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from main import app

TEST_DB_URI  = "mongodb://localhost:27017"
TEST_DB_NAME = "dtisp_test_db"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_db():
    """Creates a clean test database and drops it after the session."""
    client = AsyncIOMotorClient(TEST_DB_URI)
    db     = client[TEST_DB_NAME]
    yield db
    await client.drop_database(TEST_DB_NAME)
    client.close()


@pytest.fixture(scope="session")
async def client():
    """AsyncClient wrapping the FastAPI app (no real server needed)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac


# ── Shared test data ──────────────────────────────────────
SAMPLE_IP = {
    "indicator_type":  "ip",
    "indicator_value": "10.100.200.5",
    "threat_category": "botnet",
    "severity":        "high",
    "description":     "Test C2 server indicator",
    "reporter_id":     "test_org"
}

SAMPLE_DOMAIN = {
    "indicator_type":  "domain",
    "indicator_value": "evil-phishing-test.io",
    "threat_category": "phishing",
    "severity":        "critical",
    "description":     "Test phishing domain",
    "reporter_id":     "test_org"
}

SAMPLE_HASH = {
    "indicator_type":  "hash",
    "indicator_value": "d41d8cd98f00b204e9800998ecf8427e",
    "threat_category": "ransomware",
    "severity":        "critical",
    "description":     "Test malware hash",
    "reporter_id":     "test_org"
}