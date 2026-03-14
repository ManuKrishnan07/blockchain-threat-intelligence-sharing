import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from main import app

SAMPLE_IP = {
    "indicator_type":  "ip",
    "indicator_value": "172.16.254.1",
    "threat_category": "c2-server",
    "severity":        "high",
    "description":     "API test indicator",
    "reporter_id":     "pytest_suite"
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def http():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client


# ── /health ───────────────────────────────────────────────
class TestHealth:
    async def test_health_returns_200(self, http):
        r = await http.get("/health")
        assert r.status_code == 200

    async def test_health_has_status_field(self, http):
        r = await http.get("/health")
        assert "status" in r.json()


# ── /submit-indicator ─────────────────────────────────────
class TestSubmitIndicator:

    @patch("main.store_hash_on_chain", return_value="0xmocktxhash")
    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=None)
    @patch("main.indicator_collection.insert_one", new_callable=AsyncMock)
    @patch("main.update_reputation_on_submit", new_callable=AsyncMock)
    @patch("main.manager.broadcast", new_callable=AsyncMock)
    async def test_submit_valid_indicator(
        self, mock_bc, mock_rep, mock_ins, mock_find, mock_chain, http
    ):
        r = await http.post("/submit-indicator", json=SAMPLE_IP)
        assert r.status_code == 200
        body = r.json()
        assert "data_hash" in body
        assert "tx_hash"   in body
        assert len(body["data_hash"]) == 64

    async def test_submit_missing_field_returns_422(self, http):
        bad = {k: v for k, v in SAMPLE_IP.items() if k != "indicator_value"}
        r   = await http.post("/submit-indicator", json=bad)
        assert r.status_code == 422

    async def test_submit_invalid_type_returns_422(self, http):
        r = await http.post("/submit-indicator", json={**SAMPLE_IP, "indicator_type": "url"})
        assert r.status_code == 422

    async def test_submit_invalid_severity_returns_422(self, http):
        r = await http.post("/submit-indicator", json={**SAMPLE_IP, "severity": "catastrophic"})
        assert r.status_code == 422

    @patch("main.store_hash_on_chain", return_value=None)
    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=None)
    async def test_submit_blockchain_failure_returns_500(self, mock_find, mock_chain, http):
        r = await http.post("/submit-indicator", json=SAMPLE_IP)
        assert r.status_code == 500

    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value={"data_hash": "exists"})
    async def test_submit_duplicate_returns_409(self, mock_find, http):
        r = await http.post("/submit-indicator", json=SAMPLE_IP)
        assert r.status_code == 409


# ── /indicator/{value} ────────────────────────────────────
class TestGetIndicator:

    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value={
        "_id": "abc", "indicator_type": "ip", "indicator_value": "172.16.254.1",
        "threat_category": "c2", "severity": "high", "description": "test",
        "reporter_id": "org", "timestamp": "1700000000",
        "data_hash": "a" * 64, "blockchain_tx": "0x1"
    })
    @patch("main.verify_hash_on_chain", return_value={"verified": True, "reporter": "0xabc", "timestamp": 1700000000})
    async def test_found_indicator_returns_200(self, mock_chain, mock_db, http):
        r = await http.get("/indicator/172.16.254.1")
        assert r.status_code == 200
        body = r.json()
        assert body["indicator_value"] == "172.16.254.1"
        assert body["blockchain_status"] == "confirmed"

    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=None)
    async def test_not_found_returns_404(self, mock_db, http):
        r = await http.get("/indicator/9.9.9.9")
        assert r.status_code == 404


# ── /verify/{hash} ───────────────────────────────────────
class TestVerifyIntegrity:

    def _make_db_record(self):
        from hash_utils import generate_indicator_hash
        ts   = "1700000000"
        h    = generate_indicator_hash("ip", "10.0.0.1", ts, "org_x")
        return {
            "_id": "oid", "indicator_type": "ip", "indicator_value": "10.0.0.1",
            "threat_category": "test", "severity": "low", "description": "d",
            "reporter_id": "org_x", "timestamp": ts, "data_hash": h, "blockchain_tx": "0x1"
        }

    @patch("main.update_reputation_on_verify", new_callable=AsyncMock)
    @patch("main.verify_hash_on_chain", return_value={"verified": True, "reporter": "0xabc", "timestamp": 1700000000})
    async def test_valid_hash_returns_valid(self, mock_chain, mock_rep, http):
        record = self._make_db_record()
        with patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=record):
            r = await http.get(f"/verify/{record['data_hash']}")
            assert r.status_code == 200
            assert r.json()["status"] == "VALID"

    async def test_tampered_record_returns_tampered(self, http):
        from hash_utils import generate_indicator_hash
        ts     = "1700000000"
        good_h = generate_indicator_hash("ip", "10.0.0.1", ts, "org_x")
        # Simulate DB tampering: value changed to 10.0.0.99
        tampered_record = {
            "_id": "oid", "indicator_type": "ip", "indicator_value": "10.0.0.99",
            "threat_category": "test", "severity": "low", "description": "d",
            "reporter_id": "org_x", "timestamp": ts, "data_hash": good_h, "blockchain_tx": "0x1"
        }
        with patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=tampered_record):
            r = await http.get(f"/verify/{good_h}")
            assert r.status_code == 200
            assert r.json()["status"] == "TAMPERED"

    @patch("main.indicator_collection.find_one", new_callable=AsyncMock, return_value=None)
    async def test_unknown_hash_returns_404(self, mock_db, http):
        r = await http.get(f"/verify/{'z' * 64}")
        assert r.status_code == 404


# ── /stats ────────────────────────────────────────────────
class TestStats:
    async def test_stats_returns_expected_keys(self, http):
        with patch("main.indicator_collection.count_documents", new_callable=AsyncMock, return_value=5):
            r = await http.get("/stats")
            assert r.status_code == 200
            body = r.json()
            assert "total_indicators" in body
            assert "by_severity"      in body
            assert "by_type"          in body


# ── /threat-feed ──────────────────────────────────────────
class TestThreatFeed:

    async def test_feed_returns_200(self, http):
        r = await http.get("/threat-feed")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_feed_limit_over_100_rejected(self, http):
        r = await http.get("/threat-feed?limit=200")
        assert r.status_code == 422