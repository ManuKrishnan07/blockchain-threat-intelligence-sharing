# Decentralized Threat Intelligence Sharing Platform (DTISP)

## Quick Start

### 1. Prerequisites
- Python 3.12
- MongoDB (running on `localhost:27017`)
- Ganache (running on `localhost:7545`)
- Node.js (optional)

### 2. Install Dependencies
```bash
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Configure Environment
Copy `.env.example` to `.env` and fill in your values.

### 4. Deploy Smart Contract
```bash
cd backend
python deploy.py
# Expected: "Contract Deployed to: 0xABC..."
# Creates: backend/contract_config.json
```

### 5. Start Backend
```bash
cd backend
python -m uvicorn main:app --reload --port 8000
# API Docs available at: http://localhost:8000/docs
```

### 6. Seed Test Data (Optional)
```bash
cd backend
python seed_data.py
```

### 7. Open Frontend
Open `frontend/index.html` in your browser.

---

## API Reference

### Health Check
```bash
curl http://localhost:8000/health
```

### Submit an Indicator
```bash
curl -X POST http://localhost:8000/submit-indicator \
  -H "Content-Type: application/json" \
  -d '{
    "indicator_type":  "ip",
    "indicator_value": "185.220.101.45",
    "threat_category": "botnet",
    "severity":        "critical",
    "description":     "Active Tor-based C2 server",
    "reporter_id":     "org_alpha"
  }'
```

**Response:**
```json
{
  "message":   "Indicator submitted and anchored to blockchain.",
  "data_hash": "a1b2c3d4e5f6...",
  "tx_hash":   "0xabc123...",
  "timestamp": "1741824000"
}
```

### Search by Value
```bash
curl http://localhost:8000/indicator/185.220.101.45
```

### Verify Integrity
```bash
curl http://localhost:8000/verify/a1b2c3d4e5f6...
```

**VALID Response:**
```json
{
  "status": "VALID",
  "detail": "Data integrity confirmed. Hash matches blockchain record.",
  "db_hash": "a1b2c3...",
  "blockchain_reporter": "0xAbCd...",
  "blockchain_timestamp": 1741824000
}
```

**TAMPERED Response:**
```json
{
  "status": "TAMPERED",
  "detail": "The database record has been modified. Hashes do not match."
}
```

### Get Threat Feed (with filters)
```bash
# All
curl http://localhost:8000/threat-feed

# Critical IPs only
curl "http://localhost:8000/threat-feed?severity=critical&ioc_type=ip"
```

### Platform Statistics
```bash
curl http://localhost:8000/stats
```

### Contributor Leaderboard
```bash
curl http://localhost:8000/leaderboard
```

### Reporter Profile
```bash
curl http://localhost:8000/reporter/org_alpha
```

### Export STIX 2.1 Bundle
```bash
curl http://localhost:8000/export/stix -o threat_intel.stix.json
```

---

## Security Architecture

````
User Input ──► Pydantic Validation ──► SHA256 Hash Generation
                                              │
                                    ┌─────────┴──────────┐
                                    │                    │
                              MongoDB                Ethereum
                           (Full Record)          (Hash Only)
                                    │                    │
                                    └─────────┬──────────┘
                                              │
                              Verify: Recalculate hash
                              Compare DB hash == Chain hash
````

## Tamper Detection Proof

1. Submit an indicator and save the `data_hash`
2. Manually edit the record in MongoDB (e.g., change severity to "low")
3. Call `GET /verify/{data_hash}`
4. The system recalculates the hash from DB fields and compares it to the immutable blockchain record
5. Response will be `"status": "TAMPERED"` — proving the database was altered
````

---

### 7. Key Architecture Decisions Explained

**Why hash only goes on-chain (not full data):** Ethereum storage (SSTORE) costs gas per 32-byte slot. Storing the full record on-chain for each IOC would be prohibitively expensive even on a private network at scale. The hash serves as a cryptographic commitment — it proves the data existed in exactly that form at that time, without storing the sensitive threat data publicly on-chain.

**Why `indicator_value` duplicate is checked by hash, not raw value:** The hash includes `reporter_id` and `timestamp`, so two different organizations can independently report the same IP — both submissions are stored, each with their own hash and blockchain anchor, giving you provenance tracking rather than a naive deduplication that would hide redundant confirmations.

**Rate limiting strategy:** ``10/minute` on submissions prevents bulk spam while allowing a legitimate SOC analyst to submit an incident. The read endpoints are limited to `60/minute`, which is generous for dashboards polling on a timer.
