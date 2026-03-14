
import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Query
from slowapi import Limiter
from slowapi.util import get_remote_address

from models import SubmitIndicatorRequest
from hash_utils import generate_hash, verify_hash
from database import get_db
from blockchain import blockchain_client

logger  = logging.getLogger(__name__)
router  = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_id(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


# ── POST /submit-indicator ────────────────────────────────────────────────────

@router.post("/submit-indicator", status_code=201)
@limiter.limit("10/minute")
async def submit_indicator(request: Request, body: SubmitIndicatorRequest):
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database unavailable")

    # Duplicate check
    existing = await db.indicators.find_one({"indicator_value": body.indicator_value})
    if existing:
        raise HTTPException(409, {
            "error":       "Indicator already registered",
            "existing_id": existing["indicator_id"],
            "submitted_at": existing["timestamp"],
        })

    # Build record
    now          = datetime.now(timezone.utc).isoformat()
    indicator_id = str(uuid.uuid4())

    hash_input = {
        "indicator_type":  body.indicator_type.value,
        "indicator_value": body.indicator_value,
        "reporter_id":     body.reporter_id,
        "timestamp":       now,
    }
    data_hash = generate_hash(hash_input)

    record = {
        "indicator_id":      indicator_id,
        "indicator_type":    body.indicator_type.value,
        "indicator_value":   body.indicator_value,
        "threat_category":   body.threat_category.value,
        "severity_level":    body.severity_level.value,
        "description":       body.description.strip(),
        "reporter_id":       body.reporter_id,
        "timestamp":         now,
        "data_hash":         data_hash,
        "blockchain_tx":     None,
        "blockchain_stored": False,
        "blockchain_block":  None,
        "created_at":        now,
    }

    # Persist to MongoDB
    try:
        await db.indicators.insert_one(record)
    except Exception as exc:
        logger.error("MongoDB insert failed: %s", exc)
        raise HTTPException(500, "Database write failed")

    # Store hash on blockchain
    bc = blockchain_client.add_threat_indicator(
        indicator_id=indicator_id,
        indicator_hash=data_hash,
        indicator_type=body.indicator_type.value,
        severity=body.severity_level.value,
    )

    update = {
        "blockchain_stored": bc.get("success", False),
        "blockchain_tx":     bc.get("tx_hash"),
        "blockchain_block":  bc.get("block_number"),
    }
    await db.indicators.update_one({"indicator_id": indicator_id}, {"$set": update})
    record.update(update)
    _strip_id(record)

    return {
        "status":       "success",
        "indicator_id": indicator_id,
        "data_hash":    data_hash,
        "blockchain":   bc,
        "record":       record,
        "message":      "Threat indicator submitted and anchored to blockchain",
    }


# ── GET /indicator/{value} ────────────────────────────────────────────────────

@router.get("/indicator/{value}")
async def get_indicator(value: str):
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database unavailable")

    value = value.strip()
    doc   = await db.indicators.find_one(
        {"$or": [{"indicator_value": value}, {"indicator_value": value.lower()}]},
        {"_id": 0},
    )
    if not doc:
        raise HTTPException(404, f"Indicator '{value}' not found")

    chain = blockchain_client.get_indicator_from_chain(doc["indicator_id"])
    return {"indicator": doc, "blockchain": chain}


# ── GET /verify/{indicator_id} ────────────────────────────────────────────────

@router.get("/verify/{indicator_id}")
async def verify_indicator(indicator_id: str):
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database unavailable")

    doc = await db.indicators.find_one({"indicator_id": indicator_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Indicator not found")

    # Recalculate hash from current DB fields
    recalculated = generate_hash({
        "indicator_type":  doc["indicator_type"],
        "indicator_value": doc["indicator_value"],
        "reporter_id":     doc["reporter_id"],
        "timestamp":       doc["timestamp"],
    })

    db_match   = recalculated == doc["data_hash"]
    chain_ver  = blockchain_client.verify_on_chain(indicator_id, recalculated)

    status     = "valid"
    findings   = []

    if not db_match:
        status = "tampered"
        findings.append("Database record hash mismatch — data may have been altered")

    if chain_ver.get("success") and not chain_ver.get("is_valid"):
        status = "tampered"
        findings.append("Hash does not match blockchain record")

    if not chain_ver.get("success"):
        findings.append(f"Blockchain verification skipped: {chain_ver.get('error', 'unavailable')}")

    return {
        "indicator_id":      indicator_id,
        "integrity_status":  status,
        "db_hash_match":     db_match,
        "stored_hash":       doc["data_hash"],
        "recalculated_hash": recalculated,
        "blockchain":        chain_ver,
        "findings":          findings,
        "indicator":         doc,
    }


# ── GET /threat-feed ──────────────────────────────────────────────────────────

@router.get("/threat-feed")
async def threat_feed(
    limit:          int = Query(50,  ge=1, le=100),
    skip:           int = Query(0,   ge=0),
    severity:       str = Query(None),
    indicator_type: str = Query(None),
):
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database unavailable")

    query = {}
    if severity:
        query["severity_level"] = severity
    if indicator_type:
        query["indicator_type"] = indicator_type

    cursor = db.indicators.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    docs   = [d async for d in cursor]
    total  = await db.indicators.count_documents(query)

    # Severity stats for this query
    sev_pipeline = [{"$match": query}, {"$group": {"_id": "$severity_level", "count": {"$sum": 1}}}]
    sev_stats    = {s["_id"]: s["count"] async for s in db.indicators.aggregate(sev_pipeline)}

    return {
        "total":            total,
        "returned":         len(docs),
        "blockchain_count": blockchain_client.get_total_count(),
        "severity_stats":   sev_stats,
        "indicators":       docs,
    }


# ── GET /stats ────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats():
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database unavailable")

    total = await db.indicators.count_documents({})

    async def agg(field):
        return {s["_id"]: s["count"]
                async for s in db.indicators.aggregate(
                    [{"$group": {"_id": f"${field}", "count": {"$sum": 1}}}]
                )}

    return {
        "total_indicators":    total,
        "blockchain_count":    blockchain_client.get_total_count(),
        "blockchain_connected": blockchain_client.connected,
        "by_type":             await agg("indicator_type"),
        "by_severity":         await agg("severity_level"),
        "by_category":         await agg("threat_category"),
    }