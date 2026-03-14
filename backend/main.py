import asyncio
import json
import time
from typing import List

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from alerts import send_high_severity_alert
from blockchain import store_hash_on_chain, verify_hash_on_chain
from database import create_indexes, indicator_collection, indicator_helper
from hash_utils import generate_indicator_hash
from ioc_export import to_stix_bundle
from logger import RequestLoggingMiddleware, logger
from models import ThreatIndicatorSchema
from reputation import (
    get_leaderboard,
    get_or_create_reporter,
    update_reputation_on_submit,
    update_reputation_on_verify,
)


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Decentralized Threat Intelligence Platform",
    description="Blockchain-backed immutable IOC sharing network",
    version="2.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)


class ConnectionManager:
    """Broadcast new threat submissions to connected WebSocket clients."""

    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info("WebSocket client connected. Total: %s", len(self.active))

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
            logger.info("WebSocket client disconnected. Total: %s", len(self.active))

    async def broadcast(self, data: dict):
        payload = json.dumps(data)
        dead_connections: List[WebSocket] = []

        for ws in self.active:
            try:
                await ws.send_text(payload)
            except Exception:
                dead_connections.append(ws)

        for ws in dead_connections:
            self.disconnect(ws)


manager = ConnectionManager()


@app.on_event("startup")
async def startup_event():
    await create_indexes()
    logger.info("DTISP backend started. Indexes ready.")


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        recent = []
        async for indicator in indicator_collection.find().sort("timestamp", -1).limit(5):
            recent.append(indicator_helper(indicator))
        await websocket.send_text(json.dumps({"event": "init", "data": recent}))

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/submit-indicator")
@limiter.limit("10/minute")
async def submit_indicator(request: Request, data: ThreatIndicatorSchema):
    request_id = getattr(request.state, "request_id", "?")
    logger.info(
        "[%s] Submit: type=%s severity=%s reporter=%s",
        request_id,
        data.indicator_type,
        data.severity,
        data.reporter_id,
    )

    timestamp = str(int(time.time()))
    data_hash = generate_indicator_hash(
        data.indicator_type,
        data.indicator_value,
        timestamp,
        data.reporter_id,
    )

    if await indicator_collection.find_one({"data_hash": data_hash}):
        raise HTTPException(status_code=409, detail="Duplicate: This indicator already exists.")

    tx_hash = store_hash_on_chain(
        data_hash,
        data.indicator_type,
        data.threat_category,
        timestamp,
    )
    if not tx_hash:
        logger.error("[%s] Blockchain write failed for hash %s", request_id, data_hash[:12])
        raise HTTPException(status_code=500, detail="Blockchain write failed. Is Ganache running?")

    new_record = data.model_dump()
    new_record.update(
        {
            "timestamp": timestamp,
            "data_hash": data_hash,
            "blockchain_tx": tx_hash,
        }
    )
    await indicator_collection.insert_one(new_record)

    await update_reputation_on_submit(data.reporter_id, data.severity)
    logger.info("[%s] Stored: hash=%s tx=%s", request_id, data_hash[:12], tx_hash[:12])

    if data.severity in ("high", "critical"):
        alert_payload = {**new_record, "data_hash": data_hash}
        asyncio.get_event_loop().run_in_executor(None, send_high_severity_alert, alert_payload)

    await manager.broadcast(
        {
            "event": "new_indicator",
            "indicator_type": data.indicator_type,
            "indicator_value": data.indicator_value,
            "threat_category": data.threat_category,
            "severity": data.severity,
            "reporter_id": data.reporter_id,
            "data_hash": data_hash,
            "timestamp": timestamp,
        }
    )

    return {
        "message": "Indicator anchored to blockchain.",
        "data_hash": data_hash,
        "tx_hash": tx_hash,
        "timestamp": timestamp,
    }


@app.get("/indicator/{value}")
@limiter.limit("60/minute")
async def get_indicator(request: Request, value: str):
    record = await indicator_collection.find_one({"indicator_value": value})
    if not record:
        raise HTTPException(status_code=404, detail=f"Indicator '{value}' not found.")

    result = indicator_helper(record)
    chain = verify_hash_on_chain(result["data_hash"])
    result["blockchain_status"] = "confirmed" if chain.get("verified") else "unconfirmed"
    result["blockchain_reporter"] = chain.get("reporter", "N/A")
    return result


@app.get("/verify/{data_hash}")
@limiter.limit("30/minute")
async def verify_integrity(request: Request, data_hash: str):
    db_record = await indicator_collection.find_one({"data_hash": data_hash})
    if not db_record:
        raise HTTPException(status_code=404, detail="Record not found in database.")

    recalculated_hash = generate_indicator_hash(
        db_record["indicator_type"],
        db_record["indicator_value"],
        db_record["timestamp"],
        db_record["reporter_id"],
    )
    if recalculated_hash != data_hash:
        logger.warning(
            "TAMPERED record detected: stored=%s recalc=%s",
            data_hash[:12],
            recalculated_hash[:12],
        )
        return JSONResponse(
            status_code=200,
            content={
                "status": "TAMPERED",
                "detail": "Database record modified - hashes do not match.",
                "db_hash": data_hash,
                "recalc": recalculated_hash,
            },
        )

    chain = verify_hash_on_chain(data_hash)
    if chain.get("verified"):
        await update_reputation_on_verify(db_record["reporter_id"])
        return {
            "status": "VALID",
            "detail": "Data integrity confirmed. Hash matches blockchain record.",
            "db_hash": data_hash,
            "blockchain_reporter": chain["reporter"],
            "blockchain_timestamp": chain["timestamp"],
        }

    return JSONResponse(
        status_code=200,
        content={
            "status": "NOT_ON_CHAIN",
            "detail": chain.get("error", "Hash not found in smart contract."),
            "db_hash": data_hash,
        },
    )


@app.get("/threat-feed")
@limiter.limit("60/minute")
async def get_threat_feed(
    request: Request,
    severity: str = Query(None),
    ioc_type: str = Query(None),
    limit: int = Query(50, le=100),
):
    query_filter = {}
    if severity:
        query_filter["severity"] = severity.lower()
    if ioc_type:
        query_filter["indicator_type"] = ioc_type.lower()

    results = []
    async for indicator in indicator_collection.find(query_filter).sort("timestamp", -1).limit(limit):
        results.append(indicator_helper(indicator))
    return results


@app.get("/stats")
async def get_stats():
    total = await indicator_collection.count_documents({})
    week_ago = str(int(time.time()) - 7 * 86400)

    return {
        "total_indicators": total,
        "last_7_days": await indicator_collection.count_documents({"timestamp": {"$gte": week_ago}}),
        "by_severity": {
            severity: await indicator_collection.count_documents({"severity": severity})
            for severity in ("low", "medium", "high", "critical")
        },
        "by_type": {
            indicator_type: await indicator_collection.count_documents({"indicator_type": indicator_type})
            for indicator_type in ("ip", "domain", "hash")
        },
    }


@app.get("/reporter/{reporter_id}")
async def get_reporter_profile(reporter_id: str):
    reporter = await get_or_create_reporter(reporter_id)
    return {
        key: reporter[key]
        for key in (
            "reporter_id",
            "submissions",
            "verified_count",
            "reputation_score",
            "last_submission",
        )
        if key in reporter
    }


@app.get("/leaderboard")
async def leaderboard():
    return await get_leaderboard(limit=10)


@app.get("/export/stix")
async def export_stix(limit: int = Query(100, le=500)):
    indicators = []
    async for indicator in indicator_collection.find().sort("timestamp", -1).limit(limit):
        indicators.append(indicator_helper(indicator))

    stix_json = json.dumps(to_stix_bundle(indicators), indent=2)
    return Response(
        content=stix_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=threat_intel.stix.json"},
    )


@app.get("/health")
async def health():
    mongo_ok = True
    try:
        await indicator_collection.database.command("ping")
    except Exception:
        mongo_ok = False

    return {
        "status": "ok" if mongo_ok else "degraded",
        "mongodb": "connected" if mongo_ok else "unreachable",
        "version": "2.0.0",
    }
