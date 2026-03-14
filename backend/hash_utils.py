import hashlib
import json
from typing import Optional


def generate_indicator_hash(
    indicator_type: str,
    indicator_value: str,
    timestamp: str,
    reporter_id: str
) -> str:
    """
    Deterministic SHA256 hash of the four canonical fields.
    The same inputs ALWAYS produce the same hash — this is what
    makes tamper detection possible: if any field changes in MongoDB,
    re-running this produces a different hash that won't match the
    immutable value stored on the blockchain.
    """
    raw = f"{indicator_type.lower().strip()}" \
          f"{indicator_value.strip()}" \
          f"{timestamp.strip()}" \
          f"{reporter_id.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_record_hash(record: dict) -> str:
    """
    Full-record hash — used when you want to hash the entire document
    (useful for export integrity checks).
    Sorts keys for determinism.
    """
    # Exclude internal MongoDB fields and any previously stored hash
    exclude = {"_id", "data_hash", "blockchain_tx"}
    cleaned = {k: v for k, v in record.items() if k not in exclude}
    canonical = json.dumps(cleaned, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_hash(
    indicator_type: str,
    indicator_value: str,
    timestamp: str,
    reporter_id: str,
    expected_hash: str
) -> bool:
    """Convenience wrapper — returns True if recalculated hash matches."""
    return generate_indicator_hash(
        indicator_type, indicator_value, timestamp, reporter_id
    ) == expected_hash