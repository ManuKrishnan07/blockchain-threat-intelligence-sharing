import json
import time
import uuid


def to_stix_bundle(indicators: list) -> dict:
    """
    Converts a list of DB indicators into a STIX 2.1-compatible bundle.
    Reference: https://docs.oasis-open.org/cti/stix/v2.1/
    """
    stix_objects = []

    for item in indicators:
        # Map internal types to STIX pattern types
        pattern_map = {
            "ip":     f"[ipv4-addr:value = '{item['indicator_value']}']",
            "domain": f"[domain-name:value = '{item['indicator_value']}']",
            "hash":   f"[file:hashes.MD5 = '{item['indicator_value']}']",
        }
        pattern = pattern_map.get(item["indicator_type"], f"[unknown:value = '{item['indicator_value']}']")

        stix_indicator = {
            "type":              "indicator",
            "spec_version":      "2.1",
            "id":                f"indicator--{uuid.uuid4()}",
            "created":           _epoch_to_stix(item.get("timestamp", str(int(time.time())))),
            "modified":          _epoch_to_stix(item.get("timestamp", str(int(time.time())))),
            "name":              f"{item['indicator_type'].upper()}: {item['indicator_value']}",
            "description":       item.get("description", ""),
            "pattern":           pattern,
            "pattern_type":      "stix",
            "valid_from":        _epoch_to_stix(item.get("timestamp", str(int(time.time())))),
            "labels":            [item.get("threat_category", "unknown"), item.get("severity", "unknown")],
            "confidence":        _severity_to_confidence(item.get("severity", "low")),
            "external_references": [
                {
                    "source_name": "DTISP Blockchain",
                    "description": "Immutable hash stored on Ethereum",
                    "external_id": item.get("data_hash", "")
                }
            ]
        }
        stix_objects.append(stix_indicator)

    return {
        "type":    "bundle",
        "id":      f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }


def _epoch_to_stix(epoch_str: str) -> str:
    """Convert Unix epoch string to STIX timestamp format."""
    try:
        ts = float(epoch_str)
        import datetime
        dt = datetime.datetime.utcfromtimestamp(ts)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return "2026-01-01T00:00:00.000Z"


def _severity_to_confidence(severity: str) -> int:
    return {"low": 30, "medium": 55, "high": 80, "critical": 95}.get(severity, 30)