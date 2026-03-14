from pydantic import BaseModel, field_validator
from typing import Optional
import re

# Allowed values
VALID_TYPES      = {"ip", "domain", "hash"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

class ThreatIndicatorSchema(BaseModel):
    indicator_type:  str
    indicator_value: str
    threat_category: str
    severity:        str
    description:     str
    reporter_id:     str = "anonymous"

    @field_validator("indicator_type")
    @classmethod
    def validate_type(cls, v):
        if v.lower() not in VALID_TYPES:
            raise ValueError(f"indicator_type must be one of: {VALID_TYPES}")
        return v.lower()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v.lower() not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of: {VALID_SEVERITIES}")
        return v.lower()

    @field_validator("indicator_value")
    @classmethod
    def sanitize_value(cls, v):
        # Strip leading/trailing whitespace, enforce max length
        v = v.strip()
        if len(v) < 3:
            raise ValueError("indicator_value is too short")
        if len(v) > 512:
            raise ValueError("indicator_value exceeds max length of 512")
        return v

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v):
        v = v.strip()
        if len(v) > 2000:
            raise ValueError("description exceeds 2000 characters")
        return v

    @field_validator("threat_category")
    @classmethod
    def sanitize_category(cls, v):
        # Only allow alphanumeric, spaces, hyphens
        if not re.match(r'^[\w\s\-]{2,100}$', v):
            raise ValueError("threat_category contains invalid characters")
        return v.strip()

    class Config:
        json_schema_extra = {
            "example": {
                "indicator_type":  "ip",
                "indicator_value": "185.23.45.10",
                "threat_category": "botnet",
                "severity":        "high",
                "description":     "Active C2 server observed in honeypot traffic.",
                "reporter_id":     "org_alpha"
            }
        }

class SearchQuery(BaseModel):
    query: str
    search_type: Optional[str] = None  # ip, domain, hash