import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from pydantic import ValidationError
from models import ThreatIndicatorSchema


VALID = {
    "indicator_type":  "ip",
    "indicator_value": "192.168.1.1",
    "threat_category": "botnet",
    "severity":        "high",
    "description":     "Test description"
}


class TestThreatIndicatorSchema:

    def test_valid_ip_accepted(self):
        m = ThreatIndicatorSchema(**VALID)
        assert m.indicator_type == "ip"

    def test_valid_domain_accepted(self):
        m = ThreatIndicatorSchema(**{**VALID, "indicator_type": "domain"})
        assert m.indicator_type == "domain"

    def test_valid_hash_accepted(self):
        m = ThreatIndicatorSchema(**{**VALID, "indicator_type": "hash"})
        assert m.indicator_type == "hash"

    def test_invalid_type_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "indicator_type": "url"})

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "severity": "extreme"})

    def test_type_uppercased_is_normalized(self):
        m = ThreatIndicatorSchema(**{**VALID, "indicator_type": "IP"})
        assert m.indicator_type == "ip"

    def test_severity_uppercased_is_normalized(self):
        m = ThreatIndicatorSchema(**{**VALID, "severity": "HIGH"})
        assert m.severity == "high"

    def test_value_too_short_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "indicator_value": "x"})

    def test_value_too_long_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "indicator_value": "x" * 513})

    def test_description_too_long_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "description": "d" * 2001})

    def test_category_special_chars_rejected(self):
        with pytest.raises(ValidationError):
            ThreatIndicatorSchema(**{**VALID, "threat_category": "<script>alert(1)</script>"})

    def test_default_reporter_id(self):
        m = ThreatIndicatorSchema(**VALID)
        assert m.reporter_id == "anonymous"