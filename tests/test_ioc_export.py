import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from ioc_export import to_stix_bundle, _severity_to_confidence


SAMPLE_INDICATORS = [
    {
        "indicator_type":  "ip",
        "indicator_value": "1.2.3.4",
        "threat_category": "botnet",
        "severity":        "high",
        "description":     "Test IP",
        "reporter_id":     "org",
        "timestamp":       "1700000000",
        "data_hash":       "a" * 64
    },
    {
        "indicator_type":  "domain",
        "indicator_value": "evil.com",
        "threat_category": "phishing",
        "severity":        "critical",
        "description":     "Test domain",
        "reporter_id":     "org",
        "timestamp":       "1700000001",
        "data_hash":       "b" * 64
    }
]


class TestSTIXExport:

    def test_bundle_type_is_bundle(self):
        bundle = to_stix_bundle(SAMPLE_INDICATORS)
        assert bundle["type"] == "bundle"

    def test_bundle_has_correct_object_count(self):
        bundle = to_stix_bundle(SAMPLE_INDICATORS)
        assert len(bundle["objects"]) == 2

    def test_each_object_has_stix_type(self):
        bundle = to_stix_bundle(SAMPLE_INDICATORS)
        for obj in bundle["objects"]:
            assert obj["type"] == "indicator"
            assert obj["spec_version"] == "2.1"

    def test_ip_pattern_format(self):
        bundle = to_stix_bundle([SAMPLE_INDICATORS[0]])
        pattern = bundle["objects"][0]["pattern"]
        assert "ipv4-addr:value" in pattern
        assert "1.2.3.4" in pattern

    def test_domain_pattern_format(self):
        bundle = to_stix_bundle([SAMPLE_INDICATORS[1]])
        pattern = bundle["objects"][0]["pattern"]
        assert "domain-name:value" in pattern
        assert "evil.com" in pattern

    def test_external_reference_contains_hash(self):
        bundle = to_stix_bundle(SAMPLE_INDICATORS)
        refs = bundle["objects"][0]["external_references"]
        assert refs[0]["external_id"] == "a" * 64

    def test_empty_list_returns_empty_bundle(self):
        bundle = to_stix_bundle([])
        assert bundle["objects"] == []

    def test_severity_confidence_mapping(self):
        assert _severity_to_confidence("low")      == 30
        assert _severity_to_confidence("medium")   == 55
        assert _severity_to_confidence("high")     == 80
        assert _severity_to_confidence("critical") == 95
        assert _severity_to_confidence("unknown")  == 30