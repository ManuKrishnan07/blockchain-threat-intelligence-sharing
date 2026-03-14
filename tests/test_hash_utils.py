import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from hash_utils import generate_indicator_hash, verify_hash, generate_record_hash


class TestGenerateIndicatorHash:

    def test_returns_64_char_hex_string(self):
        h = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_deterministic_same_inputs(self):
        h1 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        h2 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        assert h1 == h2

    def test_different_value_different_hash(self):
        h1 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        h2 = generate_indicator_hash("ip", "5.6.7.8", "1700000000", "org_a")
        assert h1 != h2

    def test_different_type_different_hash(self):
        h1 = generate_indicator_hash("ip",     "test.com", "1700000000", "org_a")
        h2 = generate_indicator_hash("domain", "test.com", "1700000000", "org_a")
        assert h1 != h2

    def test_different_reporter_different_hash(self):
        h1 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        h2 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_b")
        assert h1 != h2

    def test_different_timestamp_different_hash(self):
        h1 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        h2 = generate_indicator_hash("ip", "1.2.3.4", "1700000001", "org_a")
        assert h1 != h2

    def test_whitespace_stripped(self):
        h1 = generate_indicator_hash("ip",   "1.2.3.4",   "1700000000", "org_a")
        h2 = generate_indicator_hash(" ip ", " 1.2.3.4 ", "1700000000", "org_a")
        # type gets lowercased+stripped; value gets stripped
        assert h1 == h2

    def test_type_case_insensitive(self):
        h1 = generate_indicator_hash("IP", "1.2.3.4", "1700000000", "org_a")
        h2 = generate_indicator_hash("ip", "1.2.3.4", "1700000000", "org_a")
        assert h1 == h2


class TestVerifyHash:

    def test_correct_inputs_returns_true(self):
        h = generate_indicator_hash("domain", "evil.ru", "1700000000", "org_x")
        assert verify_hash("domain", "evil.ru", "1700000000", "org_x", h) is True

    def test_tampered_value_returns_false(self):
        h = generate_indicator_hash("domain", "evil.ru", "1700000000", "org_x")
        assert verify_hash("domain", "TAMPERED.ru", "1700000000", "org_x", h) is False

    def test_empty_hash_returns_false(self):
        assert verify_hash("ip", "1.1.1.1", "123", "org", "") is False


class TestGenerateRecordHash:

    def test_excludes_id_and_data_hash(self):
        record = {
            "_id":       "mongo_object_id",
            "data_hash": "existing_hash",
            "indicator_type": "ip",
            "indicator_value": "1.2.3.4"
        }
        h = generate_record_hash(record)
        # Should not raise and should be a valid hash
        assert len(h) == 64

    def test_key_order_does_not_matter(self):
        r1 = {"indicator_type": "ip",     "indicator_value": "1.2.3.4"}
        r2 = {"indicator_value": "1.2.3.4", "indicator_type": "ip"}
        assert generate_record_hash(r1) == generate_record_hash(r2)