"""
tests/test_scrubber.py — unit tests for src/security/scrubber.py

Pure-function module, no mocking needed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security.scrubber import scrub, scrub_dict


class TestScrubIPv4:
    def test_redacts_ipv4(self):
        result, log = scrub("Connect to 192.168.10.5 for details.")
        assert "[REDACTED_IPV4]" in result
        assert "192.168.10.5" not in result
        assert ("IPV4", "192.168.10.5") in log

    def test_no_ipv4_no_redaction(self):
        result, log = scrub("No IP addresses here.")
        assert result == "No IP addresses here."
        assert log == []


class TestScrubHostname:
    def test_redacts_internal_hostname(self):
        result, log = scrub("Talk to db.internal over the network.")
        assert "[REDACTED_INTERNAL_HOSTNAME]" in result
        assert "db.internal" not in result

    def test_public_hostname_not_redacted(self):
        result, log = scrub("Visit example.com for docs.")
        assert "example.com" in result
        assert "REDACTED" not in result


class TestScrubPaths:
    def test_redacts_unix_path(self):
        result, log = scrub("Cert lives at /etc/ssl/certs/ca.pem")
        assert "[REDACTED_UNIX_PATH]" in result
        assert "/etc/ssl" not in result

    def test_redacts_windows_path(self):
        result, log = scrub(r"Config at C:\Users\admin\secrets.txt")
        assert "[REDACTED_WINDOWS_PATH]" in result
        assert "admin" not in result


class TestScrubEnvToken:
    def test_redacts_env_token(self):
        result, log = scrub("Using env.DATABASE_PASSWORD for auth.")
        assert "[REDACTED_ENV_TOKEN]" in result
        assert "DATABASE_PASSWORD" not in result


class TestScrubCombined:
    def test_multiple_patterns_in_one_string(self):
        text = (
            "Connect to 192.168.10.5 or db.internal on path "
            "/etc/ssl/certs/ca.pem from C:\\Users\\admin\\secrets.txt "
            "using env.DATABASE_PASSWORD"
        )
        result, log = scrub(text)
        assert "[REDACTED_IPV4]" in result
        assert "[REDACTED_INTERNAL_HOSTNAME]" in result
        assert "[REDACTED_UNIX_PATH]" in result
        assert "[REDACTED_WINDOWS_PATH]" in result
        assert "[REDACTED_ENV_TOKEN]" in result
        assert len(log) == 5

    def test_empty_string(self):
        result, log = scrub("")
        assert result == ""
        assert log == []

    def test_none_input(self):
        result, log = scrub(None)
        assert result is None
        assert log == []


class TestScrubDict:
    def test_scrubs_only_specified_fields(self):
        data = {
            "description": "Server at 192.168.1.1 is affected.",
            "cve_id": "CVE-2024-9999",  # not in fields list — must stay untouched
        }
        result, log = scrub_dict(data, fields=["description"])
        assert "[REDACTED_IPV4]" in result["description"]
        assert result["cve_id"] == "CVE-2024-9999"
        assert len(log) == 1

    def test_non_string_field_skipped(self):
        data = {"cvss_score": 9.8, "description": "no sensitive data"}
        result, log = scrub_dict(data, fields=["cvss_score", "description"])
        assert result["cvss_score"] == 9.8
        assert log == []

    def test_original_dict_not_mutated(self):
        data = {"description": "Contact 10.0.0.1"}
        scrub_dict(data, fields=["description"])
        assert data["description"] == "Contact 10.0.0.1"  # original untouched
