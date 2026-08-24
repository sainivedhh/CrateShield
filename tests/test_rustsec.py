"""Unit tests for rustsec.py advisory parsing and yanked-version resolution.

These tests mock the crates.io versions API so they run without network access.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from crateshield.ingestion.rustsec import (
    resolve_malicious_version,
    fetch_malicious_advisories,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ADVISORY_TOML = """
[advisory]
id = "RUSTSEC-2024-9999"
package = "evil-crate"
date = "2024-01-15"
url = "https://github.com/advisories/GHSA-fake"
categories = ["malicious-code"]
keywords = ["backdoor"]

[affected]
os = ["linux", "windows"]
"""

CRATES_IO_VERSIONS_RESPONSE = {
    "versions": [
        {"num": "1.0.1", "yanked": False},
        {"num": "1.0.0", "yanked": True},   # <-- the malicious yanked release
        {"num": "0.9.0", "yanked": False},
    ]
}

CRATES_IO_NO_YANKED_RESPONSE = {
    "versions": [
        {"num": "2.0.0", "yanked": False},
        {"num": "1.0.0", "yanked": False},
    ]
}


# ---------------------------------------------------------------------------
# Tests for _resolve_yanked_version
# ---------------------------------------------------------------------------

class TestResolveMaliciousVersion:
    def test_returns_yanked_version_from_registry(self):
        """Strategy 1: registry API returns a yanked version."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = CRATES_IO_VERSIONS_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_session.get.return_value = mock_resp

        version = resolve_malicious_version("evil-crate", {}, mock_session)
        assert version == "1.0.0"

    def test_falls_back_to_sparse_index_on_404(self):
        """Strategy 2: registry API returns 404, sparse index succeeds."""
        mock_session = MagicMock()

        registry_resp = MagicMock()
        registry_resp.status_code = 404

        sparse_resp = MagicMock()
        sparse_resp.status_code = 200
        sparse_resp.text = '{"name":"evil-crate","vers":"0.1.0","yanked":true}\n'
        sparse_resp.raise_for_status.return_value = None

        mock_session.get.side_effect = [registry_resp, sparse_resp]

        version = resolve_malicious_version("evil-crate", {}, mock_session)
        assert version == "0.1.0"

    def test_returns_none_when_all_strategies_fail(self):
        mock_session = MagicMock()
        resp_404 = MagicMock()
        resp_404.status_code = 404
        head_404 = MagicMock()
        head_404.status_code = 404
        mock_session.get.return_value = resp_404
        mock_session.head.return_value = head_404

        version = resolve_malicious_version("ghost-crate", {}, mock_session)
        assert version is None

    def test_returns_none_on_network_error(self):
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection refused")
        mock_session.head.side_effect = Exception("Connection refused")

        version = resolve_malicious_version("some-crate", {}, mock_session)
        assert version is None

    def test_prefers_most_recent_yanked_version(self):
        """When multiple versions are yanked, the newest should be returned."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "versions": [
                {"num": "2.0.0", "yanked": True},
                {"num": "1.0.0", "yanked": True},
                {"num": "0.1.0", "yanked": False},
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_session.get.return_value = mock_resp

        version = resolve_malicious_version("multi-yanked", {}, mock_session)
        assert version == "2.0.0"


# ---------------------------------------------------------------------------
# Tests for fetch_malicious_advisories (with mocked HTTP)
# ---------------------------------------------------------------------------

class TestFetchMaliciousAdvisories:
    def _make_advisory_raw_response(self, toml: str) -> str:
        """Wrap TOML in a markdown code fence as the RustSec advisory format expects."""
        return f"# Advisory Title\n\nSome text\n\n```toml\n{toml}\n```\n"

    def test_filters_malicious_advisory(self):
        """An advisory with categories=[malicious-code] should be included."""
        toml = (
            '[advisory]\nid = "RUSTSEC-2024-0001"\npackage = "evil"\n'
            'date = "2024-01-01"\ncategories = ["malicious-code"]\n'
        )
        mock_session = MagicMock()
        raw_md = self._make_advisory_raw_response(toml)

        # Mock the two-level API: crates listing -> per-crate listing -> raw advisory
        mock_session.get.side_effect = [
            MagicMock(json=lambda: [{"type": "dir", "url": "http://api/evil"}],
                      raise_for_status=lambda: None),
            MagicMock(json=lambda: [{"name": "RUSTSEC-2024-0001.md",
                                     "path": "crates/evil/RUSTSEC-2024-0001.md"}],
                      raise_for_status=lambda: None),
            MagicMock(text=raw_md, raise_for_status=lambda: None),
        ]

        advisories = fetch_malicious_advisories(mock_session)
        assert len(advisories) == 1
        assert advisories[0]["package"] == "evil"

    def test_excludes_informational_advisory(self):
        """An advisory marked informational should be excluded even if it mentions malicious."""
        toml = (
            '[advisory]\nid = "RUSTSEC-2024-0002"\npackage = "info-crate"\n'
            'date = "2024-01-01"\ncategories = ["malicious-code"]\n'
            'informational = "notice"\n'
        )
        mock_session = MagicMock()
        raw_md = self._make_advisory_raw_response(toml)

        mock_session.get.side_effect = [
            MagicMock(json=lambda: [{"type": "dir", "url": "http://api/info-crate"}],
                      raise_for_status=lambda: None),
            MagicMock(json=lambda: [{"name": "RUSTSEC-2024-0002.md",
                                     "path": "crates/info-crate/RUSTSEC-2024-0002.md"}],
                      raise_for_status=lambda: None),
            MagicMock(text=raw_md, raise_for_status=lambda: None),
        ]

        advisories = fetch_malicious_advisories(mock_session)
        assert len(advisories) == 0

    def test_excludes_non_malicious_advisory(self):
        """A vulnerability advisory with no malicious tags should be excluded."""
        toml = (
            '[advisory]\nid = "RUSTSEC-2024-0003"\npackage = "safe-vuln"\n'
            'date = "2024-01-01"\ncategories = ["memory-exposure"]\n'
        )
        mock_session = MagicMock()
        raw_md = self._make_advisory_raw_response(toml)

        mock_session.get.side_effect = [
            MagicMock(json=lambda: [{"type": "dir", "url": "http://api/safe"}],
                      raise_for_status=lambda: None),
            MagicMock(json=lambda: [{"name": "RUSTSEC-2024-0003.md",
                                     "path": "crates/safe/RUSTSEC-2024-0003.md"}],
                      raise_for_status=lambda: None),
            MagicMock(text=raw_md, raise_for_status=lambda: None),
        ]

        advisories = fetch_malicious_advisories(mock_session)
        assert len(advisories) == 0
