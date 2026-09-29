"""
Unit tests for the TunnelTwin Four-Tier Provenance Tracking System.
"""

import pytest

from tunneltwin.core.models import (
    NormalizedConnection,
    ProvenancedFact,
    ProvenanceTag,
)


def test_observed_fact():
    fact = ProvenancedFact.observed("aes256gcm", source_ref="probe_id:101")
    assert fact.tag == ProvenanceTag.OBSERVED
    assert fact.value == "aes256gcm"
    assert fact.confidence == 1.0
    assert fact.source_ref == "probe_id:101"
    assert fact.is_known() is True


def test_parsed_fact():
    fact = ProvenancedFact.parsed(1024, source_ref="cisco.cfg:line 42")
    assert fact.tag == ProvenanceTag.PARSED
    assert fact.value == 1024
    assert fact.confidence == 1.0
    assert fact.source_ref == "cisco.cfg:line 42"
    assert fact.is_known() is True


def test_inferred_fact_valid():
    fact = ProvenancedFact.inferred(
        "modp1024", confidence=0.85, source_ref="ml_heuristic_v1", notes="Default Cisco IOS 12.x"
    )
    assert fact.tag == ProvenanceTag.INFERRED
    assert fact.value == "modp1024"
    assert fact.confidence == 0.85
    assert fact.notes == "Default Cisco IOS 12.x"
    assert fact.is_known() is True


def test_inferred_fact_invalid_confidence():
    with pytest.raises(ValueError):
        ProvenancedFact[str](tag=ProvenanceTag.INFERRED, value="aes128", confidence=1.5)
    with pytest.raises(ValueError):
        ProvenancedFact[str](tag=ProvenanceTag.INFERRED, value="aes128", confidence=None)


def test_unknown_fact():
    fact = ProvenancedFact[str].unknown(source_ref="missing_in_config", notes="Peer lifetime not specified")
    assert fact.tag == ProvenanceTag.UNKNOWN
    assert fact.value is None
    assert fact.confidence is None
    assert fact.is_known() is False


def test_normalized_connection_default_provenance():
    conn = NormalizedConnection()
    assert conn.ike_version.tag == ProvenanceTag.UNKNOWN
    assert conn.ike_version.is_known() is False
    assert conn.auth_method.tag == ProvenanceTag.UNKNOWN
