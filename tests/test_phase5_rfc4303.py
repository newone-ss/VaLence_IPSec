# tests/test_phase5_rfc4303.py
from tunneltwin.capture.rfc4303 import consistent_suites, narrow_by_lengths


def test_cbc_length_must_be_block_aligned():
    # ESP len 8 (hdr) + 16 (iv) + N + 12 (icv); N must be a multiple of 16.
    bad = 8 + 16 + 17 + 12
    assert not any(s.enc == "ENCR_AES_CBC" for s in consistent_suites(bad))
    good = 8 + 16 + 32 + 12
    assert any(s.enc == "ENCR_AES_CBC" for s in consistent_suites(good))


def test_gcm_has_no_alignment_constraint():
    for n in (2, 3, 7, 19, 64):
        assert any(s.aead for s in consistent_suites(8 + 8 + n + 16))


def test_intersection_shrinks_candidate_set():
    # 68 = 8(hdr) + 16(iv) + 32(body) + 12(icv) -> body=32 valid for AES-CBC/SHA1
    # 76 = 8 + 16 + 40 + 12 -> body=40, 40%16=8 INVALID for AES-CBC/SHA1
    # but both valid for AES-CTR (stream) and AES-GCM (AEAD, no block constraint)
    lengths = [68, 76]
    assert len(narrow_by_lengths(lengths)) < len(consistent_suites(lengths[0]))
