"""
tunneltwin.probe — Safe, consent-gated active IKE proposal probing engine.

Enforces strict allowlisting, explicit consent flags, and non-intrusive
proposal discovery.  All findings carry OBSERVED provenance.

Submodules:
    allowlist   — Consent-gated target allowlist (double-barrier enforcement).
    result      — Scan result data models with provenance tagging.
    scanner     — Async UDP probe engine with elimination scanning.
"""
