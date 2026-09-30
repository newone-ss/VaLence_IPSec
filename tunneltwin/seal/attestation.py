"""
tunneltwin.seal.attestation -- Deterministic Signed Compliance Attestation Generator.

Produces formal, human-readable and machine-verifiable Markdown compliance certificates
attesting to scanned IPsec gateway posture, cited standards, verified remediations,
and cryptographic Ed25519 Merkle signatures.
"""

from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, select

from tunneltwin.core.db import (
    Finding,
    Gateway,
    Remediation,
    ScanRun,
    Seal,
    Target,
    engine,
)
from tunneltwin.seal.engine import verify_scan_run

REPORTS_DIR = Path("reports")


def generate_attestation_certificate(
    scan_run_id: int,
    db_session: Session | None = None,
) -> str:
    """
    Generate a deterministic Markdown compliance attestation certificate
    for a given ScanRun.
    """

    def _render(session: Session) -> str:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            raise ValueError(f"ScanRun #{scan_run_id} not found in fleet store.")

        target = session.get(Target, scan_run.target_id) if scan_run.target_id else None
        gateways = session.exec(select(Gateway).where(Gateway.scan_run_id == scan_run_id)).all()
        findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        seals = session.exec(
            select(Seal).where(Seal.scan_run_id == scan_run_id).order_by(Seal.id.desc())  # type: ignore[union-attr]
        ).all()

        gateway = gateways[0] if gateways else None
        target_ip = gateway.ip_address if gateway else (target.ip_or_cidr if target else "Unknown")
        target_port = gateway.port if gateway else 500
        detected_daemon = gateway.vendor_type if gateway else "Unknown"
        ike_version = gateway.ike_version if gateway else "Unknown"

        latest_seal = seals[0] if seals else None
        merkle_root = latest_seal.merkle_root if latest_seal else "UNSEALED"
        signature = latest_seal.signature if latest_seal else "UNSIGNED"
        signer = latest_seal.signed_by if latest_seal else "Unknown"
        sealed_time = latest_seal.sealed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_seal else "N/A"

        # Public key extract
        pub_key = "N/A"
        if latest_seal and latest_seal.notes and "public_key=" in latest_seal.notes:
            for part in latest_seal.notes.split(";"):
                if part.startswith("public_key="):
                    pub_key = part.split("=", 1)[1].strip()
                    break

        # Verification check
        v_report = verify_scan_run(scan_run_id, db_session=session)
        integrity_status = "VERIFIED (AUTHENTIC)" if v_report.is_valid else f"FAILED ({v_report.status})"

        # Categorize findings by cited standards (NIST SP 800-77, NSA CNSA Suite, etc.)
        # Categorize findings by cited standards (NIST SP 800-77, NSA CNSA Suite, etc.)
        crit_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL" and f.status.value == "FAIL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH" and f.status.value == "FAIL")
        pass_count = sum(1 for f in findings if f.status.value == "PASS")

        # Fetch Remediations
        finding_id_set = {f.id for f in findings if f.id is not None}
        all_rems = session.exec(select(Remediation)).all()
        remediations = [r for r in all_rems if r.finding_id in finding_id_set]

        # Markdown Document Assembly
        lines: list[str] = [
            "# CRYPTOGRAPHIC COMPLIANCE ATTESTATION CERTIFICATE",
            "**Valence-IPsec / TunnelTwin Security Assessment Framework**",
            f"**Attestation ID:** TT-CERT-RUN-{scan_run_id:06d}  ",
            f"**Issued Timestamp:** {sealed_time}  ",
            f"**Integrity Seal Status:** {integrity_status}  ",
            "",
            "---",
            "",
            "## 1. Gateway Identification & Scope of Assessment",
            "",
            f"- **Target Endpoint:** `{target_ip}:{target_port}`",
            f"- **Discovered Daemon / Vendor:** `{detected_daemon}`",
            f"- **Detected IKE Protocol:** `{ike_version}`",
            f"- **Scan Run Reference:** ScanRun #{scan_run_id}",
            f"- **Operator Identity:** `{signer}`",
            "",
            "## 2. Cited Standards & Rule Packs",
            "",
            "- **NIST Special Publication 800-77 Rev 1**: *Guide to IPsec VPNs* (Authoritative)",
            (
                "- **NSA Commercial National Security Algorithm (CNSA) Suite 2.0**: "
                "*Quantum-Resistant Cryptography Requirements* (Authoritative)"
            ),
            (
                "- **CERT-In Technical Advisory**: "
                "*Pending confirmation of official primary publication; recorded as informational advisory only.*"
            ),
            "",
            "## 3. Executive Posture Summary",
            "",
            f"- **Total Evaluated Criteria:** {len(findings)}",
            f"- **Critical Vulnerabilities:** {crit_count}",
            f"- **High-Risk Non-Compliances:** {high_count}",
            f"- **Conforming Rules (PASS):** {pass_count}",
            "",
            "## 4. Evaluated Findings & Technical Evidence",
            "",
            "| Rule ID | Standard / Framework | Severity | Outcome | Parameter | Assessment Narrative |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        # Format rows sorted deterministically
        for f in sorted(findings, key=lambda x: (x.severity != "CRITICAL", x.severity != "HIGH", x.rule_id)):
            detail_clean = f.detail.replace("\n", " ").strip()
            row = (
                f"| `{f.rule_id}` | {f.rule_framework} | **{f.severity}** | "
                f"`{f.status.value}` | `{f.parameter}` | {detail_clean} |"
            )
            lines.append(row)

        lines.extend(
            [
                "",
                "## 5. Verified Remediation & Re-Scan State",
                "",
            ]
        )

        if remediations:
            for rem in remediations:
                v_badge = "[VERIFIED]" if rem.status.value == "VERIFIED" else "[PROPOSED]"
                lines.append(f"### Proposed Patch: {rem.vendor} {v_badge}")
                lines.append("```diff")
                lines.append(rem.diff_text.strip())
                lines.append("```")
                lines.append("")
        else:
            lines.append("*No remediation patches generated for this assessment run.*")
            lines.append("")

        lines.extend(
            [
                "---",
                "",
                "## 6. Cryptographic Trust Anchor & Verification Signature",
                "",
                "This document is cryptographically bound to the underlying factual observations and rule findings.",
                "Any alteration to a single byte of stored finding or remediation records invalidates the Merkle root.",
                "",
                f"- **SHA-256 Merkle Root:** `{merkle_root}`",
                f"- **Ed25519 Signer Public Key:** `{pub_key}`",
                "- **Ed25519 Digital Signature:**",
                "  ```text",
                f"  {signature}",
                "  ```",
                "",
                "### Verification Command",
                "To independently recompute the Merkle tree and verify this certificate against the fleet store:",
                "```bash",
                f"tunneltwin verify {scan_run_id}",
                "```",
                "",
                "---",
                f"*Generated deterministically by TunnelTwin Trust Layer v0.1.0 on {sealed_time}.*",
            ]
        )

        return "\n".join(lines) + "\n"

    if db_session:
        return _render(db_session)
    with Session(engine) as session:
        return _render(session)


def save_attestation_certificate(
    scan_run_id: int,
    output_path: Path | None = None,
    db_session: Session | None = None,
) -> Path:
    """Save the generated attestation certificate markdown file to disk."""
    content = generate_attestation_certificate(scan_run_id, db_session=db_session)
    out = output_path or (REPORTS_DIR / f"attestation_run_{scan_run_id}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out
