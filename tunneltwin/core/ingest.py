"""
tunneltwin.core.ingest — Ingestion engine bridging live scan & rule evaluation to SQLite fleet store.

Extracts real probe observations from Phase 1 GatewayScanResult, rule evaluation
findings from Phase 2 RuleResult, and remediation diffs from Phase 3, persisting
the complete provenance graph into the SQLite database.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlmodel import Session, select

from tunneltwin.core.db import (
    Fact as DbFact,
)
from tunneltwin.core.db import (
    Finding as DbFinding,
)
from tunneltwin.core.db import (
    FindingStatus,
    ProvenanceEnum,
    RemediationStatus,
    ScanRun,
    ScanStatus,
    Seal,
    SealType,
    Target,
    engine,
    init_db,
)
from tunneltwin.core.db import (
    Gateway as DbGateway,
)
from tunneltwin.core.db import (
    Remediation as DbRemediation,
)
from tunneltwin.core.models import AssessmentStatus
from tunneltwin.rules.facts import scan_result_to_facts

if TYPE_CHECKING:
    from tunneltwin.probe.result import GatewayScanResult
    from tunneltwin.rules.engine import RuleResult

logger = logging.getLogger("tunneltwin.core.ingest")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _map_severity(severity_int: int, status: AssessmentStatus) -> str:
    """Map numeric severity (1-10) and status to severity category string."""
    if status == AssessmentStatus.PASS:
        return "INFO"
    if severity_int >= 9:
        return "CRITICAL"
    if severity_int >= 7:
        return "HIGH"
    if severity_int >= 4:
        return "MEDIUM"
    return "LOW"


def _map_finding_status(status: AssessmentStatus) -> FindingStatus:
    """Convert core AssessmentStatus to SQLModel FindingStatus enum."""
    if status == AssessmentStatus.PASS:
        return FindingStatus.PASS
    if status == AssessmentStatus.FAIL:
        return FindingStatus.FAIL
    return FindingStatus.CANNOT_ASSESS


def ingest_scan_run(
    scan_result: GatewayScanResult,
    rule_results: list[RuleResult] | None = None,
    remediations: list[dict[str, object]] | None = None,
    target_owner: str = "Lab-Operations",
    profile_name: str = "weak",
    operator: str = "tunneltwin-cli",
    db_session: Session | None = None,
) -> int:
    """
    Ingest a live Phase 1 GatewayScanResult and Phase 2 RuleResults into the SQLite fleet store.

    Parameters:
        scan_result: Live active scan output.
        rule_results: Evaluated compliance rules (optional).
        remediations: Remediation diffs/metadata attached to findings (optional).
        target_owner: Target organizational owner.
        profile_name: Named target profile (e.g. "weak", "mixed", "strong", "legacy-cbc").
        operator: Scanning entity/user identity.
        db_session: Optional external SQLModel session.

    Returns:
        int: The primary key ID of the created ScanRun.
    """
    init_db()

    def _execute(session: Session) -> int:
        # 1. Target allowlist/inventory entry
        target = session.exec(select(Target).where(Target.ip_or_cidr == scan_result.target_ip)).first()
        if not target:
            target = Target(
                ip_or_cidr=scan_result.target_ip,
                owner=target_owner,
                description=f"Auto-registered scan target ({profile_name})",
                consent_verified=True,
                created_at=_now(),
            )
            session.add(target)
            session.flush()

        # 2. ScanRun session record
        started = (
            datetime.fromtimestamp(scan_result.scan_start_time, tz=timezone.utc)
            if scan_result.scan_start_time
            else _now()
        )
        finished = (
            datetime.fromtimestamp(scan_result.scan_end_time, tz=timezone.utc) if scan_result.scan_end_time else _now()
        )
        is_success = scan_result.scan_status.value == "success"

        scan_run = ScanRun(
            target_id=target.id,
            status=ScanStatus.COMPLETED if is_success else ScanStatus.FAILED,
            scan_type="probe",
            started_at=started,
            finished_at=finished,
            notes=(
                f"profile={profile_name} probes={scan_result.probe_count} "
                f"duration_ms={scan_result.scan_duration_ms:.1f}"
            ),
        )
        session.add(scan_run)
        session.flush()

        # 3. Gateway endpoint observation
        ike_ver = scan_result.ike_version_detected.value or "UNKNOWN"
        vendor = scan_result.detected_daemon or "UNKNOWN"

        gateway = DbGateway(
            scan_run_id=scan_run.id,
            target_id=target.id,
            ip_address=scan_result.target_ip,
            port=scan_result.target_port,
            ike_version=str(ike_ver),
            vendor_type=str(vendor),
            provenance=ProvenanceEnum.OBSERVED,
            responded=is_success,
            discovered_at=_now(),
        )
        session.add(gateway)
        session.flush()

        # 4. Atomic Fact extraction via rules.facts bridge
        fact_store = scan_result_to_facts(scan_result)
        subject_id = f"{scan_result.target_ip}:{scan_result.target_port}"
        observed_facts = fact_store.all_facts_for(subject_id)

        for fact in observed_facts:
            # Map ProvenanceTag to ProvenanceEnum
            tag_name = fact.provenance.value.upper()
            prov_enum = getattr(ProvenanceEnum, tag_name, ProvenanceEnum.UNKNOWN)

            db_fact = DbFact(
                scan_run_id=scan_run.id,
                gateway_id=gateway.id,
                parameter=fact.key,
                raw_value=fact.value,
                provenance=prov_enum,
                confidence=fact.confidence,
                source_ref=fact.source_pointer,
                notes=f"Real scan observation ({profile_name})",
                recorded_at=_now(),
            )
            session.add(db_fact)

        session.flush()

        # 5. Rule Evaluation Findings
        finding_map: dict[str, DbFinding] = {}
        if rule_results:
            for r in rule_results:
                f_status = _map_finding_status(r.status)
                f_sev = _map_severity(r.severity, r.status)

                finding = DbFinding(
                    scan_run_id=scan_run.id,
                    rule_id=r.rule_id,
                    rule_framework=r.pack,
                    parameter=r.category,
                    status=f_status,
                    severity=f_sev,
                    detail=r.message or r.rule_name,
                    evidence_refs=r.citation,
                    assessed_at=_now(),
                )
                session.add(finding)
                session.flush()
                finding_map[r.rule_id] = finding

        # 6. Remediations (if provided)
        if remediations:
            for rem in remediations:
                rule_id = str(rem.get("rule_id", ""))
                target_finding = finding_map.get(rule_id)
                finding_id = target_finding.id if target_finding else None

                is_verified = bool(rem.get("verified", False))
                rem_status = RemediationStatus.VERIFIED if is_verified else RemediationStatus.PROPOSED

                db_rem = DbRemediation(
                    finding_id=finding_id,
                    vendor=str(rem.get("vendor", "strongswan")),
                    diff_text=str(rem.get("diff_text", "")),
                    status=rem_status,
                    verified_by=operator if is_verified else None,
                    proposed_at=_now(),
                    applied_at=_now() if is_verified else None,
                )
                session.add(db_rem)

            session.flush()

        # 7. Cryptographic Merkle Seal for Run Integrity
        finding_digests = [f"{f.rule_id}:{f.status}:{f.severity}" for f in finding_map.values()]
        payload = json.dumps(
            {
                "scan_run_id": scan_run.id,
                "target": scan_result.target_ip,
                "profile": profile_name,
                "status": scan_run.status.value,
                "findings": sorted(finding_digests),
                "timestamp": _now().isoformat(),
            },
            sort_keys=True,
        )
        run_hash = _sha256(payload)

        seal = Seal(
            scan_run_id=scan_run.id,
            seal_type=SealType.SCAN,
            entity_type="scan_run",
            entity_id=scan_run.id,
            sha256_hash=run_hash,
            merkle_root=run_hash,
            signed_by=operator,
            sealed_at=_now(),
            notes=f"Integrity seal for scan_run #{scan_run.id} ({profile_name})",
        )
        session.add(seal)
        session.commit()
        session.refresh(scan_run)
        return int(scan_run.id or 0)

    if db_session is not None:
        return _execute(db_session)
    with Session(engine) as session:
        return _execute(session)
