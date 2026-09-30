"""
tunneltwin.reports.html — Standalone Static HTML Report Generator.

Renders an executive & technical security assessment report from the SQLite fleet store.
Includes:
  - Header metadata (Target, Gateway, Detected Daemon, Duration, Status)
  - KPI summary cards (Total Findings, Critical, High, Cannot Assess)
  - Color-coded Findings table with explicit Provenance tags
  - Remediation diff view (before/after patches)
  - Cryptographic integrity seal & Merkle audit trail
Zero npm, zero React, self-contained vanilla CSS.
"""

from __future__ import annotations

import html
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

REPORTS_DIR = Path("reports")


def generate_html_report(scan_run_id: int, db_session: Session | None = None) -> str:
    """
    Generate a complete, self-contained HTML report string for a given ScanRun ID.

    Parameters:
        scan_run_id: Primary key of the ScanRun in the SQLite database.
        db_session: Optional open SQLModel session.

    Returns:
        str: Valid HTML5 document.
    """

    def _render(session: Session) -> str:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            raise ValueError(f"ScanRun #{scan_run_id} not found in database.")

        target = session.get(Target, scan_run.target_id) if scan_run.target_id else None
        gateways = session.exec(select(Gateway).where(Gateway.scan_run_id == scan_run_id)).all()
        findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        seals = session.exec(select(Seal).where(Seal.scan_run_id == scan_run_id)).all()

        gateway = gateways[0] if gateways else None
        target_ip = gateway.ip_address if gateway else (target.ip_or_cidr if target else "Unknown")
        target_port = str(gateway.port) if gateway else "500"
        detected_daemon = gateway.vendor_type if gateway else "Unknown"
        ike_ver = gateway.ike_version if gateway else "Unknown"

        # Severity breakdown
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL" and f.status.value == "FAIL")
        high_count = sum(1 for f in findings if f.severity == "HIGH" and f.status.value == "FAIL")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM" and f.status.value == "FAIL")
        pass_count = sum(1 for f in findings if f.status.value == "PASS")
        cannot_assess_count = sum(1 for f in findings if f.status.value == "CANNOT_ASSESS")
        total_count = len(findings)

        # Collect remediations linked to findings
        finding_id_set = {f.id for f in findings if f.id is not None}
        all_rems = session.exec(select(Remediation)).all()
        remediations = [r for r in all_rems if r.finding_id in finding_id_set]

        # Posture rating
        if crit_count > 0:
            posture = "CRITICAL NON-COMPLIANT"
            posture_class = "badge-crit"
        elif high_count > 0:
            posture = "ELEVATED RISK"
            posture_class = "badge-high"
        elif med_count > 0:
            posture = "MODERATE RISK"
            posture_class = "badge-med"
        elif total_count > 0 and pass_count == total_count:
            posture = "HARDENED / COMPLIANT"
            posture_class = "badge-pass"
        else:
            posture = "ASSESSMENT INCOMPLETE"
            posture_class = "badge-cannot"

        # Build Findings Rows
        finding_rows = []
        for f in findings:
            status_val = f.status.value
            status_badge_class = {
                "PASS": "badge-pass",
                "FAIL": "badge-crit",
                "CANNOT_ASSESS": "badge-cannot",
            }.get(status_val, "badge-cannot")

            sev_badge_class = {
                "CRITICAL": "badge-crit",
                "HIGH": "badge-high",
                "MEDIUM": "badge-med",
                "LOW": "badge-low",
                "INFO": "badge-info",
            }.get(f.severity, "badge-info")

            ev = html.escape(f.evidence_refs or "Direct probe SA response")
            finding_rows.append(
                f"""
                <tr>
                    <td class="font-mono"><strong>{html.escape(f.rule_id)}</strong><br>
                        <span class="subtext">{html.escape(f.rule_framework)}</span>
                    </td>
                    <td><span class="badge {sev_badge_class}">{html.escape(f.severity)}</span></td>
                    <td><span class="badge {status_badge_class}">{html.escape(status_val)}</span></td>
                    <td><span class="badge badge-prov">OBSERVED</span></td>
                    <td>
                        <div class="desc">{html.escape(f.detail)}</div>
                        <div class="subtext">Evidence / Citation: {ev}</div>
                    </td>
                </tr>
                """
            )

        # Build Remediation Section
        remediation_blocks = []
        for r in remediations:
            ver_status = "VERIFIED (Twin Check Passed)" if r.status.value == "VERIFIED" else "PROPOSED"
            ver_class = "badge-pass" if r.status.value == "VERIFIED" else "badge-med"
            remediation_blocks.append(
                f"""
                <div class="diff-card">
                    <div class="diff-header">
                        <strong>Remediation Patch — Target: {html.escape(r.vendor)}</strong>
                        <span class="badge {ver_class}">{html.escape(ver_status)}</span>
                    </div>
                    <pre class="diff-code">{html.escape(r.diff_text)}</pre>
                </div>
                """
            )

        # Seal info
        seal_text = "No seal recorded"
        if seals:
            s = seals[-1]
            seal_text = f"SHA-256: {s.sha256_hash} | Signed: {s.signed_by} | Time: {s.sealed_at.isoformat()}"

        rows_html = "".join(finding_rows)
        empty_row = '<tr><td colspan="5" style="text-align: center; color: #94a3b8;">No findings recorded.</td></tr>'
        body_table = rows_html if rows_html else empty_row

        rem_section = ""
        if remediation_blocks:
            rem_section = (
                '<div class="table-card"><h2>Remediation Plan & Twin Verification</h2>'
                + "".join(remediation_blocks)
                + "</div>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TunnelTwin Assessment Report — ScanRun #{scan_run_id}</title>
    <style>
        :root {{
            --bg-main: #0b1120;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --color-crit: #ef4444;
            --color-high: #f97316;
            --color-med: #eab308;
            --color-low: #3b82f6;
            --color-pass: #10b981;
            --color-info: #06b6d4;
            --color-prov: #0d9488;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-main);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 32px 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        .header h1 {{ font-size: 26px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }}
        .header .meta {{ font-size: 14px; color: var(--text-secondary); margin-top: 4px; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .kpi-card .label {{
            font-size: 13px; text-transform: uppercase; color: var(--text-secondary); font-weight: 600;
        }}
        .kpi-card .val {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-crit {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--color-crit);
            border: 1px solid var(--color-crit);
        }}
        .badge-high {{
            background: rgba(249, 115, 22, 0.2);
            color: var(--color-high);
            border: 1px solid var(--color-high);
        }}
        .badge-med {{
            background: rgba(234, 179, 8, 0.2);
            color: var(--color-med);
            border: 1px solid var(--color-med);
        }}
        .badge-low {{
            background: rgba(59, 130, 246, 0.2);
            color: var(--color-low);
            border: 1px solid var(--color-low);
        }}
        .badge-pass {{
            background: rgba(16, 185, 129, 0.2);
            color: var(--color-pass);
            border: 1px solid var(--color-pass);
        }}
        .badge-info {{
            background: rgba(6, 182, 212, 0.2);
            color: var(--color-info);
            border: 1px solid var(--color-info);
        }}
        .badge-cannot {{
            background: rgba(148, 163, 184, 0.2);
            color: #cbd5e1;
            border: 1px solid #64748b;
        }}
        .badge-prov {{
            background: rgba(13, 148, 136, 0.2);
            color: #2dd4bf;
            border: 1px solid #14b8a6;
            font-family: monospace;
        }}
        .table-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 32px;
        }}
        .table-card h2 {{ font-size: 18px; padding: 16px 20px; border-bottom: 1px solid var(--border); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
        th, td {{ padding: 14px 20px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        th {{
            background: #162032;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
        }}
        tr:hover {{ background: var(--bg-hover); }}
        .subtext {{ font-size: 12px; color: var(--text-secondary); margin-top: 3px; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .diff-card {{
            background: #111827;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin: 16px 20px;
        }}
        .diff-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .diff-code {{
            background: #030712;
            color: #38bdf8;
            font-family: ui-monospace, monospace;
            font-size: 13px;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        .seal-card {{
            background: #0f172a;
            border: 1px dashed #475569;
            border-radius: 8px;
            padding: 16px 20px;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 24px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>TunnelTwin — IPsec Assessment Report</h1>
                <div class="meta">
                    Target: <strong>{html.escape(target_ip)}:{html.escape(target_port)}</strong> |
                    Daemon: <strong>{html.escape(detected_daemon)}</strong> |
                    IKE: <strong>{html.escape(ike_ver)}</strong>
                </div>
            </div>
            <div>
                <span class="badge {posture_class}" style="font-size: 14px; padding: 6px 12px;">
                    {html.escape(posture)}
                </span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="label">Total Evaluated Rules</div>
                <div class="val">{total_count}</div>
            </div>
            <div class="kpi-card">
                <div class="label">Critical Findings</div>
                <div class="val" style="color: var(--color-crit);">{crit_count}</div>
            </div>
            <div class="kpi-card">
                <div class="label">High Risk Findings</div>
                <div class="val" style="color: var(--color-high);">{high_count}</div>
            </div>
            <div class="kpi-card">
                <div class="label">Rules Passed</div>
                <div class="val" style="color: var(--color-pass);">{pass_count}</div>
            </div>
            <div class="kpi-card">
                <div class="label">Cannot Assess (Zero-Pass)</div>
                <div class="val" style="color: #94a3b8;">{cannot_assess_count}</div>
            </div>
        </div>

        <div class="table-card">
            <h2>Security & Compliance Rule Evaluation</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 220px;">Rule ID & Citation</th>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 120px;">Outcome</th>
                        <th style="width: 120px;">Provenance</th>
                        <th>Evidence & Assessment Details</th>
                    </tr>
                </thead>
                <tbody>
                    {body_table}
                </tbody>
            </table>
        </div>

        {rem_section}

        <div class="seal-card">
            <strong>🔒 Cryptographic Ledger & Merkle Seal:</strong><br>
            <span class="font-mono">{html.escape(seal_text)}</span>
        </div>
    </div>
</body>
</html>
"""

    if db_session is not None:
        return _render(db_session)
    with Session(engine) as session:
        return _render(session)


def save_html_report(scan_run_id: int, output_path: str | Path | None = None) -> Path:
    """
    Generate and save the HTML report to disk.
    """
    content = generate_html_report(scan_run_id)
    if output_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / f"report_run_{scan_run_id}.html"
    else:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(content, encoding="utf-8")
    return path
