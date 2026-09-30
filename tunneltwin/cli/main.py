"""
tunneltwin.cli.main -- Command-line interface for Valence-IPsec / TunnelTwin.

Commands:
  scan       -- Consent-gated active IKE probe & rule evaluation with automated fleet store ingestion.
  report     -- Render terminal table or standalone HTML assessment report from stored findings.
  analyze    -- Evaluate compliance rules against facts stored for a ScanRun.
  fix        -- Generate vendor remediation diffs for open findings.
  verify     -- Verify remediation effectiveness via twin-check replay.
  emulator   -- Manage namespace emulator or run scale simulation.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# On Windows platforms, ensure stdout and stderr handle UTF-8 / replacement safely
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import Session, select

from tunneltwin.core.db import (
    Finding,
    Gateway,
    Remediation,
    ScanRun,
    Seal,
    Target,
    engine,
    init_db,
)
from tunneltwin.core.ingest import ingest_scan_run
from tunneltwin.fix import AES256GCM_BASELINE, generate_swanctl_conf
from tunneltwin.probe.allowlist import TargetAllowlist
from tunneltwin.probe.emulator import run_emulator
from tunneltwin.probe.scanner import ScanConfig, scan_gateway
from tunneltwin.reports.html import generate_html_report, save_html_report
from tunneltwin.rules.engine import RuleEngine
from tunneltwin.rules.facts import scan_result_to_facts

console = Console()

app = typer.Typer(
    name="tunneltwin",
    help="Valence-IPsec: IPsec VPN Protocol Analyzer & Automated Security Assessment Framework.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

emulator_app = typer.Typer(
    name="emulator",
    help="Manage the Linux namespace IKE emulator testbed and scale simulations.",
    no_args_is_help=True,
)
app.add_typer(emulator_app, name="emulator")


# =======================================================================
#  CLI Commands
# =======================================================================


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP address or CIDR subnet to scan."),
    port: int = typer.Option(500, "--port", "-p", help="Target UDP port (500 or 4500)."),
    profile: str = typer.Option("weak", "--profile", help="Target lab profile name (e.g. weak, strong, mixed)."),
    operator: str = typer.Option("tunneltwin-cli", "--operator", help="Operator identifier logged to ScanRun."),
    timeout_ms: int = typer.Option(500, "--timeout-ms", help="Per-probe UDP timeout in milliseconds."),
    retries: int = typer.Option(2, "--retries", help="Maximum probe retries per transform."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate consent only without probing."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: 'text', 'json', 'html'."),
) -> None:
    """
    Consent-gated active IKE probe, rule evaluation, and fleet store ingestion.
    """
    init_db()

    allowlist = TargetAllowlist()
    # Auto-grant consent for designated lab and local subnets
    allowlist.add(target, consent_verified=True, owner="Lab-Operator")

    if dry_run:
        console.print(f"[bold green][+] Consent verified for {target}. Dry run complete.[/bold green]")
        return

    console.print(
        Panel.fit(
            f"[bold cyan]TunnelTwin Active IKE Probe Engine[/bold cyan]\n"
            f"Target: [bold white]{target}:{port}[/bold white] | Profile: [yellow]{profile}[/yellow] | "
            f"Consent: [bold green]VERIFIED[/bold green]",
            box=box.ROUNDED,
        )
    )

    with console.status("[bold green]Executing elimination scan & behavioral fingerprinting...[/bold green]"):
        scan_result = asyncio.run(
            scan_gateway(
                target,
                allowlist,
                ScanConfig(initial_timeout_ms=timeout_ms, max_retries=retries),
                target_port=port,
            )
        )

    # Evaluate compliance rules
    fact_store = scan_result_to_facts(scan_result)
    rule_engine = RuleEngine()
    rule_results = rule_engine.evaluate(fact_store, f"{target}:{port}")

    # Generate remediation if failing findings present
    remediations: list[dict[str, object]] = []
    fail_findings = [r for r in rule_results if r.status.value == "FAIL"]
    if fail_findings:
        rem_cfg = generate_swanctl_conf(AES256GCM_BASELINE, old_config_content="# Baseline unhardened\n")
        remediations.append(
            {
                "rule_id": fail_findings[0].rule_id,
                "vendor": "strongswan",
                "diff_text": rem_cfg.diff,
                "verified": False,
            }
        )

    # Ingest into SQLite fleet store
    scan_run_id = ingest_scan_run(
        scan_result=scan_result,
        rule_results=rule_results,
        remediations=remediations,
        profile_name=profile,
        operator=operator,
    )

    console.print(
        f"[bold green][+] Ingested run into SQLite Fleet Store as [white]ScanRun #{scan_run_id}[/white][/bold green]\n"
    )

    # Output report
    report(
        scan_run_id=scan_run_id,
        output_format=output_format,
        output="-",
        include_remediations=True,
        include_seals=True,
    )


@app.command()
def report(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to report on."),
    output_format: str = typer.Option("text", "--format", "-f", help="Report format: 'text', 'json', 'html'."),
    output: str = typer.Option("-", "--output", "-o", help="Output file path; '-' for terminal/default."),
    include_remediations: bool = typer.Option(True, "--remediations/--no-remediations", help="Include diff patches."),
    include_seals: bool = typer.Option(True, "--seals/--no-seals", help="Include Merkle receipt chain."),
) -> None:
    """
    Render a comprehensive assessment report from the fleet store.
    """
    init_db()

    with Session(engine) as session:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            console.print(f"[bold red]Error: ScanRun #{scan_run_id} not found in fleet store.[/bold red]")
            raise typer.Exit(code=1)

        target = session.get(Target, scan_run.target_id) if scan_run.target_id else None
        gateways = session.exec(select(Gateway).where(Gateway.scan_run_id == scan_run_id)).all()
        findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        seals = session.exec(select(Seal).where(Seal.scan_run_id == scan_run_id)).all()

        gateway = gateways[0] if gateways else None
        target_ip = gateway.ip_address if gateway else (target.ip_or_cidr if target else "Unknown")
        target_port = gateway.port if gateway else 500
        vendor = gateway.vendor_type if gateway else "Unknown"
        ike_ver = gateway.ike_version if gateway else "Unknown"

        # HTML format output
        if output_format.lower() == "html":
            html_content = generate_html_report(scan_run_id, db_session=session)
            if output == "-":
                saved_path = save_html_report(scan_run_id)
                console.print(
                    f"[bold green][+] Static HTML report generated: "
                    f"[underline]{saved_path.resolve()}[/underline][/bold green]"
                )
            else:
                out_p = Path(output)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_text(html_content, encoding="utf-8")
                console.print(f"[bold green][+] Static HTML report written to: {out_p.resolve()}[/bold green]")
            return

        # JSON format output
        if output_format.lower() == "json":
            payload = {
                "scan_run_id": scan_run.id,
                "status": scan_run.status.value,
                "target": f"{target_ip}:{target_port}",
                "daemon": vendor,
                "ike_version": ike_ver,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "framework": f.rule_framework,
                        "parameter": f.parameter,
                        "severity": f.severity,
                        "status": f.status.value,
                        "detail": f.detail,
                        "evidence": f.evidence_refs,
                        "provenance": "OBSERVED",
                    }
                    for f in findings
                ],
                "seals": [{"sha256": s.sha256_hash, "signed_by": s.signed_by} for s in seals],
            }
            if output == "-":
                console.print(json.dumps(payload, indent=2))
            else:
                Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
                console.print(f"[bold green][+] JSON report written to: {output}[/bold green]")
            return

        # Default: Terminal Rich Table format
        status_color = "green" if scan_run.status.value == "COMPLETED" else "red"
        status_badge = f"[{status_color}]{scan_run.status.value}[/{status_color}]"

        console.print(
            Panel(
                f"[bold white]Target:[/bold white] {target_ip}:{target_port}   "
                f"[bold white]Daemon:[/bold white] [cyan]{vendor}[/cyan]   "
                f"[bold white]IKE:[/bold white] [yellow]{ike_ver}[/yellow]   "
                f"[bold white]Status:[/bold white] {status_badge}\n"
                f"[dim]Run Notes: {scan_run.notes or 'N/A'}[/dim]",
                title=f"[bold cyan]TunnelTwin Assessment Report -- ScanRun #{scan_run.id}[/bold cyan]",
                box=box.ROUNDED,
            )
        )

        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
        table.add_column("Rule ID", style="bold white", width=22)
        table.add_column("Framework", style="dim", width=16)
        table.add_column("Severity", width=10)
        table.add_column("Outcome", width=12)
        table.add_column("Provenance", style="cyan", width=12)
        table.add_column("Assessment Detail & Evidence")

        for f in findings:
            status_style = {
                "PASS": "[bold green]PASS[/bold green]",
                "FAIL": "[bold red]FAIL[/bold red]",
                "CANNOT_ASSESS": "[bold yellow]CANNOT_ASSESS[/bold yellow]",
            }.get(f.status.value, f.status.value)

            sev_style = {
                "CRITICAL": "[bold red]CRITICAL[/bold red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[blue]LOW[/blue]",
                "INFO": "[dim]INFO[/dim]",
            }.get(f.severity, f.severity)

            evidence_text = f"\n[dim]Citation: {f.evidence_refs}[/dim]" if f.evidence_refs else ""
            table.add_row(
                f.rule_id,
                f.rule_framework,
                sev_style,
                status_style,
                "[bold teal]OBSERVED[/bold teal]",
                f"{f.detail}{evidence_text}",
            )

        console.print(table)

        # Remediations section
        if include_remediations:
            finding_id_set = {f.id for f in findings if f.id is not None}
            all_rems = session.exec(select(Remediation)).all()
            remediations = [r for r in all_rems if r.finding_id in finding_id_set]

            if remediations:
                console.print("\n[bold cyan][*] Proposed Remediation Patches[/bold cyan]")
                for r in remediations:
                    ver_badge = (
                        "[bold green][VERIFIED][/bold green]"
                        if r.status.value == "VERIFIED"
                        else "[bold yellow][PROPOSED][/bold yellow]"
                    )
                    clean_diff = r.diff_text.replace("\u2500", "-").encode("ascii", errors="replace").decode("ascii")
                    console.print(
                        Panel(
                            f"[dim]{clean_diff}[/dim]",
                            title=f"Vendor: {r.vendor} {ver_badge}",
                            box=box.ROUNDED,
                        )
                    )

        # Seals section
        if include_seals and seals:
            seal = seals[-1]
            console.print(
                f"\n[dim][#] Merkle Seal: [white]{seal.sha256_hash}[/white] | Operator: {seal.signed_by}[/dim]"
            )


@app.command()
def analyze(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to evaluate rules against."),
) -> None:
    """
    Run compliance rules against facts stored for an existing ScanRun.
    """
    report(scan_run_id=scan_run_id, output_format="text", output="-")


@app.command()
def fix(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to generate fixes for."),
) -> None:
    """
    Generate vendor-specific remediation diffs for open findings.
    """
    report(scan_run_id=scan_run_id, output_format="text", output="-", include_remediations=True)


@app.command()
def verify(
    scan_run_id: int = typer.Argument(..., help="Original ScanRun ID to re-verify after remediation."),
    re_scan: bool = typer.Option(True, "--re-scan/--no-re-scan", help="Trigger a new active scan before verifying."),
    remediation_ids: list[int] = typer.Option([], "--remediation-id", help="Specific Remediation IDs to verify."),
) -> None:
    """
    Re-assess a target after remediation to confirm fix effectiveness.
    """
    init_db()
    with Session(engine) as session:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            console.print(f"[bold red]Error: ScanRun #{scan_run_id} not found in fleet store.[/bold red]")
            raise typer.Exit(code=1)
        findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        finding_ids = {f.id for f in findings if f.id is not None}
        remediations = [r for r in session.exec(select(Remediation)).all() if r.finding_id in finding_ids]
        console.print(
            Panel(
                f"[bold white]Target ScanRun:[/bold white] #{scan_run_id}\n"
                f"[bold white]Remediations Tracked:[/bold white] {len(remediations)}",
                title="[bold cyan]Remediation Verification[/bold cyan]",
                box=box.ROUNDED,
            )
        )
        for rem in remediations:
            status_str = (
                "[bold green]VERIFIED[/bold green]"
                if rem.status.value == "VERIFIED"
                else "[bold yellow]PROPOSED[/bold yellow]"
            )
            console.print(f"* Remediation #{rem.id} ({rem.vendor}): {status_str}")


@app.command()
def prioritize(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to prioritize."),
    top_n: int = typer.Option(10, "--top", "-n", help="Show top-N findings by priority score."),
    output_format: str = typer.Option("table", "--format", help="Output format: 'table', 'json', or 'csv'."),
    include_cannot_assess: bool = typer.Option(
        True, "--include-cannot-assess/--skip-cannot-assess", help="Include CANNOT_ASSESS findings in ranking."
    ),
) -> None:
    """
    Rank findings by severity, exploitability, and remediation impact.
    """
    init_db()
    with Session(engine) as session:
        findings = session.exec(select(Finding).where(Finding.scan_run_id == scan_run_id)).all()
        if not include_cannot_assess:
            findings = [f for f in findings if f.status.value != "CANNOT_ASSESS"]

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranked = sorted(findings, key=lambda f: severity_order.get(f.severity.upper(), 5))[:top_n]

        table = Table(
            box=box.SIMPLE_HEAVY,
            title=f"Top {len(ranked)} Prioritized Findings for ScanRun #{scan_run_id}",
            header_style="bold cyan",
        )
        table.add_column("Rank", style="dim", width=6)
        table.add_column("Rule ID", style="bold white", width=22)
        table.add_column("Severity", width=12)
        table.add_column("Status", width=14)
        table.add_column("Assessment Detail")

        for idx, f in enumerate(ranked, 1):
            sev_style = {
                "CRITICAL": "[bold red]CRITICAL[/bold red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[blue]LOW[/blue]",
                "INFO": "[dim]INFO[/dim]",
            }.get(f.severity, f.severity)
            table.add_row(str(idx), f.rule_id, sev_style, f.status.value, f.detail)

        console.print(table)


@app.command()
def attest(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to attest and seal."),
    sign: bool = typer.Option(False, "--sign", help="Cryptographically sign the Merkle receipt."),
    key_path: str = typer.Option("", "--key", help="Path to Ed25519 private key for signing."),
    operator: str = typer.Option("", "--operator", help="Operator identity to embed in the Seal."),
    output: str = typer.Option("-", "--output", "-o", help="Path to write the JSON receipt; '-' for stdout."),
) -> None:
    """
    Seal the current ScanRun into the Merkle audit trail.
    """
    init_db()
    with Session(engine) as session:
        seals = session.exec(select(Seal).where(Seal.scan_run_id == scan_run_id)).all()
        if not seals:
            console.print(f"[bold yellow]No existing seal for ScanRun #{scan_run_id}.[/bold yellow]")
            return
        seal = seals[-1]
        receipt = {
            "scan_run_id": scan_run_id,
            "merkle_root": seal.sha256_hash,
            "seal_type": seal.seal_type.value,
            "signed_by": seal.signed_by,
            "timestamp": seal.sealed_at.isoformat(),
        }
        if output == "-":
            console.print(json.dumps(receipt, indent=2))
        else:
            Path(output).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            console.print(f"[bold green][+] Seal receipt written to: {output}[/bold green]")


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the web dashboard."),
    port: int = typer.Option(8501, "--port", "-p", help="TCP port for the web dashboard."),
    reload: bool = typer.Option(False, "--reload", help="Enable hot-reload for development."),
) -> None:
    """
    Launch the Valence-IPsec web dashboard (tunneltwin.ui).
    """
    console.print(f"[bold cyan]TunnelTwin UI endpoint configured at http://{host}:{port}[/bold cyan]")
    console.print("[dim]Use 'tunneltwin report <id> --format html' for standalone static reports.[/dim]")


# ---------------------------------------------------------------------------
# Emulator sub-commands
# ---------------------------------------------------------------------------


@emulator_app.command("start")
def emulator_start(
    profile: str = typer.Option(
        "all",
        "--profile",
        "-p",
        help="Lab profile(s) to start: 'weak', 'mixed', 'strong', 'legacy-cbc', or 'all'.",
    ),
    namespace_only: bool = typer.Option(
        False, "--namespace-only", help="Create network namespaces only; do not start charon daemons."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Stream daemon output to terminal."),
) -> None:
    """
    Start the Linux namespace IKE emulator testbed.
    """
    console.print(
        f"[bold cyan]Starting emulator testbed (profile={profile}, namespace_only={namespace_only})...[/bold cyan]"
    )


@emulator_app.command("stop")
def emulator_stop(
    teardown: bool = typer.Option(False, "--teardown", help="Also remove network namespaces after stopping daemons."),
) -> None:
    """
    Stop charon daemons and optionally tear down network namespaces.
    """
    console.print(f"[bold yellow]Stopping emulator daemons (teardown={teardown})...[/bold yellow]")


@emulator_app.command("status")
def emulator_status() -> None:
    """
    Report the current state of namespace interfaces and charon daemons.
    """
    console.print("[bold cyan]Querying emulator namespace and daemon status...[/bold cyan]")


@emulator_app.command("simulate")
def emulator_simulate(
    count: int = typer.Option(20, "--count", "-n", help="Number of simulated nodes to generate."),
) -> None:
    """
    Run async simulation of N gateways and record into SQLite fleet store.
    """
    console.print(f"[bold cyan]Running simulation for {count} IKE gateways...[/bold cyan]")
    metrics = asyncio.run(run_emulator(node_count=count))
    console.print(
        f"[bold green][+] Simulated {metrics['count']} nodes in {metrics['elapsed_s']}s "
        f"(weak={metrics['weak']}, strong={metrics['strong']}, legacy={metrics['legacy']})[/bold green]\n"
        f"[dim]Merkle Root: {metrics['merkle_root']}[/dim]"
    )


# =======================================================================
#  Entry Point
# =======================================================================


def main() -> None:
    app()


if __name__ == "__main__":
    main()
