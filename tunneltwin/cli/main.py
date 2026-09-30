"""
tunneltwin.cli.main — Typer command-line interface.

Entry point registered in pyproject.toml:
    [project.scripts]
    tunneltwin = "tunneltwin.cli.main:app"

Commands
--------
scan        — Consent-gated active IKE probe + optional config parse.
analyze     — Run compliance rules (NIST SP 800-77r1 / ANSSI / RFC 9395) against stored facts.
fix         — Generate vendor-specific remediation diffs for open findings.
verify      — Re-assess a target after remediation to confirm fix effectiveness.
prioritize  — Rank findings by severity and remediation impact.
attest      — Sign and seal current ScanRun into the Merkle audit trail.
report      — Render assessment report (text / JSON / HTML / PDF).
ui          — Launch the web dashboard (tunneltwin.ui).
emulator    — Emulator sub-group (start / stop / status).
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="tunneltwin",
    help="Valence-IPsec: IPsec VPN Protocol Analyzer & Automated Security Assessment Framework.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

# ---------------------------------------------------------------------------
# Emulator sub-group
# ---------------------------------------------------------------------------

emulator_app = typer.Typer(
    name="emulator",
    help="Manage the Linux namespace IKE emulator testbed.",
    no_args_is_help=True,
)
app.add_typer(emulator_app, name="emulator")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP address or CIDR subnet to scan."),
    config: list[str] = typer.Option([], "--config", "-c", help="Path(s) to vendor config file(s) to parse."),
    ike_version: str = typer.Option("auto", "--ike-version", help="Force IKE version: 'v1', 'v2', or 'auto'."),
    timeout_ms: int = typer.Option(500, "--timeout-ms", help="Per-probe UDP timeout in milliseconds."),
    retries: int = typer.Option(2, "--retries", help="Maximum probe retries per transform."),
    rate_pps: float = typer.Option(10.0, "--rate-pps", help="Maximum probe rate in packets-per-second."),
    operator: str = typer.Option("", "--operator", help="Operator identifier logged to the ScanRun."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate consent and config but do not probe."),
) -> None:
    """
    Consent-gated IKE active probe and/or static config parse.

    The target MUST be registered in the TargetAllowlist with consent_verified=True
    before any active network probing is performed (double-barrier consent gating).
    Config files are always safe to parse without consent.
    """
    pass


@app.command()
def analyze(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to evaluate."),
    framework: list[str] = typer.Option(
        ["all"], "--framework", "-f", help="Compliance framework(s): 'nist', 'anssi', 'rfc9395', or 'all'."
    ),
    fail_on_cannot_assess: bool = typer.Option(
        False, "--fail-on-cannot-assess", help="Exit non-zero if any finding is CANNOT_ASSESS."
    ),
) -> None:
    """
    Run compliance rules against facts stored for a ScanRun.

    Evaluation strictly follows zero-false-pass semantics:
    any rule requiring an UNKNOWN fact emits FindingStatus.CANNOT_ASSESS.
    """
    pass


@app.command()
def fix(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID whose findings to remediate."),
    vendor: str = typer.Option(
        "auto", "--vendor", help="Vendor target: 'cisco_ios', 'strongswan', 'fortios', or 'auto'."
    ),
    severity: list[str] = typer.Option(
        ["CRITICAL", "HIGH"], "--severity", "-s", help="Minimum severity level(s) to remediate."
    ),
    output: str = typer.Option("-", "--output", "-o", help="Output path for diff file; '-' for stdout."),
    apply: bool = typer.Option(False, "--apply", help="Write diff directly to config file (requires --config)."),
    config_path: str = typer.Option("", "--config", help="Path to config file for in-place apply."),
) -> None:
    """
    Generate vendor-specific unified diffs / remediation patches for open findings.

    Diffs are stored as Remediation rows linked to their parent Finding.
    Use --apply to attempt direct config patching (requires explicit --config path).
    """
    pass


@app.command()
def verify(
    scan_run_id: int = typer.Argument(..., help="Original ScanRun ID to re-verify after remediation."),
    re_scan: bool = typer.Option(True, "--re-scan/--no-re-scan", help="Trigger a new active scan before verifying."),
    remediation_ids: list[int] = typer.Option([], "--remediation-id", help="Specific Remediation IDs to verify."),
) -> None:
    """
    Re-assess a target after remediation to confirm fix effectiveness.

    Optionally triggers a new ScanRun and compares new findings against
    the original set, marking Remediations as VERIFIED or REJECTED.
    """
    pass


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

    Produces a prioritized action list for the operator, optionally
    including CANNOT_ASSESS items flagged for manual investigation.
    """
    pass


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

    Computes SHA-256 hashes of all Finding, Remediation, and Capture rows,
    chains them to the previous Seal, and optionally signs the receipt
    with an Ed25519 private key for tamper-evident provenance.
    """
    pass


@app.command()
def report(
    scan_run_id: int = typer.Argument(..., help="ScanRun ID to report on."),
    output_format: str = typer.Option("text", "--format", "-f", help="Report format: 'text', 'json', 'html', 'pdf'."),
    output: str = typer.Option("-", "--output", "-o", help="Output file path; '-' for stdout."),
    include_remediations: bool = typer.Option(True, "--remediations/--no-remediations", help="Include diff patches."),
    include_seals: bool = typer.Option(True, "--seals/--no-seals", help="Include Merkle receipt chain."),
) -> None:
    """
    Render a comprehensive assessment report for a ScanRun.

    Output includes findings (with PASS / FAIL / CANNOT_ASSESS status),
    remediation diffs, provenance metadata, and Merkle audit receipts.
    """
    pass


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the web dashboard."),
    port: int = typer.Option(8501, "--port", "-p", help="TCP port for the web dashboard."),
    reload: bool = typer.Option(False, "--reload", help="Enable hot-reload for development."),
) -> None:
    """
    Launch the Valence-IPsec web dashboard (tunneltwin.ui).

    Starts the web interface serving real-time scan status, findings,
    Merkle audit trail visualization, and remediation management.
    """
    pass


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

    Provisions ns-left / ns-right network namespaces over a veth pair
    (10.0.1.1/30 <-> 10.0.1.2/30) and spawns isolated charon daemons
    for the requested profile matrix.

    Requires root / sudo on Linux or WSL2.
    """
    pass


@emulator_app.command("stop")
def emulator_stop(
    teardown: bool = typer.Option(False, "--teardown", help="Also remove network namespaces after stopping daemons."),
) -> None:
    """
    Stop charon daemons and optionally tear down network namespaces.
    """
    pass


@emulator_app.command("status")
def emulator_status() -> None:
    """
    Report the current state of namespace interfaces and charon daemons.
    """
    pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point registered via pyproject.toml [project.scripts]."""
    app()


if __name__ == "__main__":
    main()
