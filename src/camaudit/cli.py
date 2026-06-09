from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from camaudit.auth_guard import AuthorizationError, require_authorized_private_target
from camaudit.discovery import DiscoveryError, discover_hosts
from camaudit.envcheck import check_environment
from camaudit.redact import redact_text
from camaudit.report import ReportProfile, write_markdown_report
from camaudit.scanner import ScannerError, scan_host_ports

app = typer.Typer(help="Defensive local-only IoT camera audit toolkit.")
console = Console()
INIT_PATH_ARGUMENT = typer.Argument(Path("camaudit_project"))
AUTH_OPTION = typer.Option(False, "--i-am-authorized", help="Confirm authorized testing.")
REPORT_INPUT_ARGUMENT = typer.Argument(Path("examples/sanitized_session.json"))
REPORT_OUTPUT_ARGUMENT = typer.Argument(Path("results/reports/camaudit_report.md"))
REPORT_PROFILE_OPTION = typer.Option(
    "internal",
    "--profile",
    help="Report profile: internal or public.",
)
DEMO_PUBLIC_REPORT_PATH = Path("results/reports/camaudit_demo_report_public.md")
DEMO_INTERNAL_REPORT_PATH = Path("results/reports/camaudit_demo_report_internal.md")


@app.command()
def init(path: Path = INIT_PATH_ARGUMENT) -> None:
    """Create a local audit workspace."""
    for subdir in ["nmap", "wireshark", "cve_research", "reports", "raw"]:
        (path / subdir).mkdir(parents=True, exist_ok=True)
    (path / "notes.md").write_text("# CamAudit notes\n\nAuthorization:\nScope:\n", encoding="utf-8")
    console.print(f"[green]Created workspace:[/] {path}")


@app.command("check-env")
def check_env() -> None:
    """Check local tool availability without scanning."""
    result = check_environment()
    console.print(f"OS: {result.os_name} {result.os_release}")
    console.print(f"Python: {result.python_version}")

    table = Table("Tool", "Status", "Version / note")
    for tool in result.tools:
        status = "available" if tool.available else "missing"
        note = tool.version or tool.error or ""
        table.add_row(tool.name, status, note)
    console.print(table)


@app.command()
def discover(
    target: str,
    i_am_authorized: bool = AUTH_OPTION,
) -> None:
    """Safely discover hosts on an authorized private LAN."""
    try:
        hosts = discover_hosts(target, i_am_authorized=i_am_authorized)
    except (AuthorizationError, DiscoveryError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table("IP", "Hostname", "MAC OUI", "Vendor", "Latency ms")
    for host in hosts:
        table.add_row(
            host.ip,
            host.hostname or "",
            host.mac_oui or "",
            host.vendor or "",
            f"{host.latency_ms:.1f}" if host.latency_ms is not None else "",
        )
    console.print(table)
    console.print(f"[green]Discovered hosts:[/] {len(hosts)}")


@app.command("scan-host")
def scan_host(
    target: str,
    i_am_authorized: bool = AUTH_OPTION,
) -> None:
    """Safely scan one authorized private host."""
    try:
        result = scan_host_ports(target, i_am_authorized=i_am_authorized)
    except (AuthorizationError, ScannerError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table("Port", "Proto", "Service")
    for port in result.open_ports:
        table.add_row(str(port.port), port.proto, port.service or "")
    console.print(table)
    console.print(f"[green]Open ports:[/] {len(result.open_ports)}")


@app.command()
def audit(
    target: str,
    i_am_authorized: bool = AUTH_OPTION,
) -> None:
    """Run full safe audit. Placeholder."""
    try:
        require_authorized_private_target(target, i_am_authorized=i_am_authorized)
    except AuthorizationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[yellow]Audit placeholder approved for target:[/] {target}")


@app.command()
def redact(input_file: Path, output_file: Path, strict: bool = False) -> None:
    """Redact sensitive material from a text file."""
    redacted = redact_text(input_file.read_text(encoding="utf-8"), strict=strict)
    output_file.write_text(redacted, encoding="utf-8")
    console.print(f"[green]Wrote redacted file:[/] {output_file}")


@app.command()
def report(
    input_file: Path = REPORT_INPUT_ARGUMENT,
    output_file: Path = REPORT_OUTPUT_ARGUMENT,
    profile: ReportProfile = REPORT_PROFILE_OPTION,
) -> None:
    """Generate a redacted Markdown report."""
    data = json.loads(input_file.read_text(encoding="utf-8"))
    output_path = write_markdown_report(data, output_file, profile=profile)
    console.print(f"[green]Wrote report:[/] {output_path}")


@app.command()
def demo(
    write_internal_report: bool = typer.Option(
        False,
        "--write-internal-report",
        help="Also write an internal-profile demo report.",
    ),
) -> None:
    """Run demo mode without scanning."""
    demo_file = Path("examples/sanitized_session.json")
    if not demo_file.exists():
        console.print("[red]Missing examples/sanitized_session.json[/]")
        raise typer.Exit(1)
    data = json.loads(demo_file.read_text(encoding="utf-8"))
    console.print(Panel.fit("CamAudit Demo Mode - no network scan performed"))
    console.print_json(data=data)

    hosts = data.get("hosts", [])
    dry_run_table = Table("Step", "What would happen", "Demo data")
    dry_run_table.add_row(
        "Discovery",
        "Would run authorized Nmap ping discovery",
        f"{len(hosts)} sanitized host(s) loaded",
    )
    dry_run_table.add_row(
        "Port scan",
        "Would run safe Nmap camera/IoT port scan",
        "Using stored open_ports values",
    )
    dry_run_table.add_row(
        "Fingerprint",
        "Would run allowed header, TLS, RTSP OPTIONS, and UDP checks",
        "Using sanitized notes/findings only",
    )
    console.print(dry_run_table)

    host_table = Table("IP", "Vendor", "Type", "Open ports", "Notes")
    for host in hosts:
        open_ports = ", ".join(f"TCP/{port}" for port in host.get("open_ports", []))
        notes = "; ".join(host.get("notes", []))
        host_table.add_row(
            host.get("ip", ""),
            host.get("vendor", "Unknown"),
            host.get("candidate_type", "unknown"),
            open_ports,
            notes,
        )
    console.print(host_table)

    finding_table = Table("Finding", "Severity", "Evidence")
    for finding in data.get("findings", []):
        finding_table.add_row(
            finding.get("title", ""),
            finding.get("severity", ""),
            finding.get("evidence", ""),
        )
    console.print(finding_table)

    public_report_path = write_markdown_report(data, DEMO_PUBLIC_REPORT_PATH, profile="public")
    console.print(f"[green]Wrote public demo report:[/] {public_report_path}")
    if write_internal_report:
        internal_report_path = write_markdown_report(
            data,
            DEMO_INTERNAL_REPORT_PATH,
            profile="internal",
        )
        console.print(f"[green]Wrote internal demo report:[/] {internal_report_path}")


if __name__ == "__main__":
    app()
