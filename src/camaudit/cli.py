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

app = typer.Typer(help="Defensive local-only IoT camera audit toolkit.")
console = Console()
INIT_PATH_ARGUMENT = typer.Argument(Path("camaudit_project"))
AUTH_OPTION = typer.Option(False, "--i-am-authorized", help="Confirm authorized testing.")


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
    """Safely scan one authorized private host. Placeholder."""
    try:
        require_authorized_private_target(target, i_am_authorized=i_am_authorized)
    except AuthorizationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[yellow]Scan placeholder approved for target:[/] {target}")


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
def report(input_file: Path = Path("examples/sanitized_session.json")) -> None:
    """Placeholder report generator."""
    data = json.loads(input_file.read_text(encoding="utf-8"))
    console.print(Panel.fit(f"Report placeholder loaded session: {data.get('scope', 'unknown')}"))


@app.command()
def demo() -> None:
    """Run demo mode without scanning."""
    demo_file = Path("examples/sanitized_session.json")
    if not demo_file.exists():
        console.print("[red]Missing examples/sanitized_session.json[/]")
        raise typer.Exit(1)
    data = json.loads(demo_file.read_text(encoding="utf-8"))
    console.print(Panel.fit("CamAudit Demo Mode — no network scan performed"))
    console.print_json(data=data)


if __name__ == "__main__":
    app()
