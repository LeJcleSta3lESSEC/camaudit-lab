from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from camaudit.auth_guard import AuthorizationError, require_authorized_private_target
from camaudit.redact import redact_text

app = typer.Typer(help="Defensive local-only IoT camera audit toolkit.")
console = Console()


@app.command()
def init(path: Path = typer.Argument(Path("camaudit_project"))):
    """Create a local audit workspace."""
    for subdir in ["nmap", "wireshark", "cve_research", "reports", "raw"]:
        (path / subdir).mkdir(parents=True, exist_ok=True)
    (path / "notes.md").write_text("# CamAudit notes\n\nAuthorization:\nScope:\n", encoding="utf-8")
    console.print(f"[green]Created workspace:[/] {path}")


@app.command("check-env")
def check_env():
    """Placeholder environment checker."""
    console.print(Panel("Environment checker placeholder. Next: implement envcheck.py."))


@app.command()
def discover(
    target: str,
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="Confirm authorized testing."),
):
    """Safely discover hosts on an authorized private LAN. Placeholder."""
    try:
        require_authorized_private_target(target, i_am_authorized=i_am_authorized)
    except AuthorizationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[yellow]Discovery placeholder approved for target:[/] {target}")
    console.print("Next: implement nmap -sn wrapper after parser tests exist.")


@app.command("scan-host")
def scan_host(
    target: str,
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="Confirm authorized testing."),
):
    """Safely scan one authorized private host. Placeholder."""
    try:
        require_authorized_private_target(target, i_am_authorized=i_am_authorized)
    except AuthorizationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[yellow]Scan placeholder approved for target:[/] {target}")


@app.command()
def audit(
    target: str,
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="Confirm authorized testing."),
):
    """Run full safe audit. Placeholder."""
    try:
        require_authorized_private_target(target, i_am_authorized=i_am_authorized)
    except AuthorizationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[yellow]Audit placeholder approved for target:[/] {target}")


@app.command()
def redact(input_file: Path, output_file: Path, strict: bool = False):
    """Redact sensitive material from a text file."""
    redacted = redact_text(input_file.read_text(encoding="utf-8"), strict=strict)
    output_file.write_text(redacted, encoding="utf-8")
    console.print(f"[green]Wrote redacted file:[/] {output_file}")


@app.command()
def report(input_file: Path = Path("examples/sanitized_session.json")):
    """Placeholder report generator."""
    data = json.loads(input_file.read_text(encoding="utf-8"))
    console.print(Panel.fit(f"Report placeholder loaded session: {data.get('scope', 'unknown')}"))


@app.command()
def demo():
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
