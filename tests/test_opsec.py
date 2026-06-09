import json
import subprocess
from pathlib import Path

from camaudit.report import render_markdown_report


def test_generated_raw_results_are_git_ignored():
    raw_path = Path("results/raw/test-opsec/hosts/192_168_1_38/nmap_port_scan.txt")
    report_path = Path("results/reports/test-opsec-report.md")
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text("sensitive raw output\n", encoding="utf-8")
    report_path.write_text("generated report\n", encoding="utf-8")

    try:
        raw_result = subprocess.run(
            ["git", "check-ignore", str(raw_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        report_result = subprocess.run(
            ["git", "check-ignore", str(report_path)],
            capture_output=True,
            text=True,
            check=False,
        )

        assert raw_result.returncode == 0
        assert report_result.returncode == 0
    finally:
        if raw_path.exists():
            raw_path.unlink()
        if report_path.exists():
            report_path.unlink()


def test_sanitized_examples_remain_tracked_and_usable():
    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--error-unmatch",
            "examples/sanitized_session.json",
            "examples/sanitized_report.md",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert tracked.returncode == 0

    session = json.loads(Path("examples/sanitized_session.json").read_text(encoding="utf-8"))
    report = render_markdown_report(session)
    assert "# CamAudit Lab Report" in report


def test_report_redaction_runs_before_writing():
    session = {
        "scope": "192.168.1.0/24 authorized LAN",
        "authorized": True,
        "hosts": [],
        "findings": [
            {
                "title": "Test finding",
                "severity": "Info",
                "evidence": "public 8.8.8.8 mac 5C:E9:31:E0:56:D9",
            }
        ],
    }

    report = render_markdown_report(session)

    assert "8.8.8.8" not in report
    assert "[REDACTED_PUBLIC_IP]" in report
    assert "5C:E9:31:XX:XX:XX" in report
