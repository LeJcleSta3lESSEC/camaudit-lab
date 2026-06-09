from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

RAW_RESULTS_ROOT = Path("results/raw")
REPORTS_ROOT = Path("results/reports")


def create_run_id() -> str:
    timestamp = datetime.now(UTC)
    return timestamp.strftime("%Y%m%dT%H%M%S_%fZ")


def host_slug(target: str) -> str:
    return target.replace(".", "_").replace("/", "_")


def run_raw_dir(run_id: str) -> Path:
    return RAW_RESULTS_ROOT / run_id


def discovery_output_path(run_id: str) -> Path:
    return run_raw_dir(run_id) / "discovery" / "nmap_discovery.txt"


def host_raw_dir(run_id: str, target: str) -> Path:
    return run_raw_dir(run_id) / "hosts" / host_slug(target)


def port_scan_output_path(run_id: str, target: str) -> Path:
    return host_raw_dir(run_id, target) / "nmap_port_scan.txt"


def fingerprint_output_path(run_id: str, target: str, name: str) -> Path:
    return host_raw_dir(run_id, target) / name
