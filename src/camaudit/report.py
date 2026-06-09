from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from camaudit.redact import redact_text

DEFAULT_TEMPLATE_DIR = Path("templates")
DEFAULT_TEMPLATE_NAME = "report.md.j2"


class ReportData(BaseModel):
    scope: str
    authorized: bool
    executive_summary: str = "No executive summary provided."
    network_context: dict[str, Any] = Field(default_factory=dict)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    camera_candidates: list[dict[str, Any]] = Field(default_factory=list)
    open_services: list[dict[str, Any]] = Field(default_factory=list)
    fingerprinting_results: list[dict[str, Any]] = Field(default_factory=list)
    protocol_findings: list[dict[str, Any]] = Field(default_factory=list)
    tls_findings: list[dict[str, Any]] = Field(default_factory=list)
    cve_mapping: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    remediation_checklist: list[str] = Field(default_factory=list)
    evidence_appendix: list[dict[str, Any]] = Field(default_factory=list)
    redaction_log: list[str] = Field(default_factory=list)


def _default_summary(data: ReportData) -> str:
    if data.executive_summary != "No executive summary provided.":
        return data.executive_summary
    return (
        f"CamAudit reviewed {len(data.hosts)} discovered host(s), "
        f"{len(data.camera_candidates)} camera candidate(s), and "
        f"{len(data.findings)} finding(s) within the authorized scope."
    )


def _template_environment(template_dir: Path = DEFAULT_TEMPLATE_DIR) -> Environment:
    return Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(disabled_extensions=("j2", "md")),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_markdown_report(
    session: dict[str, Any],
    *,
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
    template_name: str = DEFAULT_TEMPLATE_NAME,
    strict_redaction: bool = False,
) -> str:
    data = ReportData.model_validate(session)
    rendered = _template_environment(template_dir).get_template(template_name).render(
        report=data,
        executive_summary=_default_summary(data),
    )
    return redact_text(rendered, strict=strict_redaction)


def write_markdown_report(
    session: dict[str, Any],
    output_path: Path,
    *,
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
    template_name: str = DEFAULT_TEMPLATE_NAME,
    strict_redaction: bool = False,
) -> Path:
    markdown = render_markdown_report(
        session,
        template_dir=template_dir,
        template_name=template_name,
        strict_redaction=strict_redaction,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return output_path
