from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field, model_validator

from camaudit.redact import redact_text

DEFAULT_TEMPLATE_DIR = Path("templates")
DEFAULT_TEMPLATE_NAME = "report.md.j2"
ReportProfile = Literal["internal", "public"]
ARTIFACT_PATH_PLACEHOLDER = "REDACTED_ARTIFACT_PATH"
LAB_GATEWAY_PLACEHOLDER = "LAB_GATEWAY"
LAB_SUBNET_PLACEHOLDER = "LAB_SUBNET/24"
MAC_OUI_PLACEHOLDER = "MAC_OUI_REDACTED"
MAC_OUI_RE = re.compile(r"\b[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\b")
PRIVATE_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ARTIFACT_PATH_RE = re.compile(r"results/raw/[^\s|`]+")


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

    @model_validator(mode="after")
    def populate_derived_sections(self) -> ReportData:
        if not self.camera_candidates:
            self.camera_candidates = [
                {
                    "ip": host.get("ip", ""),
                    "candidate_type": host.get("candidate_type", "camera_candidate"),
                    "candidate_score": host.get("candidate_score", ""),
                    "reasons": host.get("reasons", host.get("notes", [])),
                }
                for host in self.hosts
                if host.get("candidate_type") == "camera_candidate"
            ]

        if not self.open_services:
            self.open_services = [
                {
                    "ip": host.get("ip", ""),
                    "port": port,
                    "proto": "tcp",
                    "service": "",
                }
                for host in self.hosts
                for port in host.get("open_ports", [])
            ]

        if self.findings:
            if not self.protocol_findings:
                self.protocol_findings = [
                    finding
                    for finding in self.findings
                    if _matches_any(finding, ("rtsp", "onvif", "upnp", "mdns", "cseq"))
                ]
            if not self.tls_findings:
                self.tls_findings = [
                    finding
                    for finding in self.findings
                    if _matches_any(finding, ("tls", "certificate", "self-signed", "rsa", "1024"))
                ]
        return self


def _matches_any(item: dict[str, Any], terms: tuple[str, ...]) -> bool:
    text = " ".join(str(value) for value in item.values()).lower()
    return any(term in text for term in terms)


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.IPv4Address(value).is_private
    except ValueError:
        return False


def _ordered_host_ips(data: ReportData) -> list[str]:
    return [
        host_ip
        for host in data.hosts
        if (host_ip := host.get("ip")) and isinstance(host_ip, str) and _is_private_ip(host_ip)
    ]


def _all_private_ips(data: ReportData) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
            return
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if isinstance(value, str):
            for match in PRIVATE_IP_RE.findall(value):
                if _is_private_ip(match) and match not in seen:
                    seen.add(match)
                    ordered.append(match)

    visit(data.model_dump())
    return ordered


def _replace_private_ips(text: str, replacements: dict[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        ip = match.group(0)
        return replacements.get(ip, ip)

    return PRIVATE_IP_RE.sub(repl, text)


def _public_ip_alias_map(data: ReportData) -> dict[str, str]:
    replacements: dict[str, str] = {}
    network_gateway = data.network_context.get("default_gateway")
    subnet_cidr = data.network_context.get("subnet_cidr")
    subnet_network_address: str | None = None
    if isinstance(network_gateway, str) and _is_private_ip(network_gateway):
        replacements[network_gateway] = LAB_GATEWAY_PLACEHOLDER
    if isinstance(subnet_cidr, str):
        try:
            subnet_network_address = str(
                ipaddress.ip_network(subnet_cidr, strict=False).network_address
            )
        except ValueError:
            subnet_network_address = None

    index = 1
    for host_ip in _ordered_host_ips(data):
        replacements.setdefault(host_ip, f"HOST-{index:03d}")
        index += 1
    for ip in _all_private_ips(data):
        if ip in (network_gateway, subnet_network_address):
            continue
        if ip not in replacements:
            replacements[ip] = f"HOST-{index:03d}"
            index += 1
    return replacements


def _public_transform(
    value: Any,
    replacements: dict[str, str],
    *,
    subnet_cidr: str | None,
    redact_vendors: bool,
) -> Any:
    if isinstance(value, list):
        return [
            _public_transform(
                item,
                replacements,
                subnet_cidr=subnet_cidr,
                redact_vendors=redact_vendors,
            )
            for item in value
        ]
    if isinstance(value, dict):
        transformed: dict[str, Any] = {}
        for key, item in value.items():
            if key == "subnet_cidr":
                transformed[key] = LAB_SUBNET_PLACEHOLDER
                continue
            if key == "default_gateway":
                transformed[key] = LAB_GATEWAY_PLACEHOLDER
                continue
            if key == "mac_oui":
                transformed[key] = MAC_OUI_PLACEHOLDER if item else item
                continue
            if redact_vendors and key == "vendor" and item:
                transformed[key] = "VENDOR_REDACTED"
                continue
            transformed[key] = _public_transform(
                item,
                replacements,
                subnet_cidr=subnet_cidr,
                redact_vendors=redact_vendors,
            )
        return transformed
    if isinstance(value, str):
        text = ARTIFACT_PATH_RE.sub(ARTIFACT_PATH_PLACEHOLDER, value)
        if subnet_cidr:
            text = text.replace(subnet_cidr, LAB_SUBNET_PLACEHOLDER)
        text = MAC_OUI_RE.sub(MAC_OUI_PLACEHOLDER, text)
        return _replace_private_ips(text, replacements)
    return value


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
    profile: ReportProfile = "internal",
    redact_vendors: bool = False,
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
    template_name: str = DEFAULT_TEMPLATE_NAME,
    strict_redaction: bool = False,
) -> str:
    data = ReportData.model_validate(session)
    if profile == "public":
        replacements = _public_ip_alias_map(data)
        transformed_session = _public_transform(
            data.model_dump(),
            replacements,
            subnet_cidr=(
                str(data.network_context.get("subnet_cidr"))
                if data.network_context.get("subnet_cidr")
                else None
            ),
            redact_vendors=redact_vendors,
        )
        data = ReportData.model_validate(transformed_session)
    rendered = _template_environment(template_dir).get_template(template_name).render(
        report=data,
        executive_summary=_default_summary(data),
    )
    return redact_text(rendered, strict=strict_redaction)


def write_markdown_report(
    session: dict[str, Any],
    output_path: Path,
    *,
    profile: ReportProfile = "internal",
    redact_vendors: bool = False,
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
    template_name: str = DEFAULT_TEMPLATE_NAME,
    strict_redaction: bool = False,
) -> Path:
    markdown = render_markdown_report(
        session,
        profile=profile,
        redact_vendors=redact_vendors,
        template_dir=template_dir,
        template_name=template_name,
        strict_redaction=strict_redaction,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return output_path
