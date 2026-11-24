"""Terminal, Markdown, and JSON export helpers for ShadowAI-Scan Core (MIT)."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanReport


ANSI = {
    "PASS": "\033[1;32mPASS\033[0m",
    "WARN": "\033[1;33mWARN\033[0m",
    "FAIL": "\033[1;31mFAIL\033[0m",
    "SKIP": "\033[1;36mSKIP\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


def render_terminal(report: ScanReport, color: bool = True) -> str:
    b = ANSI["BOLD"] if color else ""
    d = ANSI["DIM"] if color else ""
    r = ANSI["RESET"] if color else ""
    ac = report.asset_counts
    lines = [
        f"{b}ShadowAI-Scan v{report.tool_version}{r} | Shadow AI Discovery & Governance Audit (NIST AI RMF / ISO 42001)",
        f"{d}Host: {report.hostname} | Target: {report.target_path} | UTC: {report.generated_at}{r}",
        f"{b}Governance Score: {report.score}/100 (Grade {report.grade}){r} | "
        f"PASS: {report.counts['PASS']}  WARN: {report.counts['WARN']}  FAIL: {report.counts['FAIL']}  SKIP: {report.counts['SKIP']}",
        f"{d}Shadow AI Assets: {ac['TOTAL']} total ({ac['UNAPPROVED']} unapproved, {ac['APPROVED']} approved){r}",
        "-" * 78,
    ]
    for c in report.checks:
        st = ANSI[c.status] if color and c.status in ANSI else c.status
        lines.append(f"[{st}] {c.check_id} ({c.nist_ref}, {c.severity:<8}) {c.title}")
        lines.append(f"       {c.summary}")
        for ev in c.evidence[:3]:
            lines.append(f"       {d}- {ev}{r}")
        if c.remediation and c.status != "PASS":
            lines.append(f"       Action: {c.remediation}")
    lines.append("-" * 78)
    lines.append("Need executive PDF/DOCX reports, CSV Asset Inventory, --diff tracking & AI Policy Pack?")
    lines.append("ShadowAI-Scan Pro ($39 one-time): https://rasetsukyo.gumroad.com/l/shadowaiscan")
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    ac = report.asset_counts
    lines = [
        "# ShadowAI-Scan Governance Audit Report",
        "",
        f"- **Governance Score:** {report.score}/100 (Grade {report.grade})",
        f"- **Host:** `{report.hostname}`",
        f"- **Target:** `{report.target_path}`",
        f"- **Generated (UTC):** `{report.generated_at}`",
        f"- **Controls:** {report.counts['PASS']} PASS, {report.counts['WARN']} WARN, {report.counts['FAIL']} FAIL, {report.counts['SKIP']} SKIP",
        f"- **Shadow AI Assets:** {ac['TOTAL']} total ({ac['UNAPPROVED']} unapproved, {ac['APPROVED']} approved)",
        "",
        "## Shadow AI Asset Inventory",
        "",
        "| Asset ID | Category | Provider | Name | Location | Status | Risk | Check |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if report.assets:
        for a in report.assets:
            lines.append(
                f"| {a.asset_id} | {a.category} | {a.provider} | `{a.name}` | `{a.location}` | **{a.status}** | {a.risk_level} | {a.source_check} |"
            )
    else:
        lines.append("| None | N/A | N/A | Zero Shadow AI assets discovered | N/A | PASS | INFO | N/A |")
    lines.extend(
        [
            "",
            "## Control Findings",
            "",
            "| ID | NIST AI RMF | ISO 42001 | Severity | Status | Control | Summary |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for c in report.checks:
        lines.append(
            f"| {c.check_id} | {c.nist_ref} | {c.iso_ref} | {c.severity} | **{c.status}** | {c.title} | {c.summary} |"
        )
    lines.append("")
    for c in report.checks:
        if c.status == "PASS" and not c.evidence:
            continue
        lines.append(f"### {c.check_id}: {c.title} ({c.status})")
        lines.append(f"Standards: `{c.nist_ref}`, `{c.iso_ref}`, `{c.eu_ai_act_ref}`")
        lines.append("")
        lines.append(c.summary)
        for ev in c.evidence[:8]:
            lines.append(f"- `{ev}`")
        if c.remediation and c.status != "PASS":
            lines.append(f"- **Remediation:** {c.remediation}")
        lines.append("")
    return "\n".join(lines)


def export_reports(
    report: ScanReport,
    out_dir: Path,
    formats: set[str],
    prefix: str = "shadowai-report",
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if "json" in formats or "all" in formats:
        p = out_dir / f"{prefix}.json"
        p.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        written["json"] = p

    if "md" in formats or "all" in formats:
        p = out_dir / f"{prefix}.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        written["md"] = p

    return written
