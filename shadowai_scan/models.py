"""Data models, NIST AI RMF / ISO 42001 / EU AI Act governance scoring, redaction, and baseline diffing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
STATUS_WEIGHT = {"PASS": 1.0, "WARN": 0.45, "FAIL": 0.0}
SEVERITY_WEIGHT = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.2, "LOW": 0.7, "INFO": 0.3}


@dataclass
class CheckResult:
    check_id: str
    nist_ref: str
    iso_ref: str
    eu_ai_act_ref: str
    domain: str
    title: str
    status: str  # PASS, WARN, FAIL, SKIP
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    summary: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    @property
    def framework_ref(self) -> str:
        return f"{self.nist_ref} | {self.iso_ref}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["framework_ref"] = self.framework_ref
        return data


@dataclass
class AssetRecord:
    asset_id: str
    category: str
    provider: str
    name: str
    location: str
    status: str  # APPROVED, UNAPPROVED, REVIEW
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_check: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    tool_version: str
    generated_at: str
    target_path: str
    repo_only: bool
    hostname: str
    platform_info: str
    redacted: bool
    allowlist_path: str | None
    approved_providers: list[str]
    checks: list[CheckResult]
    assets: list[AssetRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        scored = [c for c in self.checks if c.status in STATUS_WEIGHT]
        if not scored:
            return 100
        total_w = sum(SEVERITY_WEIGHT.get(c.severity, 1.0) for c in scored)
        earned = sum(
            SEVERITY_WEIGHT.get(c.severity, 1.0) * STATUS_WEIGHT[c.status]
            for c in scored
        )
        return int(round((earned / total_w) * 100)) if total_w > 0 else 100

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 95:
            return "A+"
        if s >= 90:
            return "A"
        if s >= 85:
            return "B+"
        if s >= 80:
            return "B"
        if s >= 75:
            return "C+"
        if s >= 70:
            return "C"
        if s >= 55:
            return "D"
        return "F"

    @property
    def counts(self) -> dict[str, int]:
        out = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out

    @property
    def asset_counts(self) -> dict[str, int]:
        out = {"TOTAL": len(self.assets), "APPROVED": 0, "UNAPPROVED": 0, "REVIEW": 0}
        for a in self.assets:
            out[a.status] = out.get(a.status, 0) + 1
        return out

    @property
    def domain_scores(self) -> list[dict[str, Any]]:
        buckets: dict[str, list[CheckResult]] = {}
        for c in self.checks:
            buckets.setdefault(c.domain, []).append(c)
        rows = []
        for domain, items in buckets.items():
            scored = [i for i in items if i.status in STATUS_WEIGHT]
            if scored:
                tw = sum(SEVERITY_WEIGHT.get(i.severity, 1.0) for i in scored)
                ew = sum(
                    SEVERITY_WEIGHT.get(i.severity, 1.0) * STATUS_WEIGHT[i.status]
                    for i in scored
                )
                pct = int(round((ew / tw) * 100)) if tw else 100
            else:
                pct = 100
            rows.append(
                {
                    "domain": domain,
                    "score": pct,
                    "passed": sum(1 for i in items if i.status == "PASS"),
                    "warn": sum(1 for i in items if i.status == "WARN"),
                    "failed": sum(1 for i in items if i.status == "FAIL"),
                    "skipped": sum(1 for i in items if i.status == "SKIP"),
                    "total": len(items),
                }
            )
        return rows

    def highest_failing_severity(self) -> str | None:
        failing = [c.severity for c in self.checks if c.status in ("FAIL", "WARN")]
        if not failing:
            return None
        return min(failing, key=lambda s: SEVERITY_ORDER.get(s, 99))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "ShadowAI-Scan",
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "target_path": self.target_path,
            "repo_only": self.repo_only,
            "hostname": self.hostname,
            "platform_info": self.platform_info,
            "redacted": self.redacted,
            "allowlist_path": self.allowlist_path,
            "approved_providers": self.approved_providers,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "asset_counts": self.asset_counts,
            "domain_scores": self.domain_scores,
            "metadata": self.metadata,
            "checks": [c.to_dict() for c in self.checks],
            "assets": [a.to_dict() for a in self.assets],
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_report(
    report: ScanReport,
    home_dir: str,
    username: str,
    synthetic_host: str = "eng-workstation-04",
) -> ScanReport:
    """Mask hostnames, usernames, home paths, and external IPs for safe external sharing."""
    ip_re = re.compile(r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0)\b)(?:\d{1,3}\.){3}\d{1,3}\b")

    def clean(text: str) -> str:
        if not text:
            return text
        out = text
        if home_dir:
            out = out.replace(home_dir, "/home/<redacted>")
        if username and len(username) >= 3:
            out = re.sub(re.escape(username), "<user>", out, flags=re.IGNORECASE)
        if report.hostname and len(report.hostname) >= 3:
            out = re.sub(re.escape(report.hostname), synthetic_host, out, flags=re.IGNORECASE)
        out = ip_re.sub("<redacted-ip>", out)
        return out

    cleaned_checks = [
        CheckResult(
            check_id=c.check_id,
            nist_ref=c.nist_ref,
            iso_ref=c.iso_ref,
            eu_ai_act_ref=c.eu_ai_act_ref,
            domain=c.domain,
            title=c.title,
            status=c.status,
            severity=c.severity,
            summary=clean(c.summary),
            evidence=[clean(e) for e in c.evidence],
            remediation=clean(c.remediation),
        )
        for c in report.checks
    ]
    cleaned_assets = [
        AssetRecord(
            asset_id=a.asset_id,
            category=a.category,
            provider=a.provider,
            name=clean(a.name),
            location=clean(a.location),
            status=a.status,
            risk_level=a.risk_level,
            source_check=a.source_check,
            details=clean(a.details),
        )
        for a in report.assets
    ]
    return ScanReport(
        tool_version=report.tool_version,
        generated_at=report.generated_at,
        target_path=clean(report.target_path),
        repo_only=report.repo_only,
        hostname=synthetic_host,
        platform_info=clean(report.platform_info),
        redacted=True,
        allowlist_path=clean(report.allowlist_path) if report.allowlist_path else None,
        approved_providers=list(report.approved_providers),
        checks=cleaned_checks,
        assets=cleaned_assets,
        metadata={
            k: clean(v) if isinstance(v, str) else v
            for k, v in report.metadata.items()
        },
    )


def compute_diff(baseline: dict[str, Any], current: ScanReport) -> dict[str, Any]:
    """Compare a previous JSON scan baseline against the current report."""
    prev_score = int(baseline.get("score", 0))
    prev_map = {c["check_id"]: c for c in baseline.get("checks", [])}
    rank = {"FAIL": 0, "WARN": 1, "SKIP": 2, "PASS": 3}

    improved: list[dict[str, str]] = []
    regressed: list[dict[str, str]] = []
    unchanged_risks: list[dict[str, str]] = []

    for c in current.checks:
        old = prev_map.get(c.check_id)
        if not old:
            continue
        old_st = old.get("status", "SKIP")
        if rank.get(c.status, 2) > rank.get(old_st, 2):
            improved.append(
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "from": old_st,
                    "to": c.status,
                }
            )
        elif rank.get(c.status, 2) < rank.get(old_st, 2):
            regressed.append(
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "from": old_st,
                    "to": c.status,
                }
            )
        elif c.status in ("FAIL", "WARN"):
            unchanged_risks.append(
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status,
                }
            )

    prev_unapproved = {
        (a.get("category", ""), a.get("provider", ""), a.get("name", ""))
        for a in baseline.get("assets", [])
        if a.get("status") == "UNAPPROVED"
    }
    curr_unapproved = {
        (a.category, a.provider, a.name)
        for a in current.assets
        if a.status == "UNAPPROVED"
    }
    new_shadow_assets = sorted(
        f"{cat}: {prov} ({name})" for cat, prov, name in (curr_unapproved - prev_unapproved)
    )
    resolved_shadow_assets = sorted(
        f"{cat}: {prov} ({name})" for cat, prov, name in (prev_unapproved - curr_unapproved)
    )

    return {
        "baseline_generated_at": baseline.get("generated_at", "unknown"),
        "baseline_score": prev_score,
        "current_score": current.score,
        "score_delta": current.score - prev_score,
        "improved": improved,
        "regressed": regressed,
        "unchanged_risks": unchanged_risks,
        "new_shadow_assets": new_shadow_assets,
        "resolved_shadow_assets": resolved_shadow_assets,
    }
