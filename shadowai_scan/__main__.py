"""CLI entry point for ShadowAI-Scan Core (MIT)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .report_export import export_reports, render_terminal
from .scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadowai-scan",
        description="Zero-dependency workstation and repository Shadow AI discovery and governance auditor (NIST AI RMF, ISO 42001, EU AI Act).",
    )
    p.add_argument("--version", action="version", version=f"ShadowAI-Scan {__version__}")

    sub = p.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Audit a repository and/or local workstation for Shadow AI usage and governance gaps.")
    for target in (p, scan):
        target.add_argument("--path", default=".", help="Target repository or workspace directory (default: current directory)")
        target.add_argument("--repo-only", action="store_true", help="Scan only --path (skip workstation ports, IDE/CLI configs, and browser manifests; ideal for CI)")
        target.add_argument("--allowlist", default=None, help="Path to JSON allowlist file (e.g. approved-ai.json) listing approved AI providers and tools")
        target.add_argument("--out-dir", default=".", help="Directory for exported report files")
        target.add_argument(
            "--formats",
            "--format",
            dest="formats",
            default="terminal",
            help="Comma-separated output formats: terminal,md,json,all",
        )
        target.add_argument("--prefix", default="shadowai-report", help="Output filename prefix for report files")
        target.add_argument("--fail-under", type=int, default=None, help="Exit with code 2 if governance score falls below this threshold (0-100)")
        target.add_argument("--redact", action="store_true", help="Mask hostnames, usernames, home paths, and external IPs for safe sharing")
        target.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = run_scan(
            target_path=args.path,
            repo_only=args.repo_only,
            allowlist_path=args.allowlist,
            redact=args.redact,
        )
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ShadowAI-Scan] Error: {exc}", file=sys.stderr)
        return 1

    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}
    pro_only = formats & {"pdf", "docx", "html", "csv"}
    if pro_only:
        print(
            f"[ShadowAI-Scan] Note: {', '.join(sorted(pro_only)).upper()} executive exports are part of ShadowAI-Scan Pro: "
            "https://rasetsukyo.gumroad.com/l/shadowaiscan",
            file=sys.stderr,
        )

    if "terminal" in formats or not (formats & {"json", "md", "all"}):
        use_color = sys.stdout.isatty() and not args.no_color
        print(render_terminal(report, color=use_color))

    file_formats = formats & {"json", "md", "all"}
    if file_formats:
        written = export_reports(
            report,
            out_dir=Path(args.out_dir),
            formats=file_formats,
            prefix=args.prefix,
        )
        for kind, path in written.items():
            print(f"[ShadowAI-Scan] Wrote {kind.upper()}: {path}")

    if args.fail_under is not None and report.score < args.fail_under:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
