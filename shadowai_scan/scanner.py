"""Zero-dependency, read-only Shadow AI discovery and governance scanner (SA-001 through SA-012)."""

from __future__ import annotations

from dataclasses import dataclass, field
import getpass
import json
import os
from pathlib import Path
import platform
import re
import socket
from typing import Any, Callable

from . import __version__
from .models import AssetRecord, CheckResult, ScanReport, redact_report, utc_now_iso


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "target",
    ".tox",
    ".eggs",
}

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".zsh",
    ".env",
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".xml",
    ".tf",
    ".tfvars",
}

CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
}

# Known AI provider key prefixes and env var names (SA-001)
KEY_PREFIX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai", re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{20,}|sk-(?:live|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})\b")),
    ("anthropic", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b")),
    ("google-gemini", re.compile(r"\b(AIza[0-9A-Za-z_\-]{30,})\b")),
    ("groq", re.compile(r"\b(gsk_[A-Za-z0-9]{20,})\b")),
    ("huggingface", re.compile(r"\b(hf_[A-Za-z0-9]{20,})\b")),
    ("perplexity", re.compile(r"\b(pplx-[A-Za-z0-9]{20,})\b")),
    ("xai", re.compile(r"\b(xai-[A-Za-z0-9]{20,})\b")),
    ("openrouter", re.compile(r"\b(sk-or-v1-[A-Za-z0-9]{20,})\b")),
    ("replicate", re.compile(r"\b(r8_[A-Za-z0-9]{20,})\b")),
]

ENV_VAR_PROVIDERS: dict[str, str] = {
    "OPENAI_API_KEY": "openai",
    "ANTHROPIC_API_KEY": "anthropic",
    "CLAUDE_API_KEY": "anthropic",
    "GEMINI_API_KEY": "google-gemini",
    "GOOGLE_AI_API_KEY": "google-gemini",
    "GROQ_API_KEY": "groq",
    "MISTRAL_API_KEY": "mistral",
    "COHERE_API_KEY": "cohere",
    "CO_API_KEY": "cohere",
    "HF_TOKEN": "huggingface",
    "HUGGINGFACE_API_KEY": "huggingface",
    "HUGGINGFACE_HUB_TOKEN": "huggingface",
    "DEEPSEEK_API_KEY": "deepseek",
    "PERPLEXITY_API_KEY": "perplexity",
    "XAI_API_KEY": "xai",
    "OPENROUTER_API_KEY": "openrouter",
    "TOGETHER_API_KEY": "together",
    "REPLICATE_API_TOKEN": "replicate",
}

ENV_ASSIGN_RE = re.compile(
    r"(?:export\s+)?(" + "|".join(sorted(ENV_VAR_PROVIDERS.keys())) + r")\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{10,})['\"]?"
)

# Local LLM inference server ports (SA-002)
LOCAL_LLM_PORTS: dict[int, tuple[str, str]] = {
    11434: ("ollama", "Ollama Inference Server"),
    1234: ("lmstudio", "LM Studio Local Server"),
    8000: ("vllm", "vLLM / Local AI API Server"),
    8080: ("llamacpp", "llama.cpp HTTP Server"),
    7860: ("textgen-webui", "TextGen WebUI / Gradio AI"),
    8188: ("comfyui", "ComfyUI Diffusion Server"),
    3000: ("openwebui", "OpenWebUI Local AI Portal"),
}

# AI SDK dependency catalog (SA-004)
AI_SDK_CATALOG: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "@anthropic-ai/sdk": "anthropic",
    "google-genai": "google-gemini",
    "google-generativeai": "google-gemini",
    "@google/generative-ai": "google-gemini",
    "@google/genai": "google-gemini",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-openai": "openai",
    "langchain-anthropic": "anthropic",
    "langchain-community": "langchain",
    "@langchain/core": "langchain",
    "@langchain/openai": "openai",
    "litellm": "litellm",
    "crewai": "crewai",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "autogen-agentchat": "autogen",
    "ollama": "ollama",
    "transformers": "huggingface",
    "huggingface-hub": "huggingface",
    "vllm": "vllm",
    "groq": "groq",
    "mistralai": "mistral",
    "cohere": "cohere",
    "deepseek": "deepseek",
    "together": "together",
    "replicate": "replicate",
    "async-openai": "openai",
    "go-openai": "openai",
    "github.com/sashabaranov/go-openai": "openai",
    "github.com/anthropics/anthropic-sdk-go": "anthropic",
    "ai": "vercel-ai",
    "@ai-sdk/openai": "openai",
    "@ai-sdk/anthropic": "anthropic",
}

# Hardcoded LLM API endpoints (SA-005)
LLM_ENDPOINTS: list[tuple[str, str]] = [
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("api.deepseek.com", "deepseek"),
    ("openrouter.ai", "openrouter"),
    ("api.groq.com", "groq"),
    ("generativelanguage.googleapis.com", "google-gemini"),
    ("api.mistral.ai", "mistral"),
    ("api.cohere.ai", "cohere"),
    ("api.cohere.com", "cohere"),
    ("api.perplexity.ai", "perplexity"),
    ("api.x.ai", "xai"),
    ("api.together.xyz", "together"),
    ("api.replicate.com", "replicate"),
    ("api-inference.huggingface.co", "huggingface"),
]

# Known AI SaaS browser extension keywords & host domains (SA-010)
BROWSER_AI_KEYWORDS: list[tuple[str, str]] = [
    ("chatgpt", "openai"),
    ("openai", "openai"),
    ("claude", "anthropic"),
    ("perplexity", "perplexity"),
    ("monica", "monica"),
    ("sider", "sider"),
    ("merlin", "merlin"),
    ("harpa", "harpa-ai"),
    ("jasper", "jasper"),
    ("compose ai", "compose-ai"),
    ("otter.ai", "otter"),
    ("fireflies", "fireflies"),
    ("deepseek", "deepseek"),
    ("poe", "poe"),
    ("liner", "liner"),
    ("copilot", "copilot"),
    ("codeium", "windsurf"),
    ("cody", "sourcegraph-cody"),
]

BROWSER_AI_HOSTS: list[tuple[str, str]] = [
    ("chatgpt.com", "openai"),
    ("chat.openai.com", "openai"),
    ("api.openai.com", "openai"),
    ("claude.ai", "anthropic"),
    ("perplexity.ai", "perplexity"),
    ("deepseek.com", "deepseek"),
    ("monica.im", "monica"),
    ("sider.ai", "sider"),
    ("poe.com", "poe"),
]

# Known third-party AI CI / GitHub Actions markers (SA-011)
AI_CI_MARKERS: list[tuple[str, str]] = [
    ("coderabbit", "coderabbit"),
    ("claude-code-action", "anthropic"),
    ("anthropics/", "anthropic"),
    ("openai", "openai"),
    ("chatgpt", "openai"),
    ("copilot", "copilot"),
    ("pr-agent", "qodo"),
    ("codium-ai", "qodo"),
    ("qodo-ai", "qodo"),
    ("sourcery", "sourcery"),
    ("sweepai", "sweep"),
    ("gemini", "google-gemini"),
    ("deepseek", "deepseek"),
    ("ai-code-review", "third-party-ai"),
    ("ai-pr-review", "third-party-ai"),
    ("litellm", "litellm"),
    ("ollama", "ollama"),
]

PLACEHOLDER_TOKENS = (
    "your_",
    "your-",
    "example",
    "placeholder",
    "dummy",
    "changeme",
    "replace_me",
    "test_key",
    "fake_",
    "xxxxxxxx",
    "00000000",
    "<your",
    "${",
)


@dataclass
class AllowlistConfig:
    loaded: bool = False
    path: str | None = None
    approved_providers: set[str] = field(default_factory=set)
    approved_tools: set[str] = field(default_factory=set)
    approved_sdks: set[str] = field(default_factory=set)
    approved_local_servers: set[str] = field(default_factory=set)
    approved_browser_extensions: set[str] = field(default_factory=set)
    approved_ci_actions: set[str] = field(default_factory=set)

    def is_approved(self, provider: str, name: str = "", category: str = "") -> bool:
        p = provider.strip().lower()
        n = name.strip().lower()
        if p in self.approved_providers or n in self.approved_providers:
            return True
        if category == "AI Coding Tool" and (n in self.approved_tools or p in self.approved_tools):
            return True
        if category == "AI SDK Dependency" and (n in self.approved_sdks or p in self.approved_sdks):
            return True
        if category == "Local LLM Server" and (n in self.approved_local_servers or p in self.approved_local_servers):
            return True
        if category == "Browser AI Extension" and (n in self.approved_browser_extensions or p in self.approved_browser_extensions):
            return True
        if category == "CI/CD AI Action":
            for allowed in self.approved_ci_actions:
                if allowed and (allowed == n or allowed in n or allowed == p):
                    return True
        return False


def load_allowlist(path: str | Path | None) -> AllowlistConfig:
    if not path:
        return AllowlistConfig(loaded=False)
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Allowlist file not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Allowlist JSON root must be an object.")

    def norm_set(key: str) -> set[str]:
        val = raw.get(key, [])
        if not isinstance(val, list):
            return set()
        return {str(item).strip().lower() for item in val if str(item).strip()}

    return AllowlistConfig(
        loaded=True,
        path=str(p),
        approved_providers=norm_set("approved_providers"),
        approved_tools=norm_set("approved_tools"),
        approved_sdks=norm_set("approved_sdks"),
        approved_local_servers=norm_set("approved_local_servers"),
        approved_browser_extensions=norm_set("approved_browser_extensions"),
        approved_ci_actions=norm_set("approved_ci_actions"),
    )


def mask_secret(raw: str) -> str:
    """Always redact raw secret values so plaintext credentials are never emitted."""
    val = raw.strip()
    if not val:
        return "****...****"
    known_prefixes = (
        "sk-proj-",
        "sk-ant-",
        "sk-or-v1-",
        "sk-live-",
        "sk-svcacct-",
        "AIza",
        "gsk_",
        "hf_",
        "pplx-",
        "xai-",
        "r8_",
        "sk-",
    )
    for pref in known_prefixes:
        if val.startswith(pref):
            return f"{pref}****...****"
    if len(val) >= 12:
        return f"{val[:4]}****...****"
    return "****...****"


def _is_placeholder(val: str) -> bool:
    low = val.strip().lower()
    if len(low) < 10:
        return True
    if any(tok in low for tok in PLACEHOLDER_TOKENS):
        return True
    if len(set(low)) <= 4:
        return True
    return False


def _read_text_safe(path: Path, max_bytes: int = 262_144) -> str | None:
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size > max_bytes * 4:
            with path.open("rb") as fh:
                chunk = fh.read(max_bytes)
        else:
            chunk = path.read_bytes()[:max_bytes]
        if b"\x00" in chunk:
            return None
        return chunk.decode("utf-8", errors="ignore")
    except OSError:
        return None


def _iter_repo_files(root: Path, max_files: int = 2500) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        for fn in sorted(filenames):
            files.append(base / fn)
            if len(files) >= max_files:
                return files
    return files


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _list_listening_tcp_ports() -> list[tuple[str, int]]:
    """Read-only discovery of listening local TCP sockets via /proc/net/tcp* with socket fallback."""
    listeners: set[tuple[str, int]] = set()
    proc_files = [Path("/proc/net/tcp"), Path("/proc/net/tcp6")]
    parsed_proc = False

    for pf in proc_files:
        if not pf.is_file():
            continue
        parsed_proc = True
        try:
            lines = pf.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        except OSError:
            continue
        is_v6 = pf.name.endswith("6")
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":  # 0A = TCP_LISTEN
                continue
            local_hex = parts[1]
            if ":" not in local_hex:
                continue
            addr_hex, port_hex = local_hex.split(":", 1)
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            if port not in LOCAL_LLM_PORTS:
                continue
            if is_v6:
                if addr_hex == "00000000000000000000000000000000":
                    bind = "::"
                elif addr_hex == "00000000000000000000000001000000":
                    bind = "::1"
                else:
                    bind = "ipv6-local"
            else:
                if addr_hex == "00000000":
                    bind = "0.0.0.0"
                elif addr_hex == "0100007F":
                    bind = "127.0.0.1"
                else:
                    try:
                        octets = [str(int(addr_hex[i : i + 2], 16)) for i in (6, 4, 2, 0)]
                        bind = ".".join(octets)
                    except ValueError:
                        bind = "0.0.0.0"
            listeners.add((bind, port))

    if not parsed_proc:
        # Non-Linux fallback: non-intrusive loopback probe on AI ports
        for port in LOCAL_LLM_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.08)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        listeners.add(("127.0.0.1", port))
            except OSError:
                continue

    return sorted(listeners, key=lambda x: (x[1], x[0]))


class AssetCollector:
    def __init__(self, allowlist: AllowlistConfig) -> None:
        self.allowlist = allowlist
        self.records: list[AssetRecord] = []
        self._seen: set[tuple[str, str, str, str]] = set()

    def add(
        self,
        category: str,
        provider: str,
        name: str,
        location: str,
        risk_level: str,
        source_check: str,
        details: str = "",
        force_status: str | None = None,
    ) -> AssetRecord:
        dedup_key = (category, provider.lower(), name.lower(), location)
        if dedup_key in self._seen:
            for existing in self.records:
                if (existing.category, existing.provider.lower(), existing.name.lower(), existing.location) == dedup_key:
                    return existing
        self._seen.add(dedup_key)
        if force_status is not None:
            status = force_status
        else:
            status = "APPROVED" if self.allowlist.is_approved(provider, name=name, category=category) else "UNAPPROVED"
        rec = AssetRecord(
            asset_id=f"AST-{len(self.records) + 1:03d}",
            category=category,
            provider=provider,
            name=name,
            location=location,
            status=status,
            risk_level=risk_level,
            source_check=source_check,
            details=details,
        )
        self.records.append(rec)
        return rec


def _check_sa001_api_keys(
    repo_root: Path,
    repo_files: list[Path],
    home_dir: Path,
    repo_only: bool,
    env_map: dict[str, str],
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    repo_findings: list[str] = []
    env_unapproved: list[str] = []
    env_approved: list[str] = []

    # 1. Scan repository files (.env, dotfiles, config, code)
    for fpath in repo_files:
        name_low = fpath.name.lower()
        if not (
            name_low.startswith(".env")
            or fpath.suffix.lower() in TEXT_EXTENSIONS
            or name_low in {"dockerfile", "makefile", "jenkinsfile"}
        ):
            continue
        text = _read_text_safe(fpath)
        if not text:
            continue
        rel_path = _rel(fpath, repo_root)
        matched_in_file: set[tuple[str, str]] = set()

        for provider, pat in KEY_PREFIX_PATTERNS:
            for m in pat.finditer(text):
                raw_val = m.group(1)
                if _is_placeholder(raw_val):
                    continue
                masked = mask_secret(raw_val)
                if (provider, masked) in matched_in_file:
                    continue
                matched_in_file.add((provider, masked))
                repo_findings.append(f"{rel_path}: {provider} key ({masked})")
                assets.add(
                    category="API Key",
                    provider=provider,
                    name=f"{provider} hardcoded key ({masked})",
                    location=rel_path,
                    risk_level="CRITICAL",
                    source_check="SA-001",
                    details="Hardcoded AI provider credential inside repository file",
                    force_status="UNAPPROVED",
                )

        for m in ENV_ASSIGN_RE.finditer(text):
            var_name, raw_val = m.group(1), m.group(2)
            if _is_placeholder(raw_val):
                continue
            provider = ENV_VAR_PROVIDERS[var_name]
            masked = mask_secret(raw_val)
            if (provider, masked) in matched_in_file:
                continue
            matched_in_file.add((provider, masked))
            repo_findings.append(f"{rel_path}: {var_name}={masked}")
            assets.add(
                category="API Key",
                provider=provider,
                name=f"{var_name} ({masked})",
                location=rel_path,
                risk_level="CRITICAL",
                source_check="SA-001",
                details="Plaintext AI credential assignment inside repository",
                force_status="UNAPPROVED",
            )

    # 2. Scan workstation environment and shell dotfiles (skipped in --repo-only)
    if not repo_only:
        for var_name, provider in ENV_VAR_PROVIDERS.items():
            raw_val = env_map.get(var_name, "")
            if not raw_val or _is_placeholder(raw_val):
                continue
            masked = mask_secret(raw_val)
            approved = allowlist.is_approved(provider, name=var_name, category="API Key")
            rec = assets.add(
                category="API Key",
                provider=provider,
                name=f"env:{var_name} ({masked})",
                location="process-env",
                risk_level="LOW" if approved else "HIGH",
                source_check="SA-001",
                details="Active AI provider key in workstation environment",
            )
            if rec.status == "APPROVED":
                env_approved.append(f"env:{var_name}={masked} (approved provider)")
            else:
                env_unapproved.append(f"env:{var_name}={masked} (unapproved provider: {provider})")

        dotfile_candidates = [
            home_dir / ".env",
            home_dir / ".bashrc",
            home_dir / ".zshrc",
            home_dir / ".profile",
        ]
        for df in dotfile_candidates:
            text = _read_text_safe(df)
            if not text:
                continue
            for m in ENV_ASSIGN_RE.finditer(text):
                var_name, raw_val = m.group(1), m.group(2)
                if _is_placeholder(raw_val):
                    continue
                provider = ENV_VAR_PROVIDERS[var_name]
                masked = mask_secret(raw_val)
                approved = allowlist.is_approved(provider, name=var_name, category="API Key")
                rec = assets.add(
                    category="API Key",
                    provider=provider,
                    name=f"{var_name} ({masked})",
                    location=str(df),
                    risk_level="MEDIUM" if approved else "HIGH",
                    source_check="SA-001",
                    details="AI API key stored in user shell dotfile",
                )
                entry = f"{df}: {var_name}={masked}"
                if rec.status == "APPROVED":
                    env_approved.append(f"{entry} (approved provider)")
                else:
                    env_unapproved.append(f"{entry} (unapproved provider: {provider})")

    evidence = repo_findings + env_unapproved + env_approved
    if repo_findings or env_unapproved:
        summary_parts = []
        if repo_findings:
            summary_parts.append(f"{len(repo_findings)} hardcoded AI API key(s) in repository")
        if env_unapproved:
            summary_parts.append(f"{len(env_unapproved)} unapproved AI key(s) in environment/dotfiles")
        return CheckResult(
            check_id="SA-001",
            nist_ref="NIST MAP 1.1",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="Credentials & Provider Access",
            title="Unmanaged AI Provider API Keys",
            status="FAIL",
            severity="CRITICAL",
            summary="Detected " + " and ".join(summary_parts) + " (all secrets masked).",
            evidence=evidence[:15],
            remediation="Revoke and rotate exposed keys, remove secrets from repo/dotfiles, and route AI access through a corporate AI gateway or approved secret manager.",
        )

    if env_approved:
        return CheckResult(
            check_id="SA-001",
            nist_ref="NIST MAP 1.1",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="Credentials & Provider Access",
            title="Unmanaged AI Provider API Keys",
            status="WARN",
            severity="MEDIUM",
            summary=f"Found {len(env_approved)} approved provider key(s) in local environment/dotfiles (no hardcoded repo keys).",
            evidence=env_approved[:10],
            remediation="Prefer short-lived OIDC tokens or an enterprise AI proxy instead of static developer API keys.",
        )

    return CheckResult(
        check_id="SA-001",
        nist_ref="NIST MAP 1.1",
        iso_ref="ISO 42001 A.6.2",
        eu_ai_act_ref="EU AI Act Art. 9",
        domain="Credentials & Provider Access",
        title="Unmanaged AI Provider API Keys",
        status="PASS",
        severity="CRITICAL",
        summary="No unmanaged or hardcoded AI provider API keys detected.",
    )


def _check_sa002_local_llm_servers(
    repo_only: bool,
    allowlist: AllowlistConfig,
    assets: AssetCollector,
    listeners_fn: Callable[[], list[tuple[str, int]]] | None = None,
) -> CheckResult:
    if repo_only:
        return CheckResult(
            check_id="SA-002",
            nist_ref="NIST MAP 2.2",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Shadow Infrastructure & Endpoints",
            title="Running Local LLM & Inference Servers",
            status="SKIP",
            severity="HIGH",
            summary="Skipped in --repo-only mode (workstation port check disabled for CI runners).",
        )

    listeners = (listeners_fn or _list_listening_tcp_ports)()
    exposed: list[str] = []
    unapproved_local: list[str] = []
    approved_local: list[str] = []

    for bind, port in listeners:
        if port not in LOCAL_LLM_PORTS:
            continue
        provider, label = LOCAL_LLM_PORTS[port]
        is_wild = bind in ("0.0.0.0", "::")
        approved = allowlist.is_approved(provider, name=label, category="Local LLM Server")
        risk = "CRITICAL" if is_wild else ("LOW" if approved else "HIGH")
        assets.add(
            category="Local LLM Server",
            provider=provider,
            name=f"{label} (:{port})",
            location=f"{bind}:{port}",
            risk_level=risk,
            source_check="SA-002",
            details="Network-exposed local inference server" if is_wild else "Loopback local inference server",
            force_status="UNAPPROVED" if (is_wild or not approved) else "APPROVED",
        )
        desc = f"{label} listening on {bind}:{port}"
        if is_wild:
            exposed.append(f"{desc} (EXPOSED to network)")
        elif not approved:
            unapproved_local.append(f"{desc} (unapproved local LLM)")
        else:
            approved_local.append(f"{desc} (approved loopback)")

    if exposed or unapproved_local:
        sev = "CRITICAL" if exposed else "HIGH"
        return CheckResult(
            check_id="SA-002",
            nist_ref="NIST MAP 2.2",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Shadow Infrastructure & Endpoints",
            title="Running Local LLM & Inference Servers",
            status="FAIL",
            severity=sev,
            summary=f"Detected {len(exposed)} network-exposed and {len(unapproved_local)} unapproved local AI inference server(s).",
            evidence=(exposed + unapproved_local + approved_local)[:12],
            remediation="Stop unauthorized local inference servers, bind approved servers strictly to 127.0.0.1, and register them in approved-ai.json.",
        )

    if approved_local:
        return CheckResult(
            check_id="SA-002",
            nist_ref="NIST MAP 2.2",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Shadow Infrastructure & Endpoints",
            title="Running Local LLM & Inference Servers",
            status="PASS",
            severity="HIGH",
            summary=f"{len(approved_local)} approved local AI inference server(s) bound safely to loopback.",
            evidence=approved_local[:8],
        )

    return CheckResult(
        check_id="SA-002",
        nist_ref="NIST MAP 2.2",
        iso_ref="ISO 42001 A.6.2",
        eu_ai_act_ref="EU AI Act Art. 15",
        domain="Shadow Infrastructure & Endpoints",
        title="Running Local LLM & Inference Servers",
        status="PASS",
        severity="HIGH",
        summary="No unauthorized local LLM or inference servers listening on standard AI ports.",
    )


def _check_sa003_ai_ide_and_cli_tools(
    home_dir: Path,
    repo_only: bool,
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    if repo_only:
        return CheckResult(
            check_id="SA-003",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="Installed AI IDE Extensions & CLI Coding Agents",
            status="SKIP",
            severity="MEDIUM",
            summary="Skipped in --repo-only mode (workstation IDE/CLI presence check disabled for CI runners).",
        )

    tool_probes: list[tuple[str, str, list[Path], list[str]]] = [
        ("cursor", "cursor", [home_dir / ".cursor", home_dir / ".config" / "Cursor"], []),
        ("windsurf", "windsurf", [home_dir / ".codeium" / "windsurf", home_dir / ".config" / "Windsurf"], []),
        ("cline", "cline", [home_dir / ".config" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev"], ["saoudrizwan.claude-dev"]),
        ("continue", "continue", [home_dir / ".continue"], ["continue.continue"]),
        ("copilot", "copilot", [home_dir / ".config" / "github-copilot"], ["github.copilot"]),
        ("claude-code", "anthropic", [home_dir / ".claude", home_dir / ".claude.json"], []),
        ("codex", "openai", [home_dir / ".codex"], []),
        ("aider", "aider", [home_dir / ".aider.conf.yml", home_dir / ".aider.model.settings.yml"], []),
        ("gemini-cli", "google-gemini", [home_dir / ".gemini"], []),
    ]

    vscode_ext_dir = home_dir / ".vscode" / "extensions"
    vscode_ext_names: list[str] = []
    if vscode_ext_dir.is_dir():
        try:
            vscode_ext_names = [p.name.lower() for p in vscode_ext_dir.iterdir()]
        except OSError:
            vscode_ext_names = []

    unapproved: list[str] = []
    approved: list[str] = []

    for tool_name, provider, paths, ext_prefixes in tool_probes:
        found_path: str | None = None
        for p in paths:
            if p.exists():
                found_path = str(p)
                break
        if not found_path and ext_prefixes:
            for ext_dir_name in vscode_ext_names:
                if any(ext_dir_name.startswith(pref) for pref in ext_prefixes):
                    found_path = str(vscode_ext_dir / ext_dir_name)
                    break
        if not found_path:
            continue

        rec = assets.add(
            category="AI Coding Tool",
            provider=provider,
            name=tool_name,
            location=found_path,
            risk_level="LOW" if allowlist.is_approved(provider, name=tool_name, category="AI Coding Tool") else "MEDIUM",
            source_check="SA-003",
            details="Detected AI coding agent or IDE assistant config directory",
        )
        if rec.status == "APPROVED":
            approved.append(f"{tool_name} ({found_path}) [APPROVED]")
        else:
            unapproved.append(f"{tool_name} ({found_path}) [UNAPPROVED]")

    if unapproved:
        status = "FAIL" if allowlist.loaded else "WARN"
        return CheckResult(
            check_id="SA-003",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="Installed AI IDE Extensions & CLI Coding Agents",
            status=status,
            severity="MEDIUM",
            summary=f"Found {len(unapproved)} unapproved AI coding tool(s) and {len(approved)} approved tool(s) on workstation.",
            evidence=(unapproved + approved)[:12],
            remediation="Inventory developer AI coding tools, disable unapproved extensions, and add sanctioned tools to approved-ai.json.",
        )

    if approved:
        return CheckResult(
            check_id="SA-003",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="Installed AI IDE Extensions & CLI Coding Agents",
            status="PASS",
            severity="MEDIUM",
            summary=f"All {len(approved)} installed AI coding tool(s) are explicitly approved.",
            evidence=approved[:10],
        )

    return CheckResult(
        check_id="SA-003",
        nist_ref="NIST MAP 1.5",
        iso_ref="ISO 42001 A.6.1",
        eu_ai_act_ref="EU AI Act Art. 4",
        domain="Shadow AI Tools & Extensions",
        title="Installed AI IDE Extensions & CLI Coding Agents",
        status="PASS",
        severity="MEDIUM",
        summary="No unmanaged AI IDE extensions or CLI coding agents detected.",
    )


def _extract_ai_sdks_from_manifest(fpath: Path, text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    name = fpath.name.lower()

    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return found
        for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(sec)
            if isinstance(deps, dict):
                for pkg in deps:
                    pkg_low = pkg.strip().lower()
                    if pkg_low in AI_SDK_CATALOG:
                        found.append((pkg_low, AI_SDK_CATALOG[pkg_low]))
        return found

    if name.startswith("requirements") and name.endswith(".txt"):
        for line in text.splitlines():
            clean = line.split("#", 1)[0].strip()
            if not clean or clean.startswith("-"):
                continue
            pkg = re.split(r"[=<>!~;\[\s]", clean, maxsplit=1)[0].strip().lower().replace("_", "-")
            if pkg in AI_SDK_CATALOG:
                found.append((pkg, AI_SDK_CATALOG[pkg]))
        return found

    if name in ("pyproject.toml", "cargo.toml", "pipfile"):
        for sdk, prov in AI_SDK_CATALOG.items():
            if sdk.startswith("@") or "/" in sdk:
                continue
            pat = re.compile(rf'(?:["\']|\b){re.escape(sdk)}(?:["\']|\s*[=<>!~,\[\]])', re.IGNORECASE)
            if pat.search(text):
                found.append((sdk, prov))
        return found

    if name == "go.mod":
        for line in text.splitlines():
            clean = line.strip()
            for sdk, prov in AI_SDK_CATALOG.items():
                if sdk in clean.lower():
                    found.append((sdk, prov))
        return found

    return found


def _check_sa004_ai_sdks(
    repo_root: Path,
    repo_files: list[Path],
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    unapproved: list[str] = []
    approved: list[str] = []

    for fpath in repo_files:
        name = fpath.name.lower()
        is_manifest = (
            name in {"pyproject.toml", "package.json", "cargo.toml", "go.mod", "pipfile"}
            or (name.startswith("requirements") and name.endswith(".txt"))
        )
        if not is_manifest:
            continue
        text = _read_text_safe(fpath)
        if not text:
            continue
        rel_path = _rel(fpath, repo_root)
        hits = _extract_ai_sdks_from_manifest(fpath, text)
        seen_in_file: set[str] = set()
        for sdk, provider in hits:
            if sdk in seen_in_file:
                continue
            seen_in_file.add(sdk)
            rec = assets.add(
                category="AI SDK Dependency",
                provider=provider,
                name=sdk,
                location=rel_path,
                risk_level="LOW" if allowlist.is_approved(provider, name=sdk, category="AI SDK Dependency") else "HIGH",
                source_check="SA-004",
                details=f"LLM/AI client SDK declared in {fpath.name}",
            )
            if rec.status == "APPROVED":
                approved.append(f"{rel_path}: {sdk} ({provider}) [APPROVED]")
            else:
                unapproved.append(f"{rel_path}: {sdk} ({provider}) [UNAPPROVED]")

    if unapproved:
        return CheckResult(
            check_id="SA-004",
            nist_ref="NIST MAP 2.3",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 10",
            domain="Supply Chain & CI Controls",
            title="Unapproved AI SDK & LLM Client Dependencies",
            status="FAIL",
            severity="HIGH",
            summary=f"Detected {len(unapproved)} unapproved AI SDK dependency declaration(s) in repository manifests.",
            evidence=(unapproved + approved)[:15],
            remediation="Remove unauthorized AI SDKs or submit them for vendor security review and add approved providers to approved-ai.json.",
        )

    if approved:
        return CheckResult(
            check_id="SA-004",
            nist_ref="NIST MAP 2.3",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 10",
            domain="Supply Chain & CI Controls",
            title="Unapproved AI SDK & LLM Client Dependencies",
            status="PASS",
            severity="HIGH",
            summary=f"All {len(approved)} AI SDK dependency declaration(s) match the corporate allowlist.",
            evidence=approved[:10],
        )

    return CheckResult(
        check_id="SA-004",
        nist_ref="NIST MAP 2.3",
        iso_ref="ISO 42001 A.6.2",
        eu_ai_act_ref="EU AI Act Art. 10",
        domain="Supply Chain & CI Controls",
        title="Unapproved AI SDK & LLM Client Dependencies",
        status="PASS",
        severity="HIGH",
        summary="No unmanaged AI SDK or LLM client packages found in dependency manifests.",
    )


def _check_sa005_hardcoded_endpoints(
    repo_root: Path,
    repo_files: list[Path],
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    unapproved: list[str] = []
    approved: list[str] = []

    for fpath in repo_files:
        if fpath.suffix.lower() not in CODE_EXTENSIONS:
            continue
        text = _read_text_safe(fpath)
        if not text:
            continue
        low = text.lower()
        rel_path = _rel(fpath, repo_root)
        for host, provider in LLM_ENDPOINTS:
            if host not in low:
                continue
            rec = assets.add(
                category="LLM API Endpoint",
                provider=provider,
                name=host,
                location=rel_path,
                risk_level="LOW" if allowlist.is_approved(provider, name=host, category="LLM API Endpoint") else "HIGH",
                source_check="SA-005",
                details="Direct external LLM API endpoint referenced in source code",
            )
            if rec.status == "APPROVED":
                approved.append(f"{rel_path}: {host} ({provider}) [APPROVED]")
            else:
                unapproved.append(f"{rel_path}: {host} ({provider}) [UNAPPROVED]")

    if unapproved:
        return CheckResult(
            check_id="SA-005",
            nist_ref="NIST MAP 3.1",
            iso_ref="ISO 42001 A.7.3",
            eu_ai_act_ref="EU AI Act Art. 13",
            domain="Shadow Infrastructure & Endpoints",
            title="Hardcoded LLM API Endpoints in Source Code",
            status="FAIL",
            severity="HIGH",
            summary=f"Found {len(unapproved)} hardcoded call(s) to unapproved external LLM API endpoints.",
            evidence=(unapproved + approved)[:15],
            remediation="Replace direct external LLM endpoints with a centralized internal AI gateway that enforces logging, DLP, and provider allowlists.",
        )

    if approved:
        return CheckResult(
            check_id="SA-005",
            nist_ref="NIST MAP 3.1",
            iso_ref="ISO 42001 A.7.3",
            eu_ai_act_ref="EU AI Act Art. 13",
            domain="Shadow Infrastructure & Endpoints",
            title="Hardcoded LLM API Endpoints in Source Code",
            status="WARN",
            severity="LOW",
            summary=f"Found {len(approved)} direct endpoint call(s) to approved AI providers (consider centralizing via AI proxy).",
            evidence=approved[:10],
            remediation="Configure base URLs via environment variables pointing to an audited corporate AI gateway.",
        )

    return CheckResult(
        check_id="SA-005",
        nist_ref="NIST MAP 3.1",
        iso_ref="ISO 42001 A.7.3",
        eu_ai_act_ref="EU AI Act Art. 13",
        domain="Shadow Infrastructure & Endpoints",
        title="Hardcoded LLM API Endpoints in Source Code",
        status="PASS",
        severity="HIGH",
        summary="No hardcoded external LLM API endpoints detected in repository source files.",
    )


def _check_sa006_data_boundary_policy(repo_root: Path) -> CheckResult:
    ignore_candidates = [
        ".aiignore",
        ".cursorignore",
        ".copilotignore",
        ".geminiignore",
        ".claudeignore",
    ]
    policy_candidates = [
        "AI_POLICY.md",
        "AI_ACCEPTABLE_USE_POLICY.md",
        "docs/AI_POLICY.md",
        "docs/AI_ACCEPTABLE_USE_POLICY.md",
        ".github/AI_POLICY.md",
    ]

    found_ignores: list[Path] = [repo_root / name for name in ignore_candidates if (repo_root / name).is_file()]
    found_policies: list[Path] = [repo_root / name for name in policy_candidates if (repo_root / name).is_file()]

    has_secret_rules = False
    for ig in found_ignores:
        txt = (_read_text_safe(ig) or "").lower()
        if ".env" in txt and ("*.pem" in txt or "*.key" in txt or "secret" in txt):
            has_secret_rules = True

    if found_ignores and has_secret_rules:
        ev = [f"Boundary file: {_rel(p, repo_root)}" for p in found_ignores]
        ev.extend(f"Policy doc: {_rel(p, repo_root)}" for p in found_policies)
        return CheckResult(
            check_id="SA-006",
            nist_ref="NIST GOVERN 1.2",
            iso_ref="ISO 42001 A.2.2",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="AI Governance & Policy",
            title="AI Data-Boundary Policy (.aiignore / AI_POLICY.md)",
            status="PASS",
            severity="MEDIUM",
            summary="Repository enforces AI data-boundary ignore rules blocking sensitive files.",
            evidence=ev,
        )

    if found_ignores or found_policies:
        ev = [f"Found: {_rel(p, repo_root)}" for p in found_ignores + found_policies]
        return CheckResult(
            check_id="SA-006",
            nist_ref="NIST GOVERN 1.2",
            iso_ref="ISO 42001 A.2.2",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="AI Governance & Policy",
            title="AI Data-Boundary Policy (.aiignore / AI_POLICY.md)",
            status="WARN",
            severity="MEDIUM",
            summary="Partial AI boundary documentation found, but ignore rules do not explicitly block .env and private key files.",
            evidence=ev,
            remediation="Add .env, *.pem, *.key, and customer export directories to .aiignore / .cursorignore and include AI_POLICY.md.",
        )

    return CheckResult(
        check_id="SA-006",
        nist_ref="NIST GOVERN 1.2",
        iso_ref="ISO 42001 A.2.2",
        eu_ai_act_ref="EU AI Act Art. 9",
        domain="AI Governance & Policy",
        title="AI Data-Boundary Policy (.aiignore / AI_POLICY.md)",
        status="FAIL",
        severity="MEDIUM",
        summary="No AI data-boundary file (.aiignore, .cursorignore, .copilotignore) or AI_POLICY.md found in repository.",
        evidence=["Missing .aiignore / .cursorignore / .copilotignore", "Missing AI_POLICY.md"],
        remediation="Add an enterprise .aiignore blocking secrets, certificates, and PII exports plus an AI_POLICY.md acceptable use policy.",
    )


def _check_sa007_chat_transcripts_and_datasets(
    repo_root: Path,
    repo_files: list[Path],
    assets: AssetCollector,
) -> CheckResult:
    name_pat = re.compile(
        r"(chat_history|prompts?_dump|chatgpt.*export|claude.*export|llm_logs|conversation.*log|finetune|fine_tune|training_data)",
        re.IGNORECASE,
    )
    findings: list[str] = []

    for fpath in repo_files:
        rel_path = _rel(fpath, repo_root)
        fname = fpath.name
        flagged_reason: str | None = None

        if name_pat.search(fname):
            flagged_reason = "Filename matches AI chat transcript, prompt dump, or fine-tuning dataset"
        elif fpath.suffix.lower() == ".jsonl":
            txt = _read_text_safe(fpath, max_bytes=32_768)
            if txt:
                for line in txt.splitlines()[:5]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict):
                        keys = set(obj.keys())
                        if (
                            ("messages" in keys and isinstance(obj.get("messages"), list))
                            or ({"prompt", "completion"} <= keys)
                            or ({"instruction", "output"} <= keys)
                        ):
                            flagged_reason = "JSONL file contains LLM chat/fine-tuning schema (messages/prompt/completion)"
                            break

        if flagged_reason:
            findings.append(f"{rel_path}: {flagged_reason}")
            assets.add(
                category="AI Transcript / Dataset",
                provider="workspace-data",
                name=fname,
                location=rel_path,
                risk_level="HIGH",
                source_check="SA-007",
                details=flagged_reason,
                force_status="UNAPPROVED",
            )

    if findings:
        return CheckResult(
            check_id="SA-007",
            nist_ref="NIST MEASURE 2.6",
            iso_ref="ISO 42001 A.7.4",
            eu_ai_act_ref="EU AI Act Art. 10",
            domain="Data & Model Risk",
            title="Unredacted AI Chat Transcripts & Fine-Tuning Datasets",
            status="FAIL",
            severity="HIGH",
            summary=f"Detected {len(findings)} AI chat transcript, prompt dump, or fine-tuning dataset artifact(s) in workspace.",
            evidence=findings[:12],
            remediation="Remove unredacted AI transcripts and fine-tuning JSONL datasets from source repositories, purge sensitive history, and store approved datasets in governed storage.",
        )

    return CheckResult(
        check_id="SA-007",
        nist_ref="NIST MEASURE 2.6",
        iso_ref="ISO 42001 A.7.4",
        eu_ai_act_ref="EU AI Act Art. 10",
        domain="Data & Model Risk",
        title="Unredacted AI Chat Transcripts & Fine-Tuning Datasets",
        status="PASS",
        severity="HIGH",
        summary="No unredacted AI chat transcripts, prompt dumps, or fine-tuning JSONL files detected.",
    )


def _check_sa008_sensitive_data_in_prompts(
    repo_root: Path,
    repo_files: list[Path],
) -> CheckResult:
    prompt_name_pat = re.compile(r"(prompt|system_prompt|agents\.md|claude\.md|\.cursorrules)", re.IGNORECASE)
    rfc1918_re = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
    db_uri_re = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s'\"`]+", re.IGNORECASE)
    ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    cred_re = re.compile(r"(?:password|passwd|db_pass|secret_key|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.!@#\$%\^&]{6,})", re.IGNORECASE)
    privkey_re = re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")

    findings: list[str] = []

    for fpath in repo_files:
        if fpath.suffix.lower() not in TEXT_EXTENSIONS and fpath.name.lower() != ".cursorrules":
            continue
        rel_path = _rel(fpath, repo_root)
        is_prompt_path = bool(prompt_name_pat.search(rel_path))
        text = _read_text_safe(fpath)
        if not text:
            continue
        if not is_prompt_path and "system_prompt" not in text.lower():
            continue

        reasons: list[str] = []
        if db_uri_re.search(text):
            reasons.append("database connection URI")
        if rfc1918_re.search(text):
            reasons.append("internal RFC1918 IP address")
        if ssn_re.search(text):
            reasons.append("SSN/PII pattern")
        if privkey_re.search(text):
            reasons.append("embedded private key block")
        cred_match = cred_re.search(text)
        if cred_match and not _is_placeholder(cred_match.group(1)):
            reasons.append(f"embedded credential ({mask_secret(cred_match.group(1))})")

        if reasons:
            findings.append(f"{rel_path}: contains {', '.join(reasons)}")

    if findings:
        return CheckResult(
            check_id="SA-008",
            nist_ref="NIST MEASURE 2.10",
            iso_ref="ISO 42001 A.7.4",
            eu_ai_act_ref="EU AI Act Art. 10",
            domain="Data & Model Risk",
            title="Sensitive Data Inside Prompt Templates",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Detected sensitive infrastructure, credential, or PII patterns inside {len(findings)} prompt template(s).",
            evidence=findings[:12],
            remediation="Strip internal IPs, database connection strings, credentials, and PII from system prompts; pass synthetic placeholders or tokenized references instead.",
        )

    return CheckResult(
        check_id="SA-008",
        nist_ref="NIST MEASURE 2.10",
        iso_ref="ISO 42001 A.7.4",
        eu_ai_act_ref="EU AI Act Art. 10",
        domain="Data & Model Risk",
        title="Sensitive Data Inside Prompt Templates",
        status="PASS",
        severity="CRITICAL",
        summary="No internal IPs, database URIs, credentials, or PII patterns found inside prompt templates.",
    )


def _check_sa009_model_weight_sprawl(
    repo_root: Path,
    repo_files: list[Path],
    home_dir: Path,
    repo_only: bool,
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    unsafe_pickle_exts = {".pkl", ".pickle", ".pt", ".pth", ".ckpt"}
    safer_model_exts = {".gguf", ".safetensors", ".onnx", ".mlx"}
    bin_model_pat = re.compile(r"(pytorch_model|adapter_model|model|weights|checkpoint).*\.bin$", re.IGNORECASE)

    pickle_findings: list[str] = []
    safe_sprawl: list[str] = []

    def inspect_artifact(fpath: Path, display_loc: str, provider_hint: str) -> None:
        ext = fpath.suffix.lower()
        is_unsafe = ext in unsafe_pickle_exts or (
            ext == ".bin" and (bin_model_pat.search(fpath.name) is not None or any(p in {"models", "weights", "checkpoints"} for p in fpath.parts))
        )
        is_safer = ext in safer_model_exts
        if not (is_unsafe or is_safer):
            return
        try:
            size_mb = fpath.stat().st_size / (1024 * 1024)
            size_label = f"{size_mb:.1f} MB" if size_mb >= 0.1 else f"{fpath.stat().st_size} B"
        except OSError:
            size_label = "unknown size"

        if is_unsafe:
            pickle_findings.append(f"{display_loc} ({size_label}) [UNSAFE PICKLE/DESERIALIZATION RISK]")
            assets.add(
                category="Model Weight Artifact",
                provider=provider_hint,
                name=fpath.name,
                location=display_loc,
                risk_level="CRITICAL",
                source_check="SA-009",
                details=f"Unsafe pickle-based model format ({ext}, {size_label}) vulnerable to arbitrary code execution on load",
                force_status="UNAPPROVED",
            )
        else:
            rec = assets.add(
                category="Model Weight Artifact",
                provider=provider_hint,
                name=fpath.name,
                location=display_loc,
                risk_level="LOW" if allowlist.is_approved(provider_hint, name=fpath.name) else "MEDIUM",
                source_check="SA-009",
                details=f"Local model weight file ({ext}, {size_label})",
            )
            if rec.status != "APPROVED":
                safe_sprawl.append(f"{display_loc} ({size_label}) [UNMANAGED MODEL WEIGHT]")

    for fpath in repo_files:
        inspect_artifact(fpath, _rel(fpath, repo_root), "local-model")

    if not repo_only:
        cache_dirs = [
            (home_dir / ".ollama" / "models" / "manifests", "ollama"),
            (home_dir / ".cache" / "huggingface" / "hub", "huggingface"),
            (home_dir / ".lmstudio" / "models", "lmstudio"),
        ]
        for cdir, prov in cache_dirs:
            if not cdir.is_dir():
                continue
            count = 0
            for dirpath, dirnames, filenames in os.walk(cdir):
                dirnames[:] = sorted(dirnames)[:40]
                for fn in sorted(filenames):
                    count += 1
                    if count > 400:
                        break
                    inspect_artifact(Path(dirpath) / fn, str(Path(dirpath) / fn), prov)
                if count > 400:
                    break

    if pickle_findings:
        return CheckResult(
            check_id="SA-009",
            nist_ref="NIST MEASURE 2.5",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Data & Model Risk",
            title="Model Weight Sprawl & Unsafe Pickle Deserialization Risk",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Detected {len(pickle_findings)} unsafe pickle/PyTorch weight file(s) with deserialization RCE risk and {len(safe_sprawl)} unmanaged model weight(s).",
            evidence=(pickle_findings + safe_sprawl)[:12],
            remediation="Replace .pkl/.pt/.pth/pytorch_model.bin artifacts with verified .safetensors or signed .gguf weights and track approved models in a central registry.",
        )

    if safe_sprawl:
        return CheckResult(
            check_id="SA-009",
            nist_ref="NIST MEASURE 2.5",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Data & Model Risk",
            title="Model Weight Sprawl & Unsafe Pickle Deserialization Risk",
            status="WARN",
            severity="MEDIUM",
            summary=f"Detected {len(safe_sprawl)} unmanaged local model weight artifact(s) (.gguf/.safetensors/.onnx).",
            evidence=safe_sprawl[:12],
            remediation="Verify provenance/checksums of local model weights, exclude large weights from Git repos, and approve sanctioned model sources in approved-ai.json.",
        )

    return CheckResult(
        check_id="SA-009",
        nist_ref="NIST MEASURE 2.5",
        iso_ref="ISO 42001 A.6.2",
        eu_ai_act_ref="EU AI Act Art. 15",
        domain="Data & Model Risk",
        title="Model Weight Sprawl & Unsafe Pickle Deserialization Risk",
        status="PASS",
        severity="HIGH",
        summary="No unmanaged model weights or unsafe pickle deserialization artifacts detected.",
    )


def _check_sa010_browser_extensions(
    home_dir: Path,
    repo_only: bool,
    allowlist: AllowlistConfig,
    assets: AssetCollector,
    browser_ext_dirs: list[Path] | None = None,
) -> CheckResult:
    if repo_only:
        return CheckResult(
            check_id="SA-010",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="AI SaaS Browser Extension Metadata Audit",
            status="SKIP",
            severity="MEDIUM",
            summary="Skipped in --repo-only mode (read-only extension manifest.json audit disabled for CI runners).",
        )

    # STRICT PRIVACY BOUNDARY: ONLY inspect static Extensions/*/*/manifest.json metadata.
    # Never open cookies, Login Data, History, Web Data, or SQLite files.
    if browser_ext_dirs is None:
        browser_roots = [
            home_dir / ".config" / "google-chrome",
            home_dir / ".config" / "chromium",
            home_dir / ".config" / "BraveSoftware" / "Brave-Browser",
            home_dir / ".config" / "microsoft-edge",
            home_dir / "Library" / "Application Support" / "Google" / "Chrome",
            home_dir / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser",
        ]
        ext_dirs: list[Path] = []
        for broot in browser_roots:
            if not broot.is_dir():
                continue
            for prof in ("Default", "Profile 1", "Profile 2"):
                ed = broot / prof / "Extensions"
                if ed.is_dir():
                    ext_dirs.append(ed)
    else:
        ext_dirs = [p for p in browser_ext_dirs if p.is_dir()]

    broad_unapproved: list[str] = []
    scoped_unapproved: list[str] = []
    approved_ext: list[str] = []

    for ed in ext_dirs:
        try:
            ext_id_dirs = sorted(p for p in ed.iterdir() if p.is_dir())
        except OSError:
            continue
        for ext_dir in ext_id_dirs[:200]:
            try:
                ver_dirs = sorted((p for p in ext_dir.iterdir() if p.is_dir()), reverse=True)
            except OSError:
                continue
            if not ver_dirs:
                continue
            manifest_path = ver_dirs[0] / "manifest.json"
            if not manifest_path.is_file():
                continue
            raw_txt = _read_text_safe(manifest_path, max_bytes=65_536)
            if not raw_txt:
                continue
            try:
                manifest = json.loads(raw_txt)
            except json.JSONDecodeError:
                continue
            if not isinstance(manifest, dict):
                continue

            ext_name = str(manifest.get("name", ""))
            ext_desc = str(manifest.get("description", ""))
            host_perms = manifest.get("host_permissions", []) or []
            perms = manifest.get("permissions", []) or []
            all_perms = [str(p) for p in list(host_perms) + list(perms)]
            name_low = ext_name.lower()
            desc_low = ext_desc.lower()
            combined_hosts = " ".join(all_perms).lower()

            matched_provider: str | None = None
            for kw, prov in BROWSER_AI_KEYWORDS:
                if kw in name_low:
                    matched_provider = prov
                    break
            if not matched_provider:
                for kw, prov in BROWSER_AI_KEYWORDS:
                    if kw in desc_low:
                        matched_provider = prov
                        break
            if not matched_provider:
                for host, prov in BROWSER_AI_HOSTS:
                    if host in combined_hosts:
                        matched_provider = prov
                        break
            if not matched_provider:
                continue

            display_name = ext_name if ext_name and not ext_name.startswith("__MSG_") else f"{matched_provider}-ext-{ext_dir.name[:8]}"
            has_broad = any(p in ("<all_urls>", "https://*/*", "http://*/*", "*://*/*") for p in all_perms)
            rec = assets.add(
                category="Browser AI Extension",
                provider=matched_provider,
                name=display_name,
                location=str(manifest_path),
                risk_level="LOW" if allowlist.is_approved(matched_provider, name=display_name, category="Browser AI Extension") else ("HIGH" if has_broad else "MEDIUM"),
                source_check="SA-010",
                details="Broad all-URLs page read access" if has_broad else "Scoped AI SaaS browser extension",
            )
            if rec.status == "APPROVED":
                approved_ext.append(f"{display_name} ({matched_provider}) [APPROVED]")
            elif has_broad:
                broad_unapproved.append(f"{display_name} ({matched_provider}, broad host access) at {manifest_path}")
            else:
                scoped_unapproved.append(f"{display_name} ({matched_provider}) at {manifest_path}")

    if broad_unapproved:
        return CheckResult(
            check_id="SA-010",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="AI SaaS Browser Extension Metadata Audit",
            status="FAIL",
            severity="HIGH",
            summary=f"Detected {len(broad_unapproved)} unapproved AI browser extension(s) with broad page-reading permissions.",
            evidence=(broad_unapproved + scoped_unapproved + approved_ext)[:12],
            remediation="Enforce Chrome/Brave ExtensionInstallBlocklist policy for unapproved AI sidebars that read arbitrary corporate SaaS tabs.",
        )

    if scoped_unapproved:
        return CheckResult(
            check_id="SA-010",
            nist_ref="NIST MAP 1.5",
            iso_ref="ISO 42001 A.6.1",
            eu_ai_act_ref="EU AI Act Art. 4",
            domain="Shadow AI Tools & Extensions",
            title="AI SaaS Browser Extension Metadata Audit",
            status="WARN",
            severity="MEDIUM",
            summary=f"Detected {len(scoped_unapproved)} unapproved AI SaaS browser extension(s) via static manifest metadata.",
            evidence=(scoped_unapproved + approved_ext)[:12],
            remediation="Review installed AI browser extensions against corporate DLP policy and add approved tools to approved-ai.json.",
        )

    return CheckResult(
        check_id="SA-010",
        nist_ref="NIST MAP 1.5",
        iso_ref="ISO 42001 A.6.1",
        eu_ai_act_ref="EU AI Act Art. 4",
        domain="Shadow AI Tools & Extensions",
        title="AI SaaS Browser Extension Metadata Audit",
        status="PASS",
        severity="MEDIUM",
        summary="No unapproved AI SaaS browser extensions found in static extension manifests.",
        evidence=approved_ext[:8],
    )


def _check_sa011_ai_ci_workflows(
    repo_root: Path,
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    wf_files: list[Path] = []
    gh_wf = repo_root / ".github" / "workflows"
    if gh_wf.is_dir():
        wf_files.extend(sorted(p for p in gh_wf.iterdir() if p.is_file() and p.suffix.lower() in (".yml", ".yaml")))
    gitlab_ci = repo_root / ".gitlab-ci.yml"
    if gitlab_ci.is_file():
        wf_files.append(gitlab_ci)

    uses_re = re.compile(r"uses\s*:\s*['\"]?([A-Za-z0-9_.\-/]+@[^\s'\"#]+)['\"]?")
    sha_pin_re = re.compile(r"@[0-9a-fA-F]{40}$")

    failing: list[str] = []
    warnings: list[str] = []
    passing: list[str] = []

    for wf in wf_files:
        text = _read_text_safe(wf)
        if not text:
            continue
        rel_path = _rel(wf, repo_root)
        has_pr_target = "pull_request_target" in text

        for m in uses_re.finditer(text):
            ref = m.group(1)
            ref_low = ref.lower()
            matched_provider: str | None = None
            for marker, prov in AI_CI_MARKERS:
                if marker in ref_low:
                    matched_provider = prov
                    break
            if not matched_provider:
                continue

            action_base = ref.split("@", 1)[0]
            is_pinned = bool(sha_pin_re.search(ref))
            approved = allowlist.is_approved(matched_provider, name=action_base, category="CI/CD AI Action")
            risk = "HIGH" if (not is_pinned or has_pr_target or not approved) else "LOW"
            assets.add(
                category="CI/CD AI Action",
                provider=matched_provider,
                name=ref,
                location=rel_path,
                risk_level=risk,
                source_check="SA-011",
                details="Pinned to commit SHA" if is_pinned else "Unpinned mutable Git ref in AI CI workflow",
                force_status="APPROVED" if (approved and is_pinned and not has_pr_target) else "UNAPPROVED",
            )
            issues: list[str] = []
            if not is_pinned:
                issues.append("unpinned mutable ref")
            if has_pr_target:
                issues.append("runs under pull_request_target")
            if not approved:
                issues.append("unapproved AI action")

            if not is_pinned or has_pr_target or (allowlist.loaded and not approved):
                failing.append(f"{rel_path}: {ref} ({', '.join(issues)})")
            elif not approved:
                warnings.append(f"{rel_path}: {ref} (SHA-pinned, not yet in allowlist)")
            else:
                passing.append(f"{rel_path}: {ref} (SHA-pinned & approved)")

    if failing:
        return CheckResult(
            check_id="SA-011",
            nist_ref="NIST MANAGE 2.4",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Supply Chain & CI Controls",
            title="Unpinned or Unapproved AI GitHub Actions / CI Workflows",
            status="FAIL",
            severity="HIGH",
            summary=f"Detected {len(failing)} unpinned or unapproved third-party AI CI workflow action(s).",
            evidence=(failing + warnings + passing)[:12],
            remediation="Pin all third-party AI GitHub Actions to full 40-character commit SHAs, avoid pull_request_target with AI bots, and approve actions in approved-ai.json.",
        )

    if warnings:
        return CheckResult(
            check_id="SA-011",
            nist_ref="NIST MANAGE 2.4",
            iso_ref="ISO 42001 A.6.2",
            eu_ai_act_ref="EU AI Act Art. 15",
            domain="Supply Chain & CI Controls",
            title="Unpinned or Unapproved AI GitHub Actions / CI Workflows",
            status="WARN",
            severity="MEDIUM",
            summary=f"Found {len(warnings)} SHA-pinned AI CI action(s) not yet registered in an allowlist.",
            evidence=warnings[:10],
            remediation="Register sanctioned AI CI workflows inside approved-ai.json.",
        )

    return CheckResult(
        check_id="SA-011",
        nist_ref="NIST MANAGE 2.4",
        iso_ref="ISO 42001 A.6.2",
        eu_ai_act_ref="EU AI Act Art. 15",
        domain="Supply Chain & CI Controls",
        title="Unpinned or Unapproved AI GitHub Actions / CI Workflows",
        status="PASS",
        severity="HIGH",
        summary="No unpinned or unauthorized third-party AI CI workflow actions detected.",
        evidence=passing[:8],
    )


def _check_sa012_allowlist_governance(
    allowlist: AllowlistConfig,
    assets: AssetCollector,
) -> CheckResult:
    total = len(assets.records)
    approved = [a for a in assets.records if a.status == "APPROVED"]
    unapproved = [a for a in assets.records if a.status != "APPROVED"]
    unapproved_providers = sorted({a.provider for a in unapproved})

    if allowlist.loaded:
        if not unapproved:
            return CheckResult(
                check_id="SA-012",
                nist_ref="NIST GOVERN 1.4",
                iso_ref="ISO 42001 A.2.3",
                eu_ai_act_ref="EU AI Act Art. 9",
                domain="AI Governance & Policy",
                title="Shadow AI Governance Allowlist Verification",
                status="PASS",
                severity="MEDIUM",
                summary=f"Allowlist enforced ({len(allowlist.approved_providers)} approved provider(s)): all {total} discovered AI asset(s) are governed.",
                evidence=[f"Allowlist: {allowlist.path}", f"Approved assets: {len(approved)}/{total}"],
            )
        ev = [f"Allowlist: {allowlist.path}", f"Unapproved providers: {', '.join(unapproved_providers)}"]
        ev.extend(f"{a.asset_id} [{a.category}] {a.provider}: {a.name} ({a.location})" for a in unapproved[:8])
        return CheckResult(
            check_id="SA-012",
            nist_ref="NIST GOVERN 1.4",
            iso_ref="ISO 42001 A.2.3",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="AI Governance & Policy",
            title="Shadow AI Governance Allowlist Verification",
            status="FAIL",
            severity="HIGH",
            summary=f"Allowlist verification failed: {len(unapproved)} of {total} AI asset(s) violate approved-ai.json ({len(approved)} approved).",
            evidence=ev,
            remediation="Remediate unapproved Shadow AI assets or complete formal vendor risk assessment before adding them to approved-ai.json.",
        )

    if total > 0:
        return CheckResult(
            check_id="SA-012",
            nist_ref="NIST GOVERN 1.4",
            iso_ref="ISO 42001 A.2.3",
            eu_ai_act_ref="EU AI Act Art. 9",
            domain="AI Governance & Policy",
            title="Shadow AI Governance Allowlist Verification",
            status="WARN",
            severity="MEDIUM",
            summary=f"Discovered {total} AI asset(s) across {len(unapproved_providers)} provider(s) with no --allowlist policy supplied.",
            evidence=[f"Uncatalogued providers: {', '.join(unapproved_providers)}"],
            remediation="Create approved-ai.json listing sanctioned providers and run ShadowAI-Scan with --allowlist approved-ai.json.",
        )

    return CheckResult(
        check_id="SA-012",
        nist_ref="NIST GOVERN 1.4",
        iso_ref="ISO 42001 A.2.3",
        eu_ai_act_ref="EU AI Act Art. 9",
        domain="AI Governance & Policy",
        title="Shadow AI Governance Allowlist Verification",
        status="PASS",
        severity="MEDIUM",
        summary="Zero Shadow AI assets detected in scanned scope.",
    )


def run_scan(
    target_path: str | Path = ".",
    repo_only: bool = False,
    allowlist_path: str | Path | None = None,
    redact: bool = False,
    home_dir: str | Path | None = None,
    env_override: dict[str, str] | None = None,
    listeners_fn: Callable[[], list[tuple[str, int]]] | None = None,
    browser_ext_dirs: list[Path] | None = None,
) -> ScanReport:
    """Execute all 12 read-only Shadow AI discovery and governance checks."""
    repo_root = Path(target_path).expanduser().resolve()
    resolved_home = Path(home_dir).expanduser().resolve() if home_dir else Path.home().resolve()
    env_map = dict(os.environ) if env_override is None else dict(env_override)
    allowlist = load_allowlist(allowlist_path)
    assets = AssetCollector(allowlist)

    repo_files = _iter_repo_files(repo_root)

    checks: list[CheckResult] = [
        _check_sa001_api_keys(repo_root, repo_files, resolved_home, repo_only, env_map, allowlist, assets),
        _check_sa002_local_llm_servers(repo_only, allowlist, assets, listeners_fn=listeners_fn),
        _check_sa003_ai_ide_and_cli_tools(resolved_home, repo_only, allowlist, assets),
        _check_sa004_ai_sdks(repo_root, repo_files, allowlist, assets),
        _check_sa005_hardcoded_endpoints(repo_root, repo_files, allowlist, assets),
        _check_sa006_data_boundary_policy(repo_root),
        _check_sa007_chat_transcripts_and_datasets(repo_root, repo_files, assets),
        _check_sa008_sensitive_data_in_prompts(repo_root, repo_files),
        _check_sa009_model_weight_sprawl(repo_root, repo_files, resolved_home, repo_only, allowlist, assets),
        _check_sa010_browser_extensions(resolved_home, repo_only, allowlist, assets, browser_ext_dirs=browser_ext_dirs),
        _check_sa011_ai_ci_workflows(repo_root, allowlist, assets),
    ]
    checks.append(_check_sa012_allowlist_governance(allowlist, assets))

    hostname = socket.gethostname()
    username = getpass.getuser()
    report = ScanReport(
        tool_version=__version__,
        generated_at=utc_now_iso(),
        target_path=str(repo_root),
        repo_only=repo_only,
        hostname=hostname,
        platform_info=f"{platform.system()} {platform.release()} (Python {platform.python_version()})",
        redacted=False,
        allowlist_path=allowlist.path,
        approved_providers=sorted(allowlist.approved_providers),
        checks=checks,
        assets=assets.records,
        metadata={
            "files_scanned": len(repo_files),
            "total_assets": len(assets.records),
            "unapproved_assets": sum(1 for a in assets.records if a.status != "APPROVED"),
            "approved_assets": sum(1 for a in assets.records if a.status == "APPROVED"),
            "unique_providers": len({a.provider for a in assets.records}),
        },
    )

    if redact:
        report = redact_report(report, home_dir=str(resolved_home), username=username)

    return report
