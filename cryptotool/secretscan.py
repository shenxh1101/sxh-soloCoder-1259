import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class SecretFinding:
    file_path: str
    rel_path: str
    line: int
    secret_type: str
    matched_text: str
    description: str


SECRET_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    (
        "RSA_PRIVATE_KEY",
        "RSA 私钥",
        re.compile(r"-----BEGIN (RSA |OPENSSH |DSA |EC |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    (
        "SSH_PRIVATE_KEY",
        "SSH 私钥",
        re.compile(r"-----BEGIN (OPENSSH|RSA|DSA|EC|ED25519) PRIVATE KEY-----"),
    ),
    (
        "AWS_ACCESS_KEY",
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    (
        "AWS_SECRET_KEY",
        "AWS Secret Access Key",
        re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ),
    (
        "GCP_SERVICE_ACCOUNT",
        "GCP 服务账号密钥",
        re.compile(r'"type"\s*:\s*"service_account"'),
    ),
    (
        "GITHUB_TOKEN",
        "GitHub Personal Access Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,251}"),
    ),
    (
        "GITHUB_CLASSIC_TOKEN",
        "GitHub 经典 Token",
        re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{40}(?![A-Za-z0-9])"),
    ),
    (
        "SLACK_TOKEN",
        "Slack Token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "SLACK_WEBHOOK",
        "Slack Webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),
    ),
    (
        "STRIPE_KEY",
        "Stripe API Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    ),
    (
        "PRIVATE_KEY_HEADER",
        "通用私钥头",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    (
        "GENERIC_PASSWORD",
        "通用密码赋值",
        re.compile(
            r"(?im)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
            r"(\s*[:=]\s*)(['\"]?)(?!(?:test|dummy|example|sample|xxxx|changeme|None|null|false|true|0|1)\b)"
            r"[A-Za-z0-9_\-!@#$%^&*()+=\[\]{}|;:'\",.<>?/`~]{8,}\3"
        ),
    ),
    (
        "JWT_TOKEN",
        "JWT (JSON Web Token)",
        re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ),
    (
        "HEROKU_API_KEY",
        "Heroku API Key",
        re.compile(r"(?i)heroku(.{0,20})?['\"][0-9a-fA-F-]{36}['\"]"),
    ),
    (
        "TWILIO_API_KEY",
        "Twilio API Key",
        re.compile(r"SK[0-9a-fA-F]{32}"),
    ),
    (
        "SENDGRID_API_KEY",
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    ),
]

DEFAULT_ALLOWLIST = {
    "your-access-token-here",
    "your-secret-here",
    "your-api-key",
    "your_token",
    "your_secret",
    "your_password",
    "your-password",
    "changeme",
    "change-me",
    "example_password",
    "example-password",
    "example_token",
    "example-token",
    "example_key",
    "example-key",
    "test_password",
    "test-password",
    "test_token",
    "test-token",
    "test_key",
    "test-key",
    "dummy_password",
    "dummy_token",
    "dummy_key",
    "xxxxxxxx",
    "xxxxxx",
    "xxx",
    "none",
    "null",
}

DEFAULT_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".pyo",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".ccrypt",
}


@dataclass
class ScanConfig:
    max_file_size: int = 1 * 1024 * 1024
    ignore_extensions: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_EXTENSIONS))
    allowlist: Set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWLIST))
    extra_patterns: List[Tuple[str, str, re.Pattern]] = field(default_factory=list)
    patterns_file: Optional[str] = None


def load_allowlist_from_file(allowlist_file: str) -> Set[str]:
    items = set()
    if not os.path.exists(allowlist_file):
        return items
    with open(allowlist_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.add(line.lower())
    return items


def _is_text_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in DEFAULT_IGNORE_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        if b"\x00" in chunk:
            return False
        chunk.decode("utf-8", errors="strict")
        return True
    except (OSError, UnicodeDecodeError):
        return False


def _read_text_lines(path: str) -> List[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.readlines()


def scan_file(
    file_path: str,
    base_dir: Optional[str] = None,
    config: Optional[ScanConfig] = None,
) -> List[SecretFinding]:
    config = config or ScanConfig()
    findings = []

    if os.path.getsize(file_path) > config.max_file_size:
        return findings
    ext = os.path.splitext(file_path)[1].lower()
    if ext in config.ignore_extensions:
        return findings
    if not _is_text_file(file_path):
        return findings

    rel = os.path.relpath(file_path, base_dir).replace("\\", "/") if base_dir else os.path.basename(file_path)

    patterns = SECRET_PATTERNS + config.extra_patterns
    try:
        lines = _read_text_lines(file_path)
    except OSError:
        return findings

    for line_idx, line in enumerate(lines, 1):
        line_lower = line.lower()
        allowlisted = any(allow.lower() in line_lower for allow in config.allowlist)
        if allowlisted:
            continue
        for secret_type, description, pattern in patterns:
            for match in pattern.finditer(line):
                matched = match.group(0)
                if matched.lower() in config.allowlist:
                    continue
                findings.append(SecretFinding(
                    file_path=file_path,
                    rel_path=rel,
                    line=line_idx,
                    secret_type=secret_type,
                    matched_text=matched,
                    description=description,
                ))
                break
    return findings


def scan_directory(
    dir_path: str,
    recursive: bool = True,
    base_dir: Optional[str] = None,
    config: Optional[ScanConfig] = None,
) -> List[SecretFinding]:
    config = config or ScanConfig()
    scan_base = base_dir or dir_path
    all_findings = []

    if recursive:
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules"}]
            for name in files:
                fpath = os.path.join(root, name)
                all_findings.extend(scan_file(fpath, scan_base, config))
    else:
        for entry in os.listdir(dir_path):
            fpath = os.path.join(dir_path, entry)
            if os.path.isfile(fpath):
                all_findings.extend(scan_file(fpath, scan_base, config))
    return all_findings
