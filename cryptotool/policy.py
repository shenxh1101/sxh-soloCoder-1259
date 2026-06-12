import configparser
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


def _pattern_to_regex(pattern: str) -> re.Pattern:
    pattern = pattern.strip()
    if pattern.startswith("/"):
        pattern = pattern[1:]
    regex_parts = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                regex_parts.append(".*")
                i += 2
                if i < len(pattern) and pattern[i] == "/":
                    i += 1
            else:
                regex_parts.append("[^/]*")
                i += 1
        elif c == "?":
            regex_parts.append("[^/]")
            i += 1
        elif c == ".":
            regex_parts.append(r"\.")
            i += 1
        elif c in "+()|^$[]{}":
            regex_parts.append("\\" + c)
            i += 1
        else:
            regex_parts.append(c)
            i += 1
    return re.compile("^" + "".join(regex_parts) + "(?:/.*)?$")


DEFAULT_POLICY_FILE = ".cryptpolicy"


class PolicyError(Exception):
    pass


@dataclass
class Policy:
    required: List[re.Pattern] = field(default_factory=list)
    allowed_plaintext: List[re.Pattern] = field(default_factory=list)
    ignore_extensions: Set[str] = field(default_factory=set)
    ignore_patterns: List[re.Pattern] = field(default_factory=list)
    sensitive_extensions: Set[str] = field(default_factory=set)
    source_file: Optional[str] = None

    def is_required(self, rel_path: str) -> bool:
        rel_path = rel_path.replace("\\", "/")
        if self.is_allowed_plaintext(rel_path):
            return False
        if self.should_ignore(rel_path):
            return False
        return self._matches_any(rel_path, self.required)

    def is_allowed_plaintext(self, rel_path: str) -> bool:
        rel_path = rel_path.replace("\\", "/")
        return self._matches_any(rel_path, self.allowed_plaintext)

    def should_ignore(self, rel_path: str) -> bool:
        rel_path = rel_path.replace("\\", "/")
        if self._matches_any(rel_path, self.ignore_patterns):
            return True
        ext = os.path.splitext(rel_path)[1].lower()
        return ext in self.ignore_extensions

    def _matches_any(self, rel_path: str, patterns: List[re.Pattern]) -> bool:
        for p in patterns:
            if p.match(rel_path) or p.match(os.path.basename(rel_path)):
                return True
        return False


def load_policy(
    policy_file: str = DEFAULT_POLICY_FILE,
    base_dir: Optional[str] = None,
) -> Policy:
    base = base_dir or os.getcwd()
    search_paths = []
    if os.path.isabs(policy_file):
        search_paths.append(policy_file)
    else:
        search_paths.append(os.path.join(base, policy_file))
        try:
            from .githooks import find_git_root
            git_root = find_git_root(base)
            if git_root and git_root != base:
                search_paths.append(os.path.join(git_root, policy_file))
        except Exception:
            pass

    found_path = None
    for p in search_paths:
        if os.path.exists(p):
            found_path = p
            break

    policy = Policy(source_file=found_path)

    _add_default_required(policy)
    _add_default_sensitive_extensions(policy)

    if not found_path:
        return policy

    config = configparser.ConfigParser(allow_no_value=True, interpolation=None)
    try:
        config.read(found_path, encoding="utf-8")
    except (configparser.Error, OSError) as e:
        raise PolicyError(f"读取策略文件失败 {found_path}: {e}") from e

    if config.has_section("policy"):
        _parse_section_list(
            config, "policy", "required", policy.required, _pattern_to_regex
        )
        _parse_section_list(
            config, "policy", "allowed_plaintext", policy.allowed_plaintext, _pattern_to_regex
        )
        _parse_section_list(
            config, "policy", "allowed-plaintext", policy.allowed_plaintext, _pattern_to_regex
        )
        _parse_section_set(
            config, "policy", "ignore_extensions", policy.ignore_extensions, _norm_ext
        )
        _parse_section_set(
            config, "policy", "ignore-extensions", policy.ignore_extensions, _norm_ext
        )
        _parse_section_list(
            config, "policy", "ignore_patterns", policy.ignore_patterns, _pattern_to_regex
        )
        _parse_section_list(
            config, "policy", "ignore-patterns", policy.ignore_patterns, _pattern_to_regex
        )
        _parse_section_set(
            config, "policy", "sensitive_extensions", policy.sensitive_extensions, _norm_ext
        )
        _parse_section_set(
            config, "policy", "sensitive-extensions", policy.sensitive_extensions, _norm_ext
        )

    return policy


def _add_default_required(policy: Policy) -> None:
    defaults = [
        ".env*",
        "**/*.env",
        "**/*.yaml",
        "**/*.yml",
        "**/*.pem",
        "**/*.key",
        "**/*.crt",
        "**/*.p12",
        "**/*.pfx",
        "**/*.jks",
        "**/*.kdbx",
        "id_rsa*",
        "id_ed25519*",
        "**/id_rsa",
        "**/id_ed25519",
    ]
    for p in defaults:
        try:
            policy.required.append(_pattern_to_regex(p))
        except re.error:
            pass


def _add_default_sensitive_extensions(policy: Policy) -> None:
    defaults = {
        ".pem", ".key", ".crt", ".p12", ".pfx", ".jks", ".kdbx",
    }
    policy.sensitive_extensions.update(defaults)


def _parse_section_list(
    config: configparser.ConfigParser,
    section: str,
    option: str,
    target: List,
    transform,
) -> None:
    if not config.has_option(section, option):
        return
    raw = config.get(section, option)
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            target.append(transform(line))
        except Exception:
            continue


def _parse_section_set(
    config: configparser.ConfigParser,
    section: str,
    option: str,
    target: Set,
    transform,
) -> None:
    if not config.has_option(section, option):
        return
    raw = config.get(section, option)
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        for item in line.split(","):
            item = item.strip()
            if item:
                try:
                    target.add(transform(item))
                except Exception:
                    continue


def _norm_ext(ext: str) -> str:
    ext = ext.strip().lower()
    if not ext.startswith("."):
        ext = "." + ext
    return ext
