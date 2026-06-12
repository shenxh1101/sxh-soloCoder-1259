import configparser
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


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
    _required_sources: List[str] = field(default_factory=list)
    _allowed_plaintext_sources: List[str] = field(default_factory=list)
    _ignore_pattern_sources: List[str] = field(default_factory=list)

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

    def _matches_any_with_reason(
        self, rel_path: str, patterns: List[re.Pattern], pattern_sources: List[str]
    ) -> Optional[str]:
        norm_path = rel_path.replace("\\", "/")
        base_name = os.path.basename(rel_path)
        for i, p in enumerate(patterns):
            if p.match(norm_path) or p.match(base_name):
                src = pattern_sources[i] if i < len(pattern_sources) else str(p.pattern)
                return src
        return None

    def _matches_any(self, rel_path: str, patterns: List[re.Pattern]) -> bool:
        for p in patterns:
            if p.match(rel_path) or p.match(os.path.basename(rel_path)):
                return True
        return False

    def explain(self, rel_path: str) -> Dict:
        norm_path = rel_path.replace("\\", "/")
        result = {
            "path": norm_path,
            "is_required": False,
            "is_allowed_plaintext": False,
            "should_ignore": False,
            "reasons": [],
            "final_verdict": "",
        }

        sources_req = getattr(self, "_required_sources", [])
        sources_allow = getattr(self, "_allowed_plaintext_sources", [])
        sources_ignore_pat = getattr(self, "_ignore_pattern_sources", [])

        reason_ignore = self._matches_any_with_reason(norm_path, self.ignore_patterns, sources_ignore_pat)
        ext = os.path.splitext(norm_path)[1].lower()
        if reason_ignore:
            result["should_ignore"] = True
            result["reasons"].append(f"匹配 ignore_patterns 规则: {reason_ignore}")
        elif ext in self.ignore_extensions:
            result["should_ignore"] = True
            result["reasons"].append(f"扩展名 {ext} 在 ignore_extensions 列表中")

        reason_allow = self._matches_any_with_reason(norm_path, self.allowed_plaintext, sources_allow)
        if reason_allow:
            result["is_allowed_plaintext"] = True
            result["reasons"].append(f"匹配 allowed_plaintext 规则: {reason_allow}")

        reason_req = self._matches_any_with_reason(norm_path, self.required, sources_req)
        if reason_req:
            if not result["is_allowed_plaintext"] and not result["should_ignore"]:
                result["is_required"] = True
                result["reasons"].append(f"匹配 required 规则: {reason_req}")
            else:
                result["reasons"].append(f"匹配 required 规则: {reason_req}（但被豁免）")

        if result["should_ignore"]:
            result["final_verdict"] = "忽略：不会被扫描或加密"
        elif result["is_allowed_plaintext"]:
            result["final_verdict"] = "允许明文：不会被标记为敏感"
        elif result["is_required"]:
            result["final_verdict"] = "必须加密：属于敏感文件"
        else:
            result["final_verdict"] = "非敏感：不在策略范围内"

        return result


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
            config, "policy", "required", policy.required, _pattern_to_regex,
            sources=policy._required_sources,
        )
        _parse_section_list(
            config, "policy", "allowed_plaintext", policy.allowed_plaintext, _pattern_to_regex,
            sources=policy._allowed_plaintext_sources,
        )
        _parse_section_list(
            config, "policy", "allowed-plaintext", policy.allowed_plaintext, _pattern_to_regex,
            sources=policy._allowed_plaintext_sources,
        )
        _parse_section_set(
            config, "policy", "ignore_extensions", policy.ignore_extensions, _norm_ext
        )
        _parse_section_set(
            config, "policy", "ignore-extensions", policy.ignore_extensions, _norm_ext
        )
        _parse_section_list(
            config, "policy", "ignore_patterns", policy.ignore_patterns, _pattern_to_regex,
            sources=policy._ignore_pattern_sources,
        )
        _parse_section_list(
            config, "policy", "ignore-patterns", policy.ignore_patterns, _pattern_to_regex,
            sources=policy._ignore_pattern_sources,
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
            policy._required_sources.append(p + " (默认规则)")
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
    sources: Optional[List] = None,
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
            if sources is not None:
                sources.append(line)
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


def generate_policy_template() -> str:
    return """# config-crypt 策略配置文件
# 用于定义哪些文件必须加密、哪些允许明文、哪些需要忽略
#
# 模式匹配规则（类 .gitignore）:
#   *       匹配单目录内任意字符（不包含 /）
#   **      匹配任意层级目录
#   ?       匹配单个字符
#   示例:   .env* 匹配 .env、.env.prod 等
#           **/*.yaml 匹配任意子目录下的 .yaml 文件
#           secrets/** 匹配 secrets 目录下的所有文件

[policy]

# required: 必须加密的文件路径（命中这些模式的文件会被 check/encrypt-dir/git hook 处理）
# 如果注释掉整个 required 部分，将使用内置默认规则（env/yaml/密钥文件等）
required =
    .env*
    **/*.yaml
    **/*.yml
    **/*.json
    **/*.toml
    **/*.ini
    # SSH / TLS 私钥
    **/*.pem
    **/*.key
    **/*.crt
    **/*.p12
    **/*.pfx
    id_rsa
    id_rsa.*
    id_ed25519
    id_ed25519.*
    # 敏感目录
    secrets/**
    private/**

# allowed_plaintext: 允许以明文存在的文件（即使命中 required 也不会被标记）
# 适合放示例文件、模板文件
allowed_plaintext =
    .env.example
    .env.sample
    .env.template
    **/config.example.yaml
    **/config.sample.yaml

# ignore_extensions: 忽略的文件扩展名（扫描、加密时全部跳过）
ignore_extensions =
    .md
    .txt
    .log
    .py
    .js
    .ts
    .go
    .rs
    .java
    .c
    .cpp
    .h
    .html
    .css
    .png
    .jpg
    .jpeg
    .gif
    .svg

# ignore_patterns: 忽略的路径模式（匹配这些模式的目录/文件全部跳过）
ignore_patterns =
    node_modules/**
    .git/**
    __pycache__/**
    dist/**
    build/**
    docs/**
    tests/**
    test/**

# sensitive_extensions: 额外的敏感文件扩展名（可选，通常无需修改）
# sensitive_extensions =
"""


def init_policy_file(output_path: str = DEFAULT_POLICY_FILE, force: bool = False) -> str:
    if os.path.exists(output_path) and not force:
        raise PolicyError(f"策略文件已存在: {output_path}（使用 --force 覆盖）")
    content = generate_policy_template()
    dir_path = os.path.dirname(os.path.abspath(output_path))
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path
