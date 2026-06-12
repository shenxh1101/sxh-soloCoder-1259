import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AuditFileItem:
    path: str
    rel_path: str
    status: str
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    command: str
    scan_root: str
    started_at: str
    completed_at: Optional[str] = None
    total_files: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    files: List[AuditFileItem] = field(default_factory=list)
    policy_file: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def add_file(self, item: AuditFileItem) -> None:
        self.files.append(item)
        self.total_files += 1
        if item.status == "passed":
            self.passed += 1
        elif item.status == "failed":
            self.failed += 1
        elif item.status == "skipped":
            self.skipped += 1

    def mark_completed(self) -> None:
        self.completed_at = _now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "scan_root": self.scan_root,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "summary": {
                "total": self.total_files,
                "passed": self.passed,
                "failed": self.failed,
                "skipped": self.skipped,
            },
            "policy_file": self.policy_file,
            "files": [asdict(f) for f in self.files],
            "extra": self.extra,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_sarif(self) -> Dict[str, Any]:
        from .secretscan import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

        SARIF_RULES = [
            {
                "id": "CC001",
                "name": "PlaintextSensitiveFile",
                "shortDescription": {"text": "发现明文敏感文件，需要加密"},
                "fullDescription": {"text": "文件命中敏感规则但以明文形式存在，应使用 config-crypt encrypt 加密后再提交。"},
                "help": {"text": "使用 config-crypt encrypt <file> 加密该文件，或在策略中添加到 allowed_plaintext。"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "CC002",
                "name": "HighSeveritySecret",
                "shortDescription": {"text": "发现高危密钥（云厂商密钥、私钥、平台Token）"},
                "fullDescription": {"text": "在文件内容中发现了高危敏感信息，可能导致账号被入侵、资源被盗用。"},
                "help": {"text": "立即旋转该密钥，并从代码中移除，使用环境变量或密钥管理服务。"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "CC003",
                "name": "MediumSeveritySecret",
                "shortDescription": {"text": "发现中危密钥（JWT、通用密码赋值）"},
                "fullDescription": {"text": "在文件内容中发现了中危敏感信息，可能导致账户或服务被盗用。"},
                "help": {"text": "立即撤销该密钥，并从代码中移除，使用更安全的配置方式。"},
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "CC004",
                "name": "LowSeveritySecret",
                "shortDescription": {"text": "发现低危密钥"},
                "fullDescription": {"text": "在文件内容中发现了低危敏感信息。"},
                "help": {"text": "请检查该信息是否真的是敏感信息，如属实请移除。"},
                "defaultConfiguration": {"level": "note"},
            },
        ]
        RULE_MAP = {r["id"]: r for r in SARIF_RULES}

        def _rule_and_level(f: AuditFileItem) -> Tuple[str, str]:
            sev = f.details.get("severity")
            if sev == SEVERITY_HIGH:
                return "CC002", "error"
            elif sev == SEVERITY_MEDIUM:
                return "CC003", "warning"
            elif sev == SEVERITY_LOW:
                return "CC004", "note"
            return "CC001", "error"

        results = []
        used_rule_ids = set()
        for f in self.files:
            if f.status != "failed":
                continue
            rule_id, level = _rule_and_level(f)
            used_rule_ids.add(rule_id)
            start_line = f.details.get("line", 1)
            message = f.reason or "敏感文件"
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.rel_path},
                        "region": {"startLine": start_line},
                    },
                }],
            })

        active_rules = [RULE_MAP[rid] for rid in sorted(used_rule_ids)] if used_rule_ids else SARIF_RULES

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "config-crypt",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/config-crypt/config-crypt",
                            "rules": active_rules,
                        },
                    },
                    "invocations": [
                        {
                            "commandLine": self.command,
                            "startTimeUtc": self.started_at,
                            "endTimeUtc": self.completed_at or self.started_at,
                            "executionSuccessful": True,
                        },
                    ],
                    "results": results,
                },
            ],
        }

    def to_markdown(self) -> str:
        lines = []
        lines.append(f"# config-crypt 审计报告 - {self.command}")
        lines.append("")
        lines.append(f"- **扫描根目录**: `{self.scan_root}`")
        lines.append(f"- **开始时间**: {self.started_at}")
        lines.append(f"- **完成时间**: {self.completed_at or '未完成'}")
        if self.policy_file:
            lines.append(f"- **策略文件**: `{self.policy_file}`")
        lines.append("")
        lines.append("## 汇总")
        lines.append("")
        lines.append("| 类别 | 数量 |")
        lines.append("|------|------|")
        lines.append(f"| 总计 | {self.total_files} |")
        lines.append(f"| ✅ 通过 | {self.passed} |")
        lines.append(f"| ❌ 失败 | {self.failed} |")
        lines.append(f"| ⏭️  跳过 | {self.skipped} |")
        lines.append("")

        if self.files:
            lines.append("## 详细信息")
            lines.append("")
            lines.append("| 文件 | 状态 | 说明 |")
            lines.append("|------|------|------|")
            for f in self.files:
                status_icon = "✅" if f.status == "passed" else "❌" if f.status == "failed" else "⏭️"
                reason = f.reason or ""
                lines.append(f"| `{f.rel_path}` | {status_icon} {f.status} | {reason} |")
            lines.append("")

        if self.extra:
            lines.append("## 额外信息")
            lines.append("")
            for k, v in self.extra.items():
                lines.append(f"- **{k}**: {v}")
            lines.append("")

        return "\n".join(lines)


def create_report(command: str, scan_root: str, policy_file: Optional[str] = None) -> AuditReport:
    return AuditReport(
        command=command,
        scan_root=scan_root,
        started_at=_now_iso(),
        policy_file=policy_file,
    )


def write_report(report: AuditReport, output_path: str, format: Optional[str] = None) -> str:
    if format is None:
        ext = os.path.splitext(output_path)[1].lower()
        if ext == ".json":
            format = "json"
        elif ext in (".md", ".markdown"):
            format = "markdown"
        elif ext == ".sarif":
            format = "sarif"
        else:
            format = "json"

    format = format.lower()
    if format == "json":
        content = report.to_json()
    elif format in ("markdown", "md"):
        content = report.to_markdown()
    elif format == "sarif":
        content = json.dumps(report.to_sarif(), indent=2, ensure_ascii=False)
    else:
        raise ValueError(f"不支持的报告格式: {format}")

    dir_path = os.path.dirname(os.path.abspath(output_path))
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def diff_reports(current: AuditReport, previous: AuditReport) -> Tuple[Set[str], Set[str], Set[str]]:
    curr_failed = {f.rel_path for f in current.files if f.status == "failed"}
    prev_failed = {f.rel_path for f in previous.files if f.status == "failed"}
    added = curr_failed - prev_failed
    removed = prev_failed - curr_failed
    unchanged = curr_failed & prev_failed
    return added, removed, unchanged


def filter_report_by_new(current: AuditReport, previous: AuditReport) -> AuditReport:
    added, _, _ = diff_reports(current, previous)
    new_files = [f for f in current.files if f.status != "failed" or f.rel_path in added]
    new_report = AuditReport(
        command=current.command + " (diff)",
        scan_root=current.scan_root,
        started_at=current.started_at,
        completed_at=current.completed_at,
        files=new_files,
        policy_file=current.policy_file,
        extra={
            **current.extra,
            "diff_with": previous.started_at,
            "new_failures_only": True,
            "new_failed_count": len(added),
        },
    )
    for f in new_files:
        new_report.total_files += 1
        if f.status == "passed":
            new_report.passed += 1
        elif f.status == "failed":
            new_report.failed += 1
        elif f.status == "skipped":
            new_report.skipped += 1
    return new_report


def _is_sarif(data: Dict) -> bool:
    return data.get("version") == "2.1.0" and "runs" in data


def _parse_sarif(data: Dict) -> AuditReport:
    run = data["runs"][0]
    results = run.get("results", [])
    invocation = run.get("invocations", [{}])[0]
    driver = run["tool"]["driver"]

    files = []
    failed_paths = set()
    for r in results:
        level = r.get("level", "error")
        status = "failed" if level in ("error", "warning") else "passed"
        for loc in r.get("locations", []):
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            if not uri:
                continue
            failed_paths.add(uri)
            files.append(AuditFileItem(
                path=uri,
                rel_path=uri,
                status=status,
                reason=r.get("message", {}).get("text", ""),
                details={"rule_id": r.get("ruleId", ""), "level": level},
            ))

    return AuditReport(
        command=driver.get("name", "unknown"),
        scan_root="",
        started_at=invocation.get("startTimeUtc", ""),
        completed_at=invocation.get("endTimeUtc", ""),
        total_files=len(results),
        passed=0,
        failed=len(files),
        skipped=0,
        files=files,
        policy_file=None,
        extra={"format": "sarif"},
    )


def load_report(path: str) -> AuditReport:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if _is_sarif(data):
        return _parse_sarif(data)

    files = [
        AuditFileItem(
            path=item["path"],
            rel_path=item["rel_path"],
            status=item["status"],
            reason=item.get("reason"),
            details=item.get("details", {}),
        )
        for item in data.get("files", [])
    ]
    summary = data.get("summary", {})
    return AuditReport(
        command=data.get("command", "unknown"),
        scan_root=data.get("scan_root", ""),
        started_at=data.get("started_at", ""),
        completed_at=data.get("completed_at"),
        total_files=summary.get("total", len(files)),
        passed=summary.get("passed", 0),
        failed=summary.get("failed", 0),
        skipped=summary.get("skipped", 0),
        files=files,
        policy_file=data.get("policy_file"),
        extra=data.get("extra", {}),
    )


def save_baseline(report: AuditReport, baseline_path: str) -> str:
    out = report.to_dict()
    dir_path = os.path.dirname(os.path.abspath(baseline_path))
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return baseline_path


def get_baseline_path(scan_root: str, command: str) -> str:
    return os.path.join(scan_root, f".crypt-baseline-{command}.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
