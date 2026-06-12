import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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
        else:
            format = "json"

    format = format.lower()
    if format == "json":
        content = report.to_json()
    elif format in ("markdown", "md"):
        content = report.to_markdown()
    else:
        raise ValueError(f"不支持的报告格式: {format}")

    dir_path = os.path.dirname(os.path.abspath(output_path))
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
