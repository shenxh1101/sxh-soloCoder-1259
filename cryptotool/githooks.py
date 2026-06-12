import enum
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .filehandler import DEFAULT_EXT, is_config_file, is_sensitive_file
from .policy import Policy, PolicyError, load_policy, _pattern_to_regex


HOOK_MARKER = "# >>> config-crypt pre-commit hook >>>"
HOOK_MARKER_END = "# <<< config-crypt pre-commit hook <<<"


class GitHookError(Exception):
    pass


class HookStatus(enum.Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    OTHER = "other"


def find_git_root(start_path: Optional[str] = None) -> str:
    path = Path(start_path or os.getcwd()).resolve()
    while True:
        if (path / ".git").exists():
            return str(path)
        parent = path.parent
        if parent == path:
            raise GitHookError("未找到 git 仓库")
        path = parent


def get_staged_files(git_root: Optional[str] = None) -> List[str]:
    root = find_git_root(git_root)
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise GitHookError(f"获取暂存文件列表失败: {e}") from e

    files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
    return [str(Path(root) / f) for f in files]


def _is_ignored(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def load_patterns(patterns_file: str) -> List[re.Pattern]:
    if not os.path.exists(patterns_file):
        return []
    patterns = []
    try:
        with open(patterns_file, "r", encoding="utf-8") as f:
            for line in f:
                if _is_ignored(line):
                    continue
                p = line.rstrip("\n").rstrip("\r")
                if not p:
                    continue
                try:
                    patterns.append(_pattern_to_regex(p))
                except re.error:
                    continue
    except OSError as e:
        raise GitHookError(f"读取模式文件失败: {e}") from e
    return patterns


def match_sensitive_files(
    files: List[str],
    patterns: List[re.Pattern],
    git_root: Optional[str] = None,
    policy: Optional[Policy] = None,
) -> List[str]:
    root = Path(find_git_root(git_root))
    matched = []
    for f in files:
        try:
            rel = os.path.relpath(f, str(root)).replace("\\", "/")
        except ValueError:
            continue
        if policy and policy.should_ignore(rel):
            continue
        if policy and policy.is_allowed_plaintext(rel):
            continue
        if f.endswith(DEFAULT_EXT):
            continue
        if policy and policy.is_required(rel):
            matched.append(f)
            continue
        if any(p.match(rel) for p in patterns):
            matched.append(f)
        elif is_sensitive_file(f) and not f.endswith(DEFAULT_EXT):
            matched.append(f)
    return matched


def generate_hook_script(
    patterns_file: str = ".cryptignore",
    key_file: Optional[str] = None,
    policy_file: str = ".cryptpolicy",
) -> str:
    patterns_arg = shlex.quote(patterns_file)
    policy_arg = shlex.quote(policy_file)
    if key_file:
        abs_key_file = os.path.abspath(key_file)
        key_file_arg = repr(abs_key_file)
        key_file_quoted = shlex.quote(abs_key_file)
    else:
        key_file_arg = "None"
        key_file_quoted = '""'

    script = f'''\
#!/usr/bin/env python3
"""config-crypt pre-commit hook: 自动加密敏感配置文件"""
import os
import subprocess
import sys

{HOOK_MARKER}

def run():
    try:
        repo_root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True
        ).strip()
    except Exception as e:
        print(f"[config-crypt] 错误: 无法确定仓库根目录: {{e}}", file=sys.stderr)
        return 1

    os.chdir(repo_root)

    patterns_file = {patterns_arg!r}
    policy_file = {policy_arg!r}
    key_file = {key_file_arg}

    try:
        cmd = [sys.executable, "-m", "cryptotool.cli", "git-hook", "_precommit"]
        if os.path.exists(patterns_file):
            cmd.extend(["--patterns-file", patterns_file])
        if os.path.exists(policy_file):
            cmd.extend(["--policy-file", policy_file])
        if key_file is not None:
            if not os.path.isabs(key_file):
                key_file = os.path.join(repo_root, key_file)
            if os.path.exists(key_file):
                cmd.extend(["-k", key_file])
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    except Exception as e:
        print(f"[config-crypt] hook 执行失败: {{e}}", file=sys.stderr)
        return 1

{HOOK_MARKER_END}

if __name__ == "__main__":
    sys.exit(run())
'''
    return script


def install_hook(
    hook_path: str = ".git/hooks/pre-commit",
    patterns_file: str = ".cryptignore",
    key_file: Optional[str] = None,
    policy_file: str = ".cryptpolicy",
    force: bool = False,
) -> None:
    try:
        root = find_git_root()
    except GitHookError:
        root = os.getcwd()

    abs_hook_path = os.path.abspath(hook_path)
    if not os.path.isabs(hook_path):
        abs_hook_path = os.path.join(root, hook_path)

    if os.path.exists(abs_hook_path) and not force:
        status = check_hook(abs_hook_path)
        if status == HookStatus.OTHER:
            raise GitHookError(
                f"hook 文件已存在且由其他程序管理: {abs_hook_path}\n"
                f"使用 --force 覆盖，或手动合并 hook 内容"
            )

    hook_dir = os.path.dirname(abs_hook_path)
    if hook_dir and not os.path.exists(hook_dir):
        os.makedirs(hook_dir, exist_ok=True)

    script = generate_hook_script(
        patterns_file=patterns_file,
        key_file=key_file,
        policy_file=policy_file,
    )

    if os.path.exists(abs_hook_path):
        with open(abs_hook_path, "r", encoding="utf-8") as f:
            existing = f.read()
        if HOOK_MARKER in existing:
            start = existing.index(HOOK_MARKER)
            end = existing.index(HOOK_MARKER_END) + len(HOOK_MARKER_END)
            while end < len(existing) and existing[end] in "\r\n":
                end += 1
            new_content = existing[:start] + script.strip() + "\n" + existing[end:]
        else:
            new_content = existing.rstrip() + "\n\n" + script.strip() + "\n"
    else:
        new_content = script

    with open(abs_hook_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    try:
        st = os.stat(abs_hook_path)
        os.chmod(abs_hook_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def uninstall_hook(hook_path: str = ".git/hooks/pre-commit") -> None:
    try:
        root = find_git_root()
    except GitHookError:
        root = os.getcwd()

    abs_hook_path = os.path.abspath(hook_path)
    if not os.path.isabs(hook_path):
        abs_hook_path = os.path.join(root, hook_path)

    if not os.path.exists(abs_hook_path):
        raise GitHookError(f"hook 文件不存在: {abs_hook_path}")

    with open(abs_hook_path, "r", encoding="utf-8") as f:
        content = f.read()

    if HOOK_MARKER not in content:
        raise GitHookError(
            f"hook 文件不是由 config-crypt 安装，无法自动卸载: {abs_hook_path}"
        )

    start = content.index(HOOK_MARKER)
    pre = content[:start].rstrip()

    end_idx = content.index(HOOK_MARKER_END) + len(HOOK_MARKER_END)
    while end_idx < len(content) and content[end_idx] in "\r\n":
        end_idx += 1
    post = content[end_idx:].lstrip("\r\n")

    new_content = ""
    if pre:
        new_content += pre + "\n"
    if post:
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"
        new_content += post

    if new_content.strip():
        with open(abs_hook_path, "w", encoding="utf-8") as f:
            f.write(new_content)
    else:
        os.remove(abs_hook_path)


def check_hook(hook_path: str = ".git/hooks/pre-commit") -> HookStatus:
    try:
        root = find_git_root()
    except GitHookError:
        root = os.getcwd()

    abs_hook_path = os.path.abspath(hook_path)
    if not os.path.isabs(hook_path):
        abs_hook_path = os.path.join(root, hook_path)

    if not os.path.exists(abs_hook_path):
        return HookStatus.NOT_INSTALLED

    try:
        with open(abs_hook_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return HookStatus.OTHER

    if HOOK_MARKER in content:
        return HookStatus.INSTALLED
    return HookStatus.OTHER


def precommit_hook_impl(
    patterns_file: str = ".cryptignore",
    key_file: Optional[str] = None,
    policy_file: str = ".cryptpolicy",
) -> int:
    from .keymanager import resolve_key, KeyManagerError
    from .filehandler import encrypt_file, FileHandlerError

    try:
        root = find_git_root()
    except GitHookError as e:
        print(f"[config-crypt] 错误: {e}", file=sys.stderr)
        return 1

    try:
        staged = get_staged_files(root)
    except GitHookError as e:
        print(f"[config-crypt] 警告: {e}", file=sys.stderr)
        return 0

    patterns = load_patterns(patterns_file) if os.path.exists(patterns_file) else []
    try:
        policy = load_policy(policy_file, base_dir=root)
    except PolicyError as e:
        print(f"[config-crypt] 警告: {e}", file=sys.stderr)
        policy = None
    sensitive = match_sensitive_files(staged, patterns, root, policy=policy)

    if not sensitive:
        return 0

    print(f"[config-crypt] 检测到 {len(sensitive)} 个明文敏感文件，正在自动加密并阻止明文提交...")
    for f in sensitive:
        print(f"  ⚠  {os.path.relpath(f, root)}")

    try:
        mode, key_or_pwd = resolve_key(
            password=None,
            key_file=key_file,
            env_key="CONFIG_CRYPT_KEY",
            need_confirm=False,
        )
    except KeyManagerError as e:
        print(
            f"[config-crypt] 错误: 无法获取密钥 ({e})\n"
            f"  请设置环境变量 CONFIG_CRYPT_KEY=file:///path/to/key\n"
            f"  或在安装 hook 时使用 -k 指定密钥文件",
            file=sys.stderr,
        )
        print(
            f"[config-crypt] 提交被阻止：存在 {len(sensitive)} 个明文敏感文件未加密",
            file=sys.stderr,
        )
        _unstage_files(root, sensitive)
        return 1

    failed = []
    encrypted_files = []
    success_plaintext = []

    for f in sensitive:
        if mode == "keyfile":
            res = encrypt_file(f, key=key_or_pwd, force=True)
        else:
            res = encrypt_file(f, password=key_or_pwd, force=True)

        if res.success:
            print(f"  ✓ {os.path.relpath(f, root)} → {os.path.relpath(res.target, root)}")
            encrypted_files.append(res.target)
            success_plaintext.append(f)
        else:
            print(f"  ✗ {os.path.relpath(f, root)}: {res.error}", file=sys.stderr)
            failed.append(f)

    if encrypted_files:
        try:
            subprocess.run(
                ["git", "add"] + encrypted_files,
                cwd=root,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"[config-crypt] 警告: git add 加密文件失败: {e}", file=sys.stderr)

    _unstage_files(root, sensitive)

    if failed:
        print(
            f"[config-crypt] 提交被阻止：{len(failed)} 个文件加密失败，"
            f"{len(sensitive)} 个明文文件已从暂存区移除",
            file=sys.stderr,
        )
        return 1

    print(
        f"[config-crypt] 已自动加密 {len(encrypted_files)} 个文件，"
        f"明文文件已从暂存区移除（加密版本已加入暂存区）"
    )
    return 0


def _unstage_files(root: str, files: List[str]) -> None:
    if not files:
        return
    rels = [os.path.relpath(f, root) for f in files]
    try:
        subprocess.run(
            ["git", "reset", "HEAD", "--"] + rels,
            cwd=root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[config-crypt] 警告: 从暂存区移除明文文件失败: {e}", file=sys.stderr)
