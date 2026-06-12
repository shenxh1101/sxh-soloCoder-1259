import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .crypto import CryptoError, PasswordError, TamperedError, VersionError
from .keymanager import KeyManagerError, resolve_key, write_key_file
from .filehandler import (
    FileHandlerError,
    DEFAULT_EXT,
    encrypt_file,
    decrypt_file,
    encrypt_directory_bulk,
    decrypt_directory_bulk,
    encrypt_directory_archive,
    decrypt_directory_archive,
    collect_files,
    verify_file,
    verify_directory_bulk,
    rekey_file,
    rekey_directory_bulk,
    match_sensitive_files_local,
)
from .policy import Policy, PolicyError, load_policy
from .audit import AuditFileItem, AuditReport, create_report, write_report
from . import githooks
from .githooks import (
    get_staged_files,
    match_sensitive_files,
    load_patterns,
    find_git_root,
    GitHookError,
)


def add_key_args(parser: argparse.ArgumentParser, for_encrypt: bool = False) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p",
        "--password",
        help="使用密码加密/解密（不推荐在命令行明文传入，建议省略以交互输入）",
    )
    group.add_argument(
        "-k",
        "--key-file",
        help="使用二进制密钥文件（32字节）",
    )
    parser.add_argument(
        "--env-key",
        default="CONFIG_CRYPT_KEY",
        help="环境变量名称，可存放密钥文件路径(file://...)或64字符十六进制密钥",
    )


def add_old_key_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--old-password", help="旧密码")
    group.add_argument("--old-key-file", help="旧密钥文件路径")
    parser.add_argument(
        "--old-env-key",
        default="CONFIG_CRYPT_OLD_KEY",
        help="旧密钥环境变量名称",
    )


def add_new_key_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--new-password", help="新密码")
    group.add_argument("--new-key-file", help="新密钥文件路径")
    parser.add_argument(
        "--new-env-key",
        default="CONFIG_CRYPT_NEW_KEY",
        help="新密钥环境变量名称",
    )


def add_audit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--report",
        help="输出审计报告到指定文件",
    )
    parser.add_argument(
        "--report-format",
        choices=["json", "markdown", "md"],
        default=None,
        help="报告格式（默认根据扩展名自动识别）",
    )


def add_policy_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-file",
        default=".cryptpolicy",
        help="策略配置文件路径（定义必须加密、允许明文、忽略的规则）",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="config-crypt",
        description="AES-256-GCM 配置文件加密/解密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 加密单个文件（交互式输入密码）
  config-crypt encrypt .env

  # 解密单个文件（使用密钥文件）
  config-crypt decrypt .env.ccrypt -k ~/.keys/my.key

  # 批量加密目录内所有配置文件
  config-crypt encrypt-dir ./configs

  # 将整个目录打包成单一加密存档
  config-crypt archive ./configs -o configs.ccrypt

  # 从加密存档恢复目录
  config-crypt unarchive configs.ccrypt -o ./configs

  # 生成密钥文件
  config-crypt gen-key -k ~/.keys/my.key

  # 安装 git pre-commit hook
  config-crypt git-hook install
""",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_enc = sub.add_parser("encrypt", help="加密单个文件")
    p_enc.add_argument("input", help="要加密的文件路径")
    p_enc.add_argument("-o", "--output", help="输出加密文件路径（默认追加 .ccrypt）")
    p_enc.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_enc, for_encrypt=True)

    p_dec = sub.add_parser("decrypt", help="解密单个文件")
    p_dec.add_argument("input", help="要解密的加密文件（.ccrypt）")
    p_dec.add_argument("-o", "--output", help="输出明文文件路径")
    p_dec.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_dec)

    p_encd = sub.add_parser("encrypt-dir", help="批量加密目录内的配置文件")
    p_encd.add_argument("directory", help="目标目录")
    p_encd.add_argument("-o", "--output-dir", help="输出目录（默认在原目录内）")
    p_encd.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_encd.add_argument("--all-files", action="store_true", help="加密所有文件，不限于配置文件")
    p_encd.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_encd, for_encrypt=True)
    add_policy_arg(p_encd)

    p_decd = sub.add_parser("decrypt-dir", help="批量解密目录内的加密文件")
    p_decd.add_argument("directory", help="目标目录")
    p_decd.add_argument("-o", "--output-dir", help="输出目录（默认在原目录内）")
    p_decd.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_decd.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_decd)

    p_arch = sub.add_parser("archive", help="将目录打包并加密为单一存档文件")
    p_arch.add_argument("directory", help="要打包的目录")
    p_arch.add_argument("-o", "--output", required=True, help="输出加密存档路径")
    p_arch.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_arch, for_encrypt=True)

    p_unarch = sub.add_parser("unarchive", help="解密并展开加密存档到目录")
    p_unarch.add_argument("input", help="加密存档文件")
    p_unarch.add_argument("-o", "--output", required=True, help="输出目录")
    p_unarch.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    add_key_args(p_unarch)

    p_key = sub.add_parser("gen-key", help="生成随机二进制密钥文件")
    p_key.add_argument("-k", "--key-file", required=True, help="密钥文件输出路径")
    p_key.add_argument("-f", "--force", action="store_true", help="覆盖已存在的密钥文件")

    p_ver = sub.add_parser("verify", help="校验加密文件/目录完整性与密钥正确性，不解密明文")
    p_ver.add_argument("path", help="加密文件或目录路径")
    p_ver.add_argument("--no-recursive", action="store_true", help="目录时不递归子目录")
    add_key_args(p_ver)
    add_audit_args(p_ver)
    add_policy_arg(p_ver)

    p_rekey = sub.add_parser("rekey", help="更换加密文件/目录的密码或密钥，不破坏明文内容")
    p_rekey.add_argument("path", help="加密文件或目录路径")
    p_rekey.add_argument("--no-recursive", action="store_true", help="目录时不递归子目录")
    p_rekey.add_argument("--dry-run", action="store_true", help="只列出将被迁移的文件，不实际执行")
    p_rekey.add_argument("--backup", action="store_true", help="执行前为每个文件创建 .bak 备份，失败时可恢复")
    add_old_key_args(p_rekey)
    add_new_key_args(p_rekey)
    add_policy_arg(p_rekey)

    p_check = sub.add_parser("check", help="扫描目录或 git 暂存区，找出明文敏感文件")
    p_check.add_argument("path", nargs="?", default=".", help="要扫描的目录（默认当前目录）")
    p_check.add_argument("--staged", action="store_true", help="扫描 git 暂存区而非文件系统")
    p_check.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_check.add_argument(
        "--patterns-file",
        default=".cryptignore",
        help="额外敏感文件模式配置（类 .gitignore 语法）",
    )
    p_check.add_argument(
        "--fail",
        action="store_true",
        help="发现敏感文件时以非零退出码返回（用于 CI）",
    )
    add_audit_args(p_check)
    add_policy_arg(p_check)

    p_hook = sub.add_parser("git-hook", help="Git hooks 集成管理")
    hook_sub = p_hook.add_subparsers(dest="hook_action", required=True, metavar="ACTION")
    p_install = hook_sub.add_parser("install", help="安装 pre-commit hook，自动加密敏感文件")
    p_install.add_argument("--hook-path", default=".git/hooks/pre-commit", help="hook 文件路径")
    p_install.add_argument(
        "--patterns-file",
        default=".cryptignore",
        help="敏感文件模式配置文件（类.gitignore 语法）",
    )
    p_install.add_argument("-k", "--key-file", help="使用密钥文件（推荐，避免 CI 交互）")
    p_install.add_argument("--policy-file", default=".cryptpolicy", help="策略配置文件")
    p_install.add_argument("-f", "--force", action="store_true", help="覆盖已存在的 hook")
    p_uninstall = hook_sub.add_parser("uninstall", help="卸载 pre-commit hook")
    p_uninstall.add_argument("--hook-path", default=".git/hooks/pre-commit", help="hook 文件路径")
    p_status = hook_sub.add_parser("status", help="检查 hook 安装状态")
    p_status.add_argument("--hook-path", default=".git/hooks/pre-commit", help="hook 文件路径")
    p_precommit = hook_sub.add_parser("_precommit", help=argparse.SUPPRESS)
    p_precommit.add_argument("--patterns-file", default=".cryptignore")
    p_precommit.add_argument("--policy-file", default=".cryptpolicy")
    p_precommit.add_argument("-k", "--key-file", default=None)

    p_list = sub.add_parser("list", help="列出目录内匹配的配置/加密文件")
    p_list.add_argument("directory", default=".", nargs="?", help="目标目录")
    p_list.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_list.add_argument("--encrypted", action="store_true", help="列出加密文件而非配置文件")

    return parser


def print_results_enc(results: List) -> int:
    total = len(results)
    ok = sum(1 for r in results if r.success)
    fail = total - ok
    for r in results:
        if r.success:
            print(f"  ✓ {r.source} → {r.target}")
        else:
            print(f"  ✗ {r.source} → {r.target}: {r.error}", file=sys.stderr)
    print(f"\n完成: 成功 {ok} 个，失败 {fail} 个，共 {total} 个")
    return 0 if fail == 0 else 1


def cmd_encrypt(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=True,
    )
    if mode == "keyfile":
        res = encrypt_file(args.input, args.output, key=key_or_pwd, force=args.force)
    else:
        res = encrypt_file(args.input, args.output, password=key_or_pwd, force=args.force)
    return print_results_enc([res])


def cmd_decrypt(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=False,
    )
    if mode == "keyfile":
        res = decrypt_file(args.input, args.output, key=key_or_pwd, force=args.force)
    else:
        res = decrypt_file(args.input, args.output, password=key_or_pwd, force=args.force)
    return print_results_enc([res])


def cmd_encrypt_dir(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=True,
    )
    try:
        policy = load_policy(args.policy_file, base_dir=args.directory)
    except PolicyError as e:
        print(f"警告: {e}", file=sys.stderr)
        policy = None

    if mode == "keyfile":
        results = encrypt_directory_bulk(
            args.directory,
            args.output_dir,
            key=key_or_pwd,
            recursive=not args.no_recursive,
            config_only=not args.all_files,
            force=args.force,
            policy=policy,
        )
    else:
        results = encrypt_directory_bulk(
            args.directory,
            args.output_dir,
            password=key_or_pwd,
            recursive=not args.no_recursive,
            config_only=not args.all_files,
            force=args.force,
            policy=policy,
        )
    return print_results_enc(results)


def cmd_decrypt_dir(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=False,
    )
    if mode == "keyfile":
        results = decrypt_directory_bulk(
            args.directory,
            args.output_dir,
            key=key_or_pwd,
            recursive=not args.no_recursive,
            force=args.force,
        )
    else:
        results = decrypt_directory_bulk(
            args.directory,
            args.output_dir,
            password=key_or_pwd,
            recursive=not args.no_recursive,
            force=args.force,
        )
    return print_results_enc(results)


def cmd_archive(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=True,
    )
    if mode == "keyfile":
        res = encrypt_directory_archive(
            args.directory, args.output, key=key_or_pwd, force=args.force
        )
    else:
        res = encrypt_directory_archive(
            args.directory, args.output, password=key_or_pwd, force=args.force
        )
    return print_results_enc([res])


def cmd_unarchive(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=False,
    )
    if mode == "keyfile":
        res = decrypt_directory_archive(
            args.input, args.output, key=key_or_pwd, force=args.force
        )
    else:
        res = decrypt_directory_archive(
            args.input, args.output, password=key_or_pwd, force=args.force
        )
    return print_results_enc([res])


def cmd_gen_key(args) -> int:
    try:
        key = write_key_file(args.key_file, force=args.force)
        print(f"已生成密钥文件: {args.key_file} ({len(key)} 字节)")
        print(f"请妥善保管此文件，丢失将无法解密！")
        return 0
    except KeyManagerError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1


def cmd_verify(args) -> int:
    mode, key_or_pwd = resolve_key(
        password=args.password,
        key_file=args.key_file,
        env_key=args.env_key,
        need_confirm=False,
    )
    try:
        policy_base = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."
        policy = load_policy(args.policy_file, base_dir=policy_base)
    except PolicyError as e:
        print(f"警告: {e}", file=sys.stderr)
        policy = None

    if os.path.isdir(args.path):
        scan_root = args.path
        report = create_report(
            command="verify",
            scan_root=scan_root,
            policy_file=policy.source_file if policy else None,
        )
        if mode == "keyfile":
            results = verify_directory_bulk(
                args.path, key=key_or_pwd, recursive=not args.no_recursive, policy=policy
            )
        else:
            results = verify_directory_bulk(
                args.path, password=key_or_pwd, recursive=not args.no_recursive, policy=policy
            )
        total = len(results)
        ok = sum(1 for r in results if r.success)
        fail = total - ok
        for r in results:
            rel = os.path.relpath(r.source, scan_root)
            if r.success:
                print(f"  ✓ {r.source}")
                report.add_file(AuditFileItem(
                    path=r.source, rel_path=rel, status="passed", reason="校验通过",
                ))
            else:
                print(f"  ✗ {r.source}: {r.error}", file=sys.stderr)
                report.add_file(AuditFileItem(
                    path=r.source, rel_path=rel, status="failed", reason=str(r.error),
                ))
        print(f"\n校验完成: 通过 {ok}，失败 {fail}，共 {total} 个")
        report.mark_completed()
        if args.report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return 0 if fail == 0 else 1
    else:
        scan_root = os.path.dirname(args.path) or "."
        report = create_report(
            command="verify",
            scan_root=scan_root,
            policy_file=policy.source_file if policy else None,
        )
        if mode == "keyfile":
            r = verify_file(args.path, key=key_or_pwd)
        else:
            r = verify_file(args.path, password=key_or_pwd)
        rel = os.path.basename(args.path)
        if r.success:
            print(f"  ✓ {r.source}: 校验通过")
            report.add_file(AuditFileItem(
                path=r.source, rel_path=rel, status="passed", reason="校验通过",
            ))
            rc = 0
        else:
            print(f"  ✗ {r.source}: {r.error}", file=sys.stderr)
            report.add_file(AuditFileItem(
                path=r.source, rel_path=rel, status="failed", reason=str(r.error),
            ))
            rc = 1
        report.mark_completed()
        if args.report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return rc


def cmd_rekey(args) -> int:
    old_mode, old_val = resolve_key(
        password=getattr(args, "old_password", None),
        key_file=getattr(args, "old_key_file", None),
        env_key=getattr(args, "old_env_key", "CONFIG_CRYPT_OLD_KEY"),
        need_confirm=False,
    )
    new_mode, new_val = resolve_key(
        password=getattr(args, "new_password", None),
        key_file=getattr(args, "new_key_file", None),
        env_key=getattr(args, "new_env_key", "CONFIG_CRYPT_NEW_KEY"),
        need_confirm=True,
    )

    try:
        policy_base = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."
        policy = load_policy(args.policy_file, base_dir=policy_base)
    except PolicyError as e:
        print(f"警告: {e}", file=sys.stderr)
        policy = None

    old_kwargs = {"old_key": old_val} if old_mode == "keyfile" else {"old_password": old_val}
    new_kwargs = {"new_key": new_val} if new_mode == "keyfile" else {"new_password": new_val}
    kwargs = {**old_kwargs, **new_kwargs}

    dry_run = getattr(args, "dry_run", False)
    backup = getattr(args, "backup", False)

    if dry_run:
        print("(DRY RUN) 以下文件将被迁移（不实际执行）:")

    if os.path.isdir(args.path):
        results = rekey_directory_bulk(
            args.path,
            recursive=not args.no_recursive,
            dry_run=dry_run,
            backup=backup,
            policy=policy,
            **kwargs,
        )
        total = len(results)
        ok = sum(1 for r in results if r.success)
        fail = total - ok
        for r in results:
            prefix = "(DRY RUN) " if dry_run else ""
            if r.success:
                msg = "将迁移" if dry_run else "已更换密钥"
                if r.backup:
                    msg += f" (备份: {os.path.basename(r.backup)})"
                print(f"  ✓ {prefix}{r.source}: {msg}")
            else:
                msg = "将失败" if dry_run else r.error
                print(f"  ✗ {prefix}{r.source}: {msg}", file=sys.stderr)
        if dry_run:
            print(f"\n预计: 成功 {ok}，失败 {fail}，共 {total} 个")
            return 0
        print(f"\n更换完成: 成功 {ok}，失败 {fail}，共 {total} 个")
        if backup and fail == 0:
            print("提示: 备份文件 (.bak) 已创建，确认无误后可手动删除")
        elif fail > 0:
            print("提示: 失败的文件保留原状态，成功的文件如有备份可用于恢复", file=sys.stderr)
        return 0 if fail == 0 else 1
    else:
        r = rekey_file(args.path, dry_run=dry_run, backup=backup, **kwargs)
        prefix = "(DRY RUN) " if dry_run else ""
        if r.success:
            msg = "将迁移" if dry_run else "已更换密钥"
            if r.backup:
                msg += f" (备份: {os.path.basename(r.backup)})"
            print(f"  ✓ {prefix}{r.source}: {msg}")
            return 0
        else:
            msg = "将失败" if dry_run else r.error
            print(f"  ✗ {prefix}{r.source}: {msg}", file=sys.stderr)
            return 1


def cmd_check(args) -> int:
    report = None
    try:
        if args.staged:
            root = find_git_root(args.path)
            scan_root = root
            try:
                policy = load_policy(args.policy_file, base_dir=root)
            except PolicyError as e:
                print(f"警告: {e}", file=sys.stderr)
                policy = None
            files = get_staged_files(root)
            patterns = (
                load_patterns(os.path.join(root, args.patterns_file))
                if os.path.exists(os.path.join(root, args.patterns_file))
                else []
            )
            sensitive = match_sensitive_files(files, patterns, root, policy=policy)
            sensitive_display = [os.path.relpath(f, root) for f in sensitive]
            all_files_display = [os.path.relpath(f, root) for f in files]
        else:
            if os.path.isfile(args.path):
                scan_root = os.path.dirname(args.path) or "."
                files_to_check = [args.path]
            else:
                scan_root = args.path
                files_to_check = collect_files(
                    args.path,
                    recursive=not args.no_recursive,
                    config_only=False,
                    include_encrypted=False,
                )
            try:
                policy = load_policy(args.policy_file, base_dir=scan_root)
            except PolicyError as e:
                print(f"警告: {e}", file=sys.stderr)
                policy = None
            patterns = (
                load_patterns(args.patterns_file)
                if os.path.exists(args.patterns_file)
                else []
            )
            sensitive = match_sensitive_files_local(
                files_to_check, patterns, base_dir=scan_root, policy=policy
            )
            root_display = scan_root
            sensitive_display = []
            for f in sensitive:
                try:
                    sensitive_display.append(os.path.relpath(f, root_display))
                except ValueError:
                    sensitive_display.append(f)
            all_files_display = []
            for f in files_to_check:
                try:
                    all_files_display.append(os.path.relpath(f, root_display))
                except ValueError:
                    all_files_display.append(f)

        report = create_report(
            command="check",
            scan_root=scan_root,
            policy_file=policy.source_file if policy else None,
        )
        report.extra["staged"] = args.staged
        report.extra["scanned_files"] = len(files_to_check) if not args.staged else len(files)

        for disp, full in zip(sensitive_display, sensitive):
            report.add_file(AuditFileItem(
                path=full,
                rel_path=disp,
                status="failed",
                reason="明文敏感文件，需加密",
            ))

        if args.staged:
            for full, disp in zip(files, all_files_display):
                if full not in sensitive:
                    try:
                        rel = os.path.relpath(full, root).replace("\\", "/")
                    except ValueError:
                        rel = disp
                    reason = "已加密" if full.endswith(DEFAULT_EXT) else "非敏感文件"
                    status = "passed" if full.endswith(DEFAULT_EXT) or not policy or not policy.is_required(rel) else "failed"
                    if status == "passed":
                        report.add_file(AuditFileItem(
                            path=full, rel_path=disp, status="passed", reason=reason,
                        ))

    except (FileHandlerError, GitHookError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1

    if report:
        report.mark_completed()

    if not sensitive_display:
        print("未发现明文敏感文件 ✓")
        if args.report and report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return 0

    print(f"发现 {len(sensitive_display)} 个明文敏感文件（需先加密后再提交）:")
    for f in sensitive_display:
        print(f"  ⚠  {f}")
    print(f"\n提示: 使用 config-crypt encrypt <file> 加密，或 config-crypt git-hook install 自动处理")

    if args.report and report:
        write_report(report, args.report, format=args.report_format)
        print(f"\n审计报告已写入: {args.report}")

    return 1 if args.fail else 0


def cmd_git_hook(args) -> int:
    if args.hook_action == "install":
        try:
            githooks.install_hook(
                hook_path=args.hook_path,
                patterns_file=args.patterns_file,
                key_file=args.key_file,
                policy_file=getattr(args, "policy_file", ".cryptpolicy"),
                force=args.force,
            )
            print(f"已安装 git pre-commit hook: {args.hook_path}")
            if args.key_file:
                print(f"使用密钥文件: {args.key_file}")
            else:
                print(f"提示: 未指定密钥文件，将使用环境变量 CONFIG_CRYPT_KEY 或交互式密码")
            return 0
        except (githooks.GitHookError, FileHandlerError, KeyManagerError) as e:
            print(f"错误: {e}", file=sys.stderr)
            return 1
    elif args.hook_action == "uninstall":
        try:
            githooks.uninstall_hook(args.hook_path)
            print(f"已卸载 git hook: {args.hook_path}")
            return 0
        except githooks.GitHookError as e:
            print(f"错误: {e}", file=sys.stderr)
            return 1
    elif args.hook_action == "status":
        status = githooks.check_hook(args.hook_path)
        if status == githooks.HookStatus.INSTALLED:
            print(f"hook 已安装: {args.hook_path}")
        elif status == githooks.HookStatus.OTHER:
            print(f"hook 已存在但非 config-crypt 管理: {args.hook_path}")
        else:
            print(f"hook 未安装: {args.hook_path}")
        return 0
    elif args.hook_action == "_precommit":
        return githooks.precommit_hook_impl(
            patterns_file=args.patterns_file,
            key_file=args.key_file,
            policy_file=getattr(args, "policy_file", ".cryptpolicy"),
        )
    return 1


def cmd_list(args) -> int:
    if args.encrypted:
        files = collect_files(
            args.directory,
            recursive=not args.no_recursive,
            config_only=False,
            include_encrypted=True,
        )
        files = [f for f in files if f.endswith(DEFAULT_EXT)]
    else:
        files = collect_files(
            args.directory,
            recursive=not args.no_recursive,
            config_only=True,
            include_encrypted=False,
        )
    for f in files:
        print(f)
    print(f"\n共 {len(files)} 个文件")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "encrypt-dir": cmd_encrypt_dir,
        "decrypt-dir": cmd_decrypt_dir,
        "archive": cmd_archive,
        "unarchive": cmd_unarchive,
        "gen-key": cmd_gen_key,
        "verify": cmd_verify,
        "rekey": cmd_rekey,
        "check": cmd_check,
        "git-hook": cmd_git_hook,
        "list": cmd_list,
    }

    try:
        return handlers[args.command](args)
    except (CryptoError, FileHandlerError, KeyManagerError) as e:
        if isinstance(e, PasswordError):
            print(f"密码错误: {e}", file=sys.stderr)
        elif isinstance(e, TamperedError):
            print(f"文件校验失败: {e}", file=sys.stderr)
        elif isinstance(e, VersionError):
            print(f"版本错误: {e}", file=sys.stderr)
        else:
            print(f"错误: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n操作已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
