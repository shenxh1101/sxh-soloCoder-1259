import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

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
from .policy import Policy, PolicyError, load_policy, init_policy_file, generate_policy_template
from .audit import (
    AuditFileItem,
    AuditReport,
    create_report,
    write_report,
    filter_report_by_new,
    load_report,
    save_baseline,
    get_baseline_path,
)
from .secretscan import (
    ScanConfig,
    scan_file,
    scan_directory,
    load_allowlist_from_file,
    findings_by_severity,
    should_fail,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_ORDER,
)
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
        choices=["json", "markdown", "md", "sarif"],
        default=None,
        help="报告格式：json / markdown(md) / sarif（默认根据扩展名自动识别）",
    )
    parser.add_argument(
        "--diff-with",
        help="与之前的报告做 diff，只显示新增的问题（支持 JSON 或 SARIF 报告）",
    )
    parser.add_argument(
        "--baseline",
        help="与基线报告比较，只拦截新增问题（支持 JSON 或 SARIF 格式），等同于 --diff-with",
    )
    parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="扫描完成后，将当前报告保存为基线文件（默认路径：.crypt-baseline-<command>.json）",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="扫描完成后，更新基线文件为当前报告（等同于 --init-baseline，但会覆盖已有基线）",
    )
    parser.add_argument(
        "--baseline-path",
        help="自定义基线文件路径（用于 --init-baseline / --update-baseline / --baseline）",
    )


def _validate_paths(paths: List[str]) -> None:
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        if len(missing) == 1:
            raise FileNotFoundError(f"路径不存在: {missing[0]}")
        raise FileNotFoundError(f"以下路径不存在: {', '.join(missing)}")


def _apply_report_filters(
    report: AuditReport,
    args,
) -> AuditReport:
    diff_path = args.baseline or args.diff_with
    if diff_path:
        try:
            baseline = load_report(diff_path)
            report = filter_report_by_new(report, baseline)
        except FileNotFoundError:
            print(f"[警告] 基线/对比报告不存在: {diff_path}，跳过 diff，使用完整报告", file=sys.stderr)
    return report


def _save_baseline_if_needed(report: AuditReport, args, command: str) -> Optional[str]:
    if not (args.init_baseline or args.update_baseline):
        return None
    scan_root = report.scan_root or "."
    if args.baseline_path:
        baseline_path = args.baseline_path
    else:
        baseline_path = get_baseline_path(scan_root, command)
    if os.path.exists(baseline_path) and args.init_baseline and not args.update_baseline:
        raise FileExistsError(
            f"基线文件已存在: {baseline_path}。使用 --update-baseline 覆盖，或指定 --baseline-path"
        )
    saved = save_baseline(report, baseline_path)
    print(f"[基线] 已保存基线: {saved}", file=sys.stderr)
    return saved


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

    p_policy = sub.add_parser("policy", help="策略文件管理")
    policy_sub = p_policy.add_subparsers(dest="policy_action", required=True, metavar="ACTION")
    p_policy_init = policy_sub.add_parser("init", help="生成带注释的 .cryptpolicy 策略模板")
    p_policy_init.add_argument("-o", "--output", default=".cryptpolicy", help="输出路径（默认 .cryptpolicy）")
    p_policy_init.add_argument("-f", "--force", action="store_true", help="覆盖已存在的文件")
    p_policy_explain = policy_sub.add_parser("explain", help="解释某个文件为什么被策略标记/豁免/忽略")
    p_policy_explain.add_argument("file", help="要分析的文件路径")
    p_policy_explain.add_argument("--base-dir", default=".", help="相对路径基准目录（默认当前目录）")
    add_policy_arg(p_policy_explain)

    p_sscan = sub.add_parser("secret-scan", help="扫描文件内容中的密钥、token、私钥等敏感信息")
    p_sscan.add_argument("path", nargs="?", default=".", help="文件或目录路径（默认当前目录）")
    p_sscan.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_sscan.add_argument(
        "--allowlist-file",
        default=".cryptallowlist",
        help="白名单文件路径，每行一个允许字符串（匹配行内任意位置）",
    )
    p_sscan.add_argument(
        "--fail",
        action="store_true",
        help="发现任何敏感信息时以非零退出码返回（用于 CI）",
    )
    p_sscan.add_argument(
        "--fail-on-severity",
        choices=["high", "medium", "low"],
        default=None,
        help="按严重级别决定 CI 失败：high（仅高危失败）/ medium（中高危失败）/ low（所有失败）",
    )
    add_audit_args(p_sscan)

    p_base = sub.add_parser("baseline", help="基线管理：init-baseline / update-baseline")
    base_sub = p_base.add_subparsers(dest="baseline_action", required=True, metavar="ACTION")
    p_init = base_sub.add_parser("init", help="初始化基线：先扫描指定命令，再保存基线")
    p_init.add_argument("scan_command", choices=["check", "verify", "secret-scan"], help="要执行的扫描命令")
    p_init.add_argument("path", nargs="?", default=".", help="扫描路径")
    p_init.add_argument("--baseline-path", help="自定义基线文件输出路径")
    p_init.add_argument("--policy-file", default=".cryptpolicy", help="策略文件（用于 check/verify）")
    p_init.add_argument("--allowlist-file", default=".cryptallowlist", help="白名单文件（用于 secret-scan）")
    p_init.add_argument("--no-recursive", action="store_true", help="不递归子目录")

    p_update = base_sub.add_parser("update", help="更新基线：重新扫描并覆盖已有基线")
    p_update.add_argument("scan_command", choices=["check", "verify", "secret-scan"], help="要执行的扫描命令")
    p_update.add_argument("path", nargs="?", default=".", help="扫描路径")
    p_update.add_argument("--baseline-path", help="自定义基线文件路径")
    p_update.add_argument("--policy-file", default=".cryptpolicy", help="策略文件（用于 check/verify）")
    p_update.add_argument("--allowlist-file", default=".cryptallowlist", help="白名单文件（用于 secret-scan）")
    p_update.add_argument("--no-recursive", action="store_true", help="不递归子目录")

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
    _validate_paths([args.path])

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

        report = _apply_report_filters(report, args)
        _save_baseline_if_needed(report, args, "verify")

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

        report = _apply_report_filters(report, args)
        _save_baseline_if_needed(report, args, "verify")

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
    if not args.staged:
        _validate_paths([args.path])

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

        sensitive_set = set(sensitive)

        for disp, full in zip(sensitive_display, sensitive):
            report.add_file(AuditFileItem(
                path=full,
                rel_path=disp,
                status="failed",
                reason="明文敏感文件，需加密",
            ))

        if args.staged:
            for full, disp in zip(files, all_files_display):
                if full not in sensitive_set:
                    try:
                        rel = os.path.relpath(full, root).replace("\\", "/")
                    except ValueError:
                        rel = disp
                    reason = "已加密" if full.endswith(DEFAULT_EXT) else "非敏感文件"
                    report.add_file(AuditFileItem(
                        path=full, rel_path=disp, status="passed", reason=reason,
                    ))
        else:
            for full, disp in zip(files_to_check, all_files_display):
                if full in sensitive_set:
                    continue
                try:
                    rel = os.path.relpath(full, scan_root).replace("\\", "/")
                except ValueError:
                    rel = disp
                if full.endswith(DEFAULT_EXT):
                    reason = "已加密"
                elif policy and policy.should_ignore(rel):
                    reason = "忽略（ignore_extensions/ignore_patterns）"
                elif policy and policy.is_allowed_plaintext(rel):
                    reason = "允许明文（allowed_plaintext）"
                else:
                    reason = "非敏感文件"
                report.add_file(AuditFileItem(
                    path=full, rel_path=disp, status="passed", reason=reason,
                ))

    except (FileHandlerError, GitHookError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1

    if report:
        report.mark_completed()

    original_failed = len(sensitive_display)
    report = _apply_report_filters(report, args)
    _save_baseline_if_needed(report, args, "check")

    is_diff_mode = bool(args.baseline or args.diff_with)
    if is_diff_mode:
        new_sensitive = [f.rel_path for f in report.files if f.status == "failed"]
        display_list = new_sensitive
    else:
        display_list = sensitive_display

    if not display_list:
        if is_diff_mode and original_failed > 0:
            print(f"未发现新增明文敏感文件 ✓（基线中已有 {original_failed} 个已知问题）")
        else:
            print("未发现明文敏感文件 ✓")
        if args.report and report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return 0

    prefix = "新增 " if is_diff_mode else ""
    print(f"发现 {prefix}{len(display_list)} 个明文敏感文件（需先加密后再提交）:")
    for f in display_list:
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


def cmd_policy(args) -> int:
    if args.policy_action == "init":
        try:
            path = init_policy_file(args.output, force=args.force)
            print(f"已生成策略模板: {path}")
            print("提示: 编辑此文件以自定义团队加密规则")
            return 0
        except PolicyError as e:
            print(f"错误: {e}", file=sys.stderr)
            return 1
    elif args.policy_action == "explain":
        try:
            policy = load_policy(args.policy_file, base_dir=args.base_dir)
        except PolicyError as e:
            print(f"警告: {e}", file=sys.stderr)
            policy = load_policy(base_dir=args.base_dir)

        if os.path.isabs(args.file):
            rel_path = os.path.relpath(args.file, args.base_dir)
        else:
            rel_path = args.file
        rel_path = rel_path.replace("\\", "/")

        result = policy.explain(rel_path)
        print(f"文件: {result['path']}")
        if policy.source_file:
            print(f"策略: {policy.source_file}")
        else:
            print("策略: 使用内置默认规则")
        print()
        if result["reasons"]:
            print("匹配原因:")
            for r in result["reasons"]:
                print(f"  - {r}")
        else:
            print("匹配原因: 无匹配规则")
        print()
        print(f"最终结论: {result['final_verdict']}")
        return 0
    return 1


def cmd_secret_scan(args) -> int:
    _validate_paths([args.path])

    allowlist = load_allowlist_from_file(args.allowlist_file)
    config = ScanConfig(
        allowlist=allowlist,
        fail_on_severity=args.fail_on_severity,
    )

    if os.path.isfile(args.path):
        scan_root = os.path.dirname(args.path) or "."
        findings = scan_file(args.path, base_dir=scan_root, config=config)
    else:
        scan_root = args.path
        findings = scan_directory(
            args.path,
            recursive=not args.no_recursive,
            base_dir=scan_root,
            config=config,
        )

    report = create_report(command="secret-scan", scan_root=scan_root)
    report.extra["allowlist_file"] = args.allowlist_file
    report.extra["scanned_with_allowlist"] = len(allowlist) > 0

    original_findings = findings
    if not findings:
        print("未发现敏感信息 ✓")
        report.add_file(AuditFileItem(
            path=scan_root, rel_path=scan_root, status="passed", reason="无敏感信息",
        ))
        report.mark_completed()

        report = _apply_report_filters(report, args)
        _save_baseline_if_needed(report, args, "secret-scan")

        if args.report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return 0

    by_file: Dict[str, List] = {}
    for f in findings:
        by_file.setdefault(f.rel_path, []).append(f)
        severity_label = {
            SEVERITY_HIGH: "高危",
            SEVERITY_MEDIUM: "中危",
            SEVERITY_LOW: "低危",
        }.get(f.severity, "未知")
        report.add_file(AuditFileItem(
            path=f.file_path,
            rel_path=f.rel_path,
            status="failed",
            reason=f"{severity_label} · {f.description} (行 {f.line})",
            details={
                "line": f.line,
                "type": f.secret_type,
                "severity": f.severity,
                "matched": f.matched_text,
            },
        ))

    by_sev = findings_by_severity(findings)
    sev_counts = {k: len(v) for k, v in by_sev.items() if v}

    report.extra["severity_counts"] = sev_counts

    report.mark_completed()
    original_report = report
    report = _apply_report_filters(report, args)
    _save_baseline_if_needed(report, args, "secret-scan")

    is_diff_mode = bool(args.baseline or args.diff_with)
    if is_diff_mode:
        new_finding_paths = {f.rel_path for f in report.files if f.status == "failed"}
        filtered_findings = [f for f in findings if f.rel_path in new_finding_paths]
        by_file = {}
        for f in filtered_findings:
            by_file.setdefault(f.rel_path, []).append(f)
        findings = filtered_findings

    if not findings:
        print(f"未发现新增敏感信息 ✓（基线中已有 {len(original_findings)} 个已知问题）")
        if args.report:
            write_report(report, args.report, format=args.report_format)
            print(f"\n审计报告已写入: {args.report}")
        return 0

    sev_line = ", ".join(
        f"{'高危' if k == SEVERITY_HIGH else '中危' if k == SEVERITY_MEDIUM else '低危'}: {v}"
        for k, v in sorted(sev_counts.items(), key=lambda x: -SEVERITY_ORDER[x[0]])
    )

    prefix = "新增 " if is_diff_mode else ""
    print(f"发现 {prefix}{len(findings)} 处敏感信息（{sev_line}），涉及 {len(by_file)} 个文件:")
    for rel_path, items in by_file.items():
        print(f"\n  ⚠  {rel_path}:")
        for item in items:
            sev = {
                SEVERITY_HIGH: "🔴 高危",
                SEVERITY_MEDIUM: "🟡 中危",
                SEVERITY_LOW: "🔵 低危",
            }.get(item.severity, "⚪ 未知")
            preview = item.matched_text[:60]
            if len(item.matched_text) > 60:
                preview += "..."
            print(f"    第 {item.line} 行 {sev} [{item.description}]: {preview}")

    fail_threshold = args.fail_on_severity
    if fail_threshold:
        sev_label = "高危" if fail_threshold == SEVERITY_HIGH else "中高危" if fail_threshold == SEVERITY_MEDIUM else "所有"
        print(f"\nCI 失败级别: {sev_label} 及以上")

    print(f"\n提示: 使用 --allowlist-file 添加白名单放过测试样例，或加密这些文件")

    if args.report:
        write_report(report, args.report, format=args.report_format)
        print(f"\n审计报告已写入: {args.report}")

    if args.fail:
        return 1 if should_fail(findings, fail_threshold) else 0
    if fail_threshold:
        return 1 if should_fail(findings, fail_threshold) else 0
    return 0


def cmd_baseline(args) -> int:
    _validate_paths([args.path])

    scan_command = args.scan_command
    scan_args = argparse.Namespace(
        path=args.path,
        policy_file=getattr(args, "policy_file", ".cryptpolicy"),
        allowlist_file=getattr(args, "allowlist_file", ".cryptallowlist"),
        no_recursive=args.no_recursive,
        staged=False,
        fail=False,
        fail_on_severity=None,
        patterns_file=".cryptignore",
        report=None,
        report_format=None,
        diff_with=None,
        baseline=None,
        init_baseline=args.baseline_action == "init",
        update_baseline=args.baseline_action == "update",
        baseline_path=args.baseline_path,
        password=None,
        key_file=None,
        env_key="CONFIG_CRYPT_KEY",
        old_password=None,
        old_key_file=None,
        old_env_key="CONFIG_CRYPT_OLD_KEY",
        new_password=None,
        new_key_file=None,
        new_env_key="CONFIG_CRYPT_NEW_KEY",
    )

    command_handlers = {
        "check": cmd_check,
        "verify": cmd_verify,
        "secret-scan": cmd_secret_scan,
    }

    handler = command_handlers[scan_command]
    try:
        handler(scan_args)
    except SystemExit:
        pass
    except (FileNotFoundError, FileExistsError):
        raise
    except Exception as e:
        print(f"基线扫描失败: {e}", file=sys.stderr)
        return 1

    scan_root = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."
    baseline_path = args.baseline_path or get_baseline_path(scan_root, scan_command)

    if os.path.exists(baseline_path):
        print(f"✅ 基线已{'初始化' if args.baseline_action == 'init' else '更新'}: {baseline_path}")
        print(f"   后续使用 `config-crypt {scan_command} {args.path} --baseline {baseline_path}` 只拦截新增问题")
        return 0

    print(f"❌ 基线未生成: {baseline_path}", file=sys.stderr)
    return 1


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
        "policy": cmd_policy,
        "secret-scan": cmd_secret_scan,
        "baseline": cmd_baseline,
    }

    try:
        return handlers[args.command](args)
    except FileNotFoundError as e:
        print(f"[错误] {e}", file=sys.stderr)
        print("请检查路径是否正确，避免流水线误判通过。", file=sys.stderr)
        return 3
    except FileExistsError as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 4
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
