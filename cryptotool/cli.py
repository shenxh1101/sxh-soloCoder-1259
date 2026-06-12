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
)
from . import githooks


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
    p_install.add_argument("-f", "--force", action="store_true", help="覆盖已存在的 hook")
    p_uninstall = hook_sub.add_parser("uninstall", help="卸载 pre-commit hook")
    p_uninstall.add_argument("--hook-path", default=".git/hooks/pre-commit", help="hook 文件路径")
    p_status = hook_sub.add_parser("status", help="检查 hook 安装状态")
    p_status.add_argument("--hook-path", default=".git/hooks/pre-commit", help="hook 文件路径")
    p_precommit = hook_sub.add_parser("_precommit", help=argparse.SUPPRESS)
    p_precommit.add_argument("--patterns-file", default=".cryptignore")
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
    if mode == "keyfile":
        results = encrypt_directory_bulk(
            args.directory,
            args.output_dir,
            key=key_or_pwd,
            recursive=not args.no_recursive,
            config_only=not args.all_files,
            force=args.force,
        )
    else:
        results = encrypt_directory_bulk(
            args.directory,
            args.output_dir,
            password=key_or_pwd,
            recursive=not args.no_recursive,
            config_only=not args.all_files,
            force=args.force,
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


def cmd_git_hook(args) -> int:
    if args.hook_action == "install":
        try:
            githooks.install_hook(
                hook_path=args.hook_path,
                patterns_file=args.patterns_file,
                key_file=args.key_file,
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
