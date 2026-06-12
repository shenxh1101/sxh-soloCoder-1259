import os
import sys
import getpass
from typing import Optional, Tuple

from .crypto import KEY_SIZE, generate_key, CryptoError


class KeyManagerError(Exception):
    pass


def read_password(prompt: str = "请输入密码: ", confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        password2 = getpass.getpass("请再次输入密码: ")
        if password != password2:
            raise KeyManagerError("两次输入的密码不一致")
    if not password:
        raise KeyManagerError("密码不能为空")
    return password


def read_key_file(key_path: str) -> bytes:
    if not os.path.exists(key_path):
        raise KeyManagerError(f"密钥文件不存在: {key_path}")
    if not os.path.isfile(key_path):
        raise KeyManagerError(f"不是有效的文件: {key_path}")
    try:
        with open(key_path, "rb") as f:
            key = f.read()
    except OSError as e:
        raise KeyManagerError(f"读取密钥文件失败: {e}") from e

    if len(key) != KEY_SIZE:
        raise KeyManagerError(
            f"密钥文件长度错误: 需要 {KEY_SIZE} 字节，得到 {len(key)} 字节"
        )
    return key


def write_key_file(key_path: str, force: bool = False) -> bytes:
    if os.path.exists(key_path) and not force:
        raise KeyManagerError(f"密钥文件已存在: {key_path}（使用 --force 覆盖）")
    key = generate_key()
    try:
        dir_path = os.path.dirname(os.path.abspath(key_path))
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except OSError as e:
        raise KeyManagerError(f"写入密钥文件失败: {e}") from e
    return key


def resolve_key(
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    env_key: Optional[str] = "CONFIG_CRYPT_KEY",
    need_confirm: bool = False,
) -> Tuple[str, Optional[bytes]]:
    if key_file:
        return ("keyfile", read_key_file(key_file))

    if env_key and env_key in os.environ:
        env_val = os.environ[env_key]
        if env_val.startswith("file://"):
            file_path = env_val[7:]
            return ("keyfile", read_key_file(file_path))
        elif len(env_val) == KEY_SIZE * 2:
            try:
                key = bytes.fromhex(env_val)
                return ("keyfile", key)
            except ValueError:
                pass

    if password is not None:
        if not password:
            raise KeyManagerError("密码不能为空")
        return ("password", password)

    if sys.stdin.isatty():
        try:
            pwd = read_password(confirm=need_confirm)
            return ("password", pwd)
        except (EOFError, KeyboardInterrupt):
            raise KeyManagerError("密码输入被取消")

    raise KeyManagerError(
        "未提供密钥或密码：请使用 --password、--key-file 或设置环境变量"
    )
