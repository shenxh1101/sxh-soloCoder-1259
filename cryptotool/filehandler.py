import io
import os
import shutil
import tarfile
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple, Union

from .crypto import (
    encrypt_data,
    decrypt_data,
    encrypt_with_password,
    decrypt_with_password,
    verify_data,
    verify_with_password,
    CryptoError,
)
from .policy import Policy


DEFAULT_EXT = ".ccrypt"
CONFIG_EXTENSIONS = {
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".config",
}
SENSITIVE_EXTENSIONS = CONFIG_EXTENSIONS | {
    ".key",
    ".pem",
    ".crt",
    ".cer",
    ".p12",
    ".pfx",
    ".jks",
    ".der",
    ".pub",
    ".prv",
    ".secret",
    ".sec",
    ".pgp",
    ".gpg",
    ".asc",
    ".kdbx",
    ".keystore",
    ".ts",
    ".env.example",
}


class FileHandlerError(Exception):
    pass


@dataclass
class EncryptResult:
    source: str
    target: str
    success: bool
    error: Optional[str] = None


@dataclass
class DecryptResult:
    source: str
    target: str
    success: bool
    error: Optional[str] = None


@dataclass
class VerifyResult:
    source: str
    success: bool
    error: Optional[str] = None


def verify_file(
    input_path: str,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
) -> VerifyResult:
    try:
        ciphertext = read_file(input_path)
        if key is not None:
            verify_data(ciphertext, key)
        elif password is not None:
            verify_with_password(ciphertext, password)
        else:
            raise FileHandlerError("必须提供密码或密钥")
        return VerifyResult(source=input_path, success=True)
    except (CryptoError, FileHandlerError) as e:
        return VerifyResult(source=input_path, success=False, error=str(e))


def verify_directory_bulk(
    dir_path: str,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    recursive: bool = True,
    policy: Optional[Policy] = None,
) -> List[VerifyResult]:
    root = Path(dir_path)
    if not root.exists() or not root.is_dir():
        raise FileHandlerError(f"目录不存在或不是目录: {dir_path}")

    pattern = "**/*" + DEFAULT_EXT if recursive else "*" + DEFAULT_EXT
    files = [str(p) for p in root.glob(pattern) if p.is_file()]

    if policy:
        filtered = []
        for f in files:
            try:
                rel = os.path.relpath(f, dir_path).replace("\\", "/")
            except ValueError:
                rel = os.path.basename(f)
            if policy.should_ignore(rel):
                continue
            filtered.append(f)
        files = filtered

    files.sort()

    results = []
    for f in files:
        results.append(verify_file(f, password=password, key=key))
    return results


def is_config_file(path: str) -> bool:
    p = Path(path)
    if p.name.startswith(".env"):
        return True
    return p.suffix.lower() in CONFIG_EXTENSIONS


def is_sensitive_file(path: str) -> bool:
    p = Path(path)
    name = p.name.lower()
    if name.startswith(".env"):
        return True
    if name in {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "known_hosts", "authorized_keys"}:
        return True
    suffix = p.suffix.lower()
    if suffix in SENSITIVE_EXTENSIONS:
        return True
    stem = p.stem.lower()
    if stem.startswith(".env") and p.suffix.lower() in CONFIG_EXTENSIONS:
        return True
    return False


def match_sensitive_files_local(
    files: List[str],
    patterns: Optional[List] = None,
    base_dir: Optional[str] = None,
    policy: Optional[Policy] = None,
) -> List[str]:
    matched = []
    root = base_dir or os.getcwd()
    for f in files:
        if f.endswith(DEFAULT_EXT):
            continue
        try:
            rel = os.path.relpath(f, root).replace("\\", "/")
        except ValueError:
            rel = os.path.basename(f)
        if policy and policy.should_ignore(rel):
            continue
        if policy and policy.is_allowed_plaintext(rel):
            continue
        if policy and policy.is_required(rel):
            matched.append(f)
            continue
        if patterns and any(p.match(os.path.basename(f)) or p.match(f.replace("\\", "/")) for p in patterns):
            matched.append(f)
            continue
        if is_sensitive_file(f):
            matched.append(f)
    return matched


def default_output_path(input_path: str, ext: str = DEFAULT_EXT, decrypt: bool = False) -> str:
    p = Path(input_path)
    if decrypt:
        if p.suffix == ext:
            return str(p.with_suffix(""))
        return str(p.with_suffix(".decrypted"))
    else:
        if p.suffix == ext:
            raise FileHandlerError(f"文件已是加密格式: {input_path}")
        return str(p) + ext


def read_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise FileHandlerError(f"读取文件失败 {path}: {e}") from e


def write_file(path: str, data: bytes, force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise FileHandlerError(f"输出文件已存在: {path}（使用 --force 覆盖）")
    try:
        dir_path = os.path.dirname(os.path.abspath(path))
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise FileHandlerError(f"写入文件失败 {path}: {e}") from e


def encrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    force: bool = False,
) -> EncryptResult:
    target = output_path or default_output_path(input_path)
    try:
        plaintext = read_file(input_path)
        if key is not None:
            ciphertext = encrypt_data(plaintext, key)
        elif password is not None:
            ciphertext = encrypt_with_password(plaintext, password)
        else:
            raise FileHandlerError("必须提供密码或密钥")
        write_file(target, ciphertext, force=force)
        return EncryptResult(source=input_path, target=target, success=True)
    except (CryptoError, FileHandlerError) as e:
        return EncryptResult(
            source=input_path, target=target, success=False, error=str(e)
        )


def decrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    force: bool = False,
) -> DecryptResult:
    target = output_path or default_output_path(input_path, decrypt=True)
    try:
        ciphertext = read_file(input_path)
        if key is not None:
            plaintext = decrypt_data(ciphertext, key)
        elif password is not None:
            plaintext = decrypt_with_password(ciphertext, password)
        else:
            raise FileHandlerError("必须提供密码或密钥")
        write_file(target, plaintext, force=force)
        return DecryptResult(source=input_path, target=target, success=True)
    except (CryptoError, FileHandlerError) as e:
        return DecryptResult(
            source=input_path, target=target, success=False, error=str(e)
        )


def collect_files(
    dir_path: str,
    recursive: bool = True,
    config_only: bool = True,
    include_encrypted: bool = False,
) -> List[str]:
    root = Path(dir_path)
    if not root.exists():
        raise FileHandlerError(f"目录不存在: {dir_path}")
    if not root.is_dir():
        raise FileHandlerError(f"不是目录: {dir_path}")

    pattern = "**/*" if recursive else "*"
    files = []
    for p in root.glob(pattern):
        if not p.is_file():
            continue
        if p.suffix == DEFAULT_EXT and not include_encrypted:
            continue
        if config_only and not is_config_file(str(p)):
            continue
        files.append(str(p))
    return sorted(files)


def encrypt_directory_bulk(
    dir_path: str,
    output_dir: Optional[str] = None,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    recursive: bool = True,
    config_only: bool = True,
    force: bool = False,
    policy: Optional[Policy] = None,
) -> List[EncryptResult]:
    if policy is not None:
        files = collect_files(dir_path, recursive=recursive, config_only=False)
    else:
        files = collect_files(dir_path, recursive=recursive, config_only=config_only)
    results = []
    out_root = Path(output_dir) if output_dir else Path(dir_path)

    for f in files:
        rel = os.path.relpath(f, dir_path).replace("\\", "/")
        if policy is not None:
            if policy.should_ignore(rel):
                continue
            if policy.is_allowed_plaintext(rel):
                continue
            if not policy.is_required(rel):
                continue
        target = str(out_root / (rel + DEFAULT_EXT))
        results.append(
            encrypt_file(
                f, target, password=password, key=key, force=force
            )
        )
    return results


def decrypt_directory_bulk(
    dir_path: str,
    output_dir: Optional[str] = None,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    recursive: bool = True,
    force: bool = False,
) -> List[DecryptResult]:
    root = Path(dir_path)
    if not root.exists() or not root.is_dir():
        raise FileHandlerError(f"目录不存在或不是目录: {dir_path}")

    pattern = "**/*" + DEFAULT_EXT if recursive else "*" + DEFAULT_EXT
    files = [str(p) for p in root.glob(pattern) if p.is_file()]
    files.sort()

    results = []
    out_root = Path(output_dir) if output_dir else Path(dir_path)

    for f in files:
        rel = os.path.relpath(f, dir_path)
        target = str(out_root / Path(rel).with_suffix(""))
        results.append(
            decrypt_file(
                f, target, password=password, key=key, force=force
            )
        )
    return results


def create_archive(dir_path: str) -> bytes:
    root = Path(dir_path)
    if not root.exists() or not root.is_dir():
        raise FileHandlerError(f"目录不存在或不是目录: {dir_path}")

    manifest = []
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tar:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = os.path.relpath(str(p), str(root))
            tar.add(str(p), arcname=rel)
            manifest.append({"path": rel, "size": p.stat().st_size})

    tar_bytes = buf.getvalue()
    manifest_json = json.dumps(manifest, ensure_ascii=False).encode("utf-8")

    header = io.BytesIO()
    header.write(len(manifest_json).to_bytes(4, "little"))
    header.write(manifest_json)
    header.write(tar_bytes)
    return header.getvalue()


def extract_archive(data: bytes, output_dir: str) -> List[str]:
    if len(data) < 4:
        raise FileHandlerError("存档数据格式错误")

    manifest_len = int.from_bytes(data[:4], "little")
    if 4 + manifest_len > len(data):
        raise FileHandlerError("存档数据不完整")

    try:
        manifest = json.loads(data[4 : 4 + manifest_len].decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise FileHandlerError(f"解析存档清单失败: {e}") from e

    tar_bytes = data[4 + manifest_len :]
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    extracted = []
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
            tar.extractall(path=str(out_path))
            extracted = [str(out_path / m["path"]) for m in manifest]
    except tarfile.TarError as e:
        raise FileHandlerError(f"解压存档失败: {e}") from e

    return extracted


def encrypt_directory_archive(
    dir_path: str,
    output_path: str,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    force: bool = False,
) -> EncryptResult:
    try:
        archive_data = create_archive(dir_path)
        if key is not None:
            ciphertext = encrypt_data(archive_data, key)
        elif password is not None:
            ciphertext = encrypt_with_password(archive_data, password)
        else:
            raise FileHandlerError("必须提供密码或密钥")
        write_file(output_path, ciphertext, force=force)
        return EncryptResult(source=dir_path, target=output_path, success=True)
    except (CryptoError, FileHandlerError) as e:
        return EncryptResult(
            source=dir_path, target=output_path, success=False, error=str(e)
        )


def decrypt_directory_archive(
    input_path: str,
    output_dir: str,
    *,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    force: bool = False,
) -> DecryptResult:
    try:
        ciphertext = read_file(input_path)
        if key is not None:
            plaintext = decrypt_data(ciphertext, key)
        elif password is not None:
            plaintext = decrypt_with_password(ciphertext, password)
        else:
            raise FileHandlerError("必须提供密码或密钥")
        extract_archive(plaintext, output_dir)
        return DecryptResult(source=input_path, target=output_dir, success=True)
    except (CryptoError, FileHandlerError) as e:
        return DecryptResult(
            source=input_path, target=output_dir, success=False, error=str(e)
        )


@dataclass
class RekeyResult:
    source: str
    success: bool
    error: Optional[str] = None
    dry_run: bool = False
    backup: Optional[str] = None


def rekey_file(
    input_path: str,
    *,
    old_password: Optional[str] = None,
    old_key: Optional[bytes] = None,
    new_password: Optional[str] = None,
    new_key: Optional[bytes] = None,
    dry_run: bool = False,
    backup: bool = False,
) -> RekeyResult:
    if not (old_password is not None or old_key is not None):
        return RekeyResult(
            source=input_path, success=False, error="必须提供旧密码或旧密钥"
        )
    if not (new_password is not None or new_key is not None):
        return RekeyResult(
            source=input_path, success=False, error="必须提供新密码或新密钥"
        )

    if dry_run:
        try:
            ciphertext_old = read_file(input_path)
            if old_key is not None:
                decrypt_data(ciphertext_old, old_key)
            else:
                decrypt_with_password(ciphertext_old, old_password)
            return RekeyResult(source=input_path, success=True, dry_run=True)
        except (CryptoError, FileHandlerError) as e:
            return RekeyResult(source=input_path, success=False, error=str(e), dry_run=True)

    backup_path = None
    try:
        ciphertext_old = read_file(input_path)

        if old_key is not None:
            plaintext = decrypt_data(ciphertext_old, old_key)
        else:
            plaintext = decrypt_with_password(ciphertext_old, old_password)

        if backup:
            backup_path = input_path + ".bak"
            shutil.copy2(input_path, backup_path)

        if new_key is not None:
            ciphertext_new = encrypt_data(plaintext, new_key)
        else:
            ciphertext_new = encrypt_with_password(plaintext, new_password)

        tmp_path = input_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(ciphertext_new)
        os.replace(tmp_path, input_path)

        if backup_path:
            return RekeyResult(source=input_path, success=True, backup=backup_path)
        return RekeyResult(source=input_path, success=True)
    except (CryptoError, FileHandlerError, OSError) as e:
        try:
            tmp = input_path + ".tmp"
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        return RekeyResult(
            source=input_path, success=False, error=str(e), backup=backup_path
        )


def rekey_directory_bulk(
    dir_path: str,
    *,
    old_password: Optional[str] = None,
    old_key: Optional[bytes] = None,
    new_password: Optional[str] = None,
    new_key: Optional[bytes] = None,
    recursive: bool = True,
    dry_run: bool = False,
    backup: bool = False,
    policy: Optional[Policy] = None,
) -> List[RekeyResult]:
    root = Path(dir_path)
    if not root.exists() or not root.is_dir():
        raise FileHandlerError(f"目录不存在或不是目录: {dir_path}")

    pattern = "**/*" + DEFAULT_EXT if recursive else "*" + DEFAULT_EXT
    files = [str(p) for p in root.glob(pattern) if p.is_file()]

    if policy:
        filtered = []
        for f in files:
            try:
                rel = os.path.relpath(f, dir_path).replace("\\", "/")
            except ValueError:
                rel = os.path.basename(f)
            if policy.should_ignore(rel):
                continue
            filtered.append(f)
        files = filtered

    files.sort()

    results = []
    for f in files:
        results.append(
            rekey_file(
                f,
                old_password=old_password,
                old_key=old_key,
                new_password=new_password,
                new_key=new_key,
                dry_run=dry_run,
                backup=backup,
            )
        )
    return results
