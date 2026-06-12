import os
import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


MAGIC = b"CCRYPT"
VERSION = 1
HEADER_SIZE = 8
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
CHECKSUM_SIZE = 32
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1


class CryptoError(Exception):
    pass


class PasswordError(CryptoError):
    pass


class TamperedError(CryptoError):
    pass


class VersionError(CryptoError):
    pass


@dataclass
class EncryptedData:
    version: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    checksum: bytes

    def serialize(self) -> bytes:
        header = MAGIC + struct.pack("<H", self.version)
        return (
            header
            + self.salt
            + self.nonce
            + self.tag
            + self.ciphertext
            + self.checksum
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedData":
        if len(data) < HEADER_SIZE:
            raise CryptoError("文件格式错误：数据过短")

        magic = data[:6]
        if magic != MAGIC:
            raise CryptoError("文件格式错误：不是有效的加密文件")

        version = struct.unpack("<H", data[6:8])[0]
        if version != VERSION:
            raise VersionError(f"不支持的版本：{version}（当前版本：{VERSION}）")

        offset = HEADER_SIZE
        salt = data[offset : offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        tag = data[offset : offset + 16]
        offset += 16

        remaining = len(data) - offset - CHECKSUM_SIZE
        if remaining < 0:
            raise CryptoError("文件格式错误：数据不完整")

        ciphertext = data[offset : offset + remaining]
        offset += remaining
        checksum = data[offset : offset + CHECKSUM_SIZE]

        return cls(
            version=version,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            checksum=checksum,
        )


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def compute_checksum(
    salt: bytes, nonce: bytes, tag: bytes, ciphertext: bytes
) -> bytes:
    h = hashlib.sha256()
    h.update(MAGIC)
    h.update(struct.pack("<H", VERSION))
    h.update(salt)
    h.update(nonce)
    h.update(tag)
    h.update(ciphertext)
    return h.digest()


def verify_checksum(enc: EncryptedData) -> bool:
    expected = compute_checksum(enc.salt, enc.nonce, enc.tag, enc.ciphertext)
    return hmac.compare_digest(expected, enc.checksum)


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise CryptoError(f"密钥长度错误：需要 {KEY_SIZE} 字节，得到 {len(key)} 字节")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, salt)

    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    checksum = compute_checksum(salt, nonce, tag, ciphertext)

    enc = EncryptedData(
        version=VERSION,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        checksum=checksum,
    )
    return enc.serialize()


def encrypt_with_password(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_password(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, salt)

    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    checksum = compute_checksum(salt, nonce, tag, ciphertext)

    enc = EncryptedData(
        version=VERSION,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        checksum=checksum,
    )
    return enc.serialize()


def decrypt_data(data: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise CryptoError(f"密钥长度错误：需要 {KEY_SIZE} 字节，得到 {len(key)} 字节")

    enc = EncryptedData.deserialize(data)

    if not verify_checksum(enc):
        raise TamperedError("文件已被篡改：校验和不匹配")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(enc.nonce, enc.ciphertext + enc.tag, enc.salt)
    except InvalidTag:
        raise PasswordError("解密失败：密钥错误或文件已损坏")

    return plaintext


def decrypt_with_password(data: bytes, password: str) -> bytes:
    enc = EncryptedData.deserialize(data)

    if not verify_checksum(enc):
        raise TamperedError("文件已被篡改：校验和不匹配")

    key = derive_key_from_password(password, enc.salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(enc.nonce, enc.ciphertext + enc.tag, enc.salt)
    except InvalidTag:
        raise PasswordError("解密失败：密码错误")

    return plaintext


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def verify_data(data: bytes, key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise CryptoError(f"密钥长度错误：需要 {KEY_SIZE} 字节，得到 {len(key)} 字节")

    enc = EncryptedData.deserialize(data)

    if not verify_checksum(enc):
        raise TamperedError("文件已被篡改：校验和不匹配")

    aesgcm = AESGCM(key)
    try:
        aesgcm.decrypt(enc.nonce, enc.ciphertext + enc.tag, enc.salt)
    except InvalidTag:
        raise PasswordError("验证失败：密钥错误或文件已损坏")


def verify_with_password(data: bytes, password: str) -> None:
    enc = EncryptedData.deserialize(data)

    if not verify_checksum(enc):
        raise TamperedError("文件已被篡改：校验和不匹配")

    key = derive_key_from_password(password, enc.salt)
    aesgcm = AESGCM(key)
    try:
        aesgcm.decrypt(enc.nonce, enc.ciphertext + enc.tag, enc.salt)
    except InvalidTag:
        raise PasswordError("验证失败：密码错误")
