import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptotool.crypto import (
    encrypt_data,
    decrypt_data,
    encrypt_with_password,
    decrypt_with_password,
    generate_key,
    PasswordError,
    TamperedError,
    CryptoError,
    EncryptedData,
)
from cryptotool.filehandler import (
    encrypt_file,
    decrypt_file,
    encrypt_directory_bulk,
    decrypt_directory_bulk,
    encrypt_directory_archive,
    decrypt_directory_archive,
    collect_files,
    is_config_file,
    DEFAULT_EXT,
)
from cryptotool.keymanager import (
    write_key_file,
    read_key_file,
    KEY_SIZE,
)


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_data = b"Hello, World! This is a test.\nWith newlines and special chars: \xe4\xb8\xad\xe6\x96\x87"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_encrypt_decrypt_with_key(self):
        key = generate_key()
        ct = encrypt_data(self.test_data, key)
        self.assertNotEqual(ct, self.test_data)
        pt = decrypt_data(ct, key)
        self.assertEqual(pt, self.test_data)

    def test_encrypt_decrypt_with_password(self):
        pwd = "my-super-password-123"
        ct = encrypt_with_password(self.test_data, pwd)
        self.assertNotEqual(ct, self.test_data)
        pt = decrypt_with_password(ct, pwd)
        self.assertEqual(pt, self.test_data)

    def test_wrong_password(self):
        ct = encrypt_with_password(self.test_data, "correct-password")
        with self.assertRaises(PasswordError):
            decrypt_with_password(ct, "wrong-password")

    def test_wrong_key(self):
        key1 = generate_key()
        key2 = generate_key()
        ct = encrypt_data(self.test_data, key1)
        with self.assertRaises(PasswordError):
            decrypt_data(ct, key2)

    def test_tampered_data(self):
        key = generate_key()
        ct = encrypt_data(self.test_data, key)
        tampered = bytearray(ct)
        tampered[-5] ^= 0xFF
        with self.assertRaises(TamperedError):
            decrypt_data(bytes(tampered), key)

    def test_different_salt_each_time(self):
        pwd = "same-password"
        ct1 = encrypt_with_password(self.test_data, pwd)
        ct2 = encrypt_with_password(self.test_data, pwd)
        self.assertNotEqual(ct1, ct2)

    def test_invalid_file_format(self):
        key = generate_key()
        with self.assertRaises(CryptoError):
            decrypt_data(b"not valid encrypted data", key)

    def test_key_size(self):
        self.assertEqual(len(generate_key()), KEY_SIZE)

    def test_wrong_key_size(self):
        with self.assertRaises(CryptoError):
            encrypt_data(self.test_data, b"short-key")


class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_read_key_file(self):
        kp = os.path.join(self.tmpdir, "test.key")
        key = write_key_file(kp)
        self.assertEqual(len(key), KEY_SIZE)
        key2 = read_key_file(kp)
        self.assertEqual(key, key2)

    def test_no_force_overwrite(self):
        kp = os.path.join(self.tmpdir, "test.key")
        write_key_file(kp)
        with self.assertRaises(Exception):
            write_key_file(kp, force=False)

    def test_force_overwrite(self):
        kp = os.path.join(self.tmpdir, "test.key")
        k1 = write_key_file(kp)
        k2 = write_key_file(kp, force=True)
        self.assertNotEqual(k1, k2)

    def test_nonexistent_key_file(self):
        with self.assertRaises(Exception):
            read_key_file(os.path.join(self.tmpdir, "nope.key"))


class TestFileHandler(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_file(self, name, content=None):
        path = os.path.join(self.tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content or f"content of {name}".encode())
        return path

    def test_encrypt_decrypt_single_file_with_key(self):
        key = generate_key()
        src = self._make_file("test.env", b"DB_PASSWORD=secret123\n")
        res = encrypt_file(src, key=key)
        self.assertTrue(res.success)
        self.assertTrue(os.path.exists(res.target))
        self.assertTrue(res.target.endswith(DEFAULT_EXT))

        os.unlink(src)
        res2 = decrypt_file(res.target, key=key)
        self.assertTrue(res2.success)
        with open(res2.target, "rb") as f:
            self.assertEqual(f.read(), b"DB_PASSWORD=secret123\n")

    def test_encrypt_decrypt_single_file_with_password(self):
        pwd = "test-password"
        src = self._make_file("config.yaml", b"key: value\n")
        res = encrypt_file(src, password=pwd)
        self.assertTrue(res.success)

        os.unlink(src)
        res2 = decrypt_file(res.target, password=pwd)
        self.assertTrue(res2.success)
        with open(res2.target, "rb") as f:
            self.assertEqual(f.read(), b"key: value\n")

    def test_decrypt_wrong_password(self):
        src = self._make_file("x.json", b"{}")
        res = encrypt_file(src, password="right")
        self.assertTrue(res.success)
        res2 = decrypt_file(res.target, password="wrong")
        self.assertFalse(res2.success)
        self.assertIn("密码错误", res2.error or "")

    def test_is_config_file(self):
        self.assertTrue(is_config_file(".env"))
        self.assertTrue(is_config_file(".env.local"))
        self.assertTrue(is_config_file("config.yaml"))
        self.assertTrue(is_config_file("config.yml"))
        self.assertTrue(is_config_file("settings.json"))
        self.assertTrue(is_config_file("app.toml"))
        self.assertFalse(is_config_file("main.py"))
        self.assertFalse(is_config_file("README.md"))

    def test_collect_files(self):
        self._make_file(".env")
        self._make_file("config.yaml")
        self._make_file("sub/app.yml")
        self._make_file("main.py")
        self._make_file("data.csv")

        files = collect_files(self.tmpdir, recursive=True, config_only=True)
        basenames = [os.path.basename(f) for f in files]
        self.assertIn(".env", basenames)
        self.assertIn("config.yaml", basenames)
        self.assertIn("app.yml", basenames)
        self.assertNotIn("main.py", basenames)
        self.assertNotIn("data.csv", basenames)

    def test_bulk_encrypt_decrypt_directory(self):
        key = generate_key()
        self._make_file(".env", b"ENV=prod\n")
        self._make_file("config.yaml", b"a: 1\n")
        self._make_file("sub/app.json", b"{}")

        results = encrypt_directory_bulk(self.tmpdir, key=key, force=True)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertTrue(r.success, r.error)

        for f in [".env", "config.yaml", "sub/app.json"]:
            os.unlink(os.path.join(self.tmpdir, f))

        results2 = decrypt_directory_bulk(self.tmpdir, key=key, force=True)
        self.assertEqual(len(results2), 3)
        for r in results2:
            self.assertTrue(r.success, r.error)

        with open(os.path.join(self.tmpdir, ".env"), "rb") as f:
            self.assertEqual(f.read(), b"ENV=prod\n")

    def test_archive_encrypt_decrypt_directory(self):
        key = generate_key()
        self._make_file(".env", b"KEY=123\n")
        self._make_file("nested/deep.conf", b"setting=value\n")

        archive_path = os.path.join(self.tmpdir, "all.ccrypt")
        out_dir = os.path.join(self.tmpdir, "restored")

        res = encrypt_directory_archive(self.tmpdir, archive_path, key=key, force=True)
        self.assertTrue(res.success, res.error)

        res2 = decrypt_directory_archive(archive_path, out_dir, key=key, force=True)
        self.assertTrue(res2.success, res2.error)

        self.assertTrue(os.path.exists(os.path.join(out_dir, ".env")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "nested", "deep.conf")))
        with open(os.path.join(out_dir, ".env"), "rb") as f:
            self.assertEqual(f.read(), b"KEY=123\n")

    def test_custom_output_path(self):
        key = generate_key()
        src = self._make_file("a.env", b"x")
        custom_out = os.path.join(self.tmpdir, "my.enc")
        res = encrypt_file(src, custom_out, key=key)
        self.assertTrue(res.success)
        self.assertEqual(res.target, custom_out)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, args):
        from cryptotool.cli import main
        sys.argv = ["config-crypt"] + args
        try:
            return main()
        except SystemExit as e:
            return e.code

    def test_help(self):
        rc = self._run(["--help"])
        self.assertEqual(rc, 0)

    def test_version(self):
        rc = self._run(["--version"])
        self.assertEqual(rc, 0)

    def test_gen_key(self):
        kp = os.path.join(self.tmpdir, "my.key")
        rc = self._run(["gen-key", "-k", kp])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(kp))
        self.assertEqual(os.path.getsize(kp), 32)

    def test_encrypt_decrypt_cli_with_keyfile(self):
        kp = os.path.join(self.tmpdir, "k.key")
        self._run(["gen-key", "-k", kp])

        env_file = os.path.join(self.tmpdir, ".env")
        with open(env_file, "w") as f:
            f.write("HELLO=WORLD\n")

        rc = self._run(["encrypt", env_file, "-k", kp])
        self.assertEqual(rc, 0)
        enc = env_file + DEFAULT_EXT
        self.assertTrue(os.path.exists(enc))

        os.unlink(env_file)
        rc = self._run(["decrypt", enc, "-k", kp])
        self.assertEqual(rc, 0)
        with open(env_file) as f:
            self.assertEqual(f.read(), "HELLO=WORLD\n")

    def test_list(self):
        Path(self.tmpdir, ".env").write_text("a=1")
        Path(self.tmpdir, "cfg.yaml").write_text("x: 1")
        Path(self.tmpdir, "code.py").write_text("print(1)")
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            rc = self._run(["list"])
            self.assertEqual(rc, 0)
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
