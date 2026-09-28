"""Файлы ключей: атомарная запись 0600, проверка прав, шифрование секретов паролем (scrypt+ChaCha20)"""
from __future__ import annotations

import getpass
import json
import os
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import crypto as c

KEYFILE_FORMAT = "secure-terminal-keyfile/v1"
KEYFILE_AAD = b"SECURE-TERMINAL/v2 KEYFILE"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1      # ~32 МБ памяти и ~0,1 с на попытку
PASSPHRASE_ENV = "ST_PASSPHRASE_FILE"
MIN_PASSPHRASE = 12
POSIX = os.name == "posix"


class KeyFileError(Exception):
    pass
def get_passphrase(*, confirm: bool = False) -> bytes:
    path = os.environ.get(PASSPHRASE_ENV)
    if path:
        check_permissions(path, secret=True)
        with open(path, "rb") as f:
            pw = f.read().rstrip(b"\r\n")
    elif sys.stdin.isatty():
        pw = getpass.getpass("Пароль файла ключей: ").encode()
        if confirm and getpass.getpass("Повторите пароль: ").encode() != pw:
            raise KeyFileError("пароли не совпали")
    else:
        raise KeyFileError(f"файл ключей зашифрован: укажите файл с паролем в {PASSPHRASE_ENV}")
    if len(pw) < MIN_PASSPHRASE:
        raise KeyFileError(f"пароль короче {MIN_PASSPHRASE} символов")
    return pw


def encrypt_json(data: dict, passphrase: bytes) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase)
    ct = ChaCha20Poly1305(key).encrypt(nonce, json.dumps(data).encode(), KEYFILE_AAD)
    return {"format": KEYFILE_FORMAT,
            "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": c.b64e(salt)},
            "aead": "chacha20poly1305", "nonce": c.b64e(nonce), "ciphertext": c.b64e(ct)}


def decrypt_json(blob: dict, passphrase: bytes) -> dict:
    kdf = blob.get("kdf", {})
    if kdf.get("name") != "scrypt" or blob.get("aead") != "chacha20poly1305":
        raise KeyFileError("неизвестный формат зашифрованного файла ключей")
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    if not (2 ** 14 <= n <= 2 ** 17 and n & (n - 1) == 0 and 1 <= r <= 8 and 1 <= p <= 4):
        raise KeyFileError("недопустимые параметры scrypt в файле ключей")
    key = Scrypt(salt=c.b64d(kdf["salt"]), length=32, n=n, r=r, p=p).derive(passphrase)
    try:
        pt = ChaCha20Poly1305(key).decrypt(c.b64d(blob["nonce"]), c.b64d(blob["ciphertext"]), KEYFILE_AAD)
    except InvalidTag:
        raise KeyFileError("неверный пароль или файл ключей повреждён") from None
    return json.loads(pt)


def is_encrypted(data: dict) -> bool:
    return isinstance(data, dict) and data.get("format") == KEYFILE_FORMAT


def check_permissions(path: str, *, secret: bool) -> None:
    """Секрет, доступный группе/всем, не читаем; реестр, доступный на запись другим, тоже."""
    if not POSIX:
        return
    mode = os.stat(path).st_mode & 0o777
    bad = mode & (0o077 if secret else 0o022)
    if bad:
        need = "600" if secret else "644 или 600"
        raise KeyFileError(f"{path}: права {oct(mode)[2:]} слишком открыты, выполните chmod {need}")


def ensure_dir(path: str) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        if POSIX:
            os.chmod(path, 0o700)
    elif POSIX and os.stat(path).st_mode & 0o077:
        print(f"warning: папка {path} доступна другим пользователям (рекомендуется chmod 700)", file=sys.stderr)


def write_json_secure(path: str, data: dict) -> None:
    """Атомарная запись через временный файл 0600 + rename; симлинк заменяется, а не читается"""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_secret(path: str, data: dict, passphrase: bytes | None) -> None:
    write_json_secure(path, encrypt_json(data, passphrase) if passphrase else data)


def load_secret_json(path: str, passphrase: bytes | None = None) -> dict:
    check_permissions(path, secret=True)
    data = read_json(path)
    if is_encrypted(data):
        data = decrypt_json(data, passphrase or get_passphrase())
    return data


def load_server_keys(path: str, passphrase: bytes | None = None) -> c.ServerKeys:
    return c.ServerKeys.from_json(load_secret_json(path, passphrase))


def load_terminal_keys(path: str, passphrase: bytes | None = None) -> c.TerminalKeys:
    return c.TerminalKeys.from_json(load_secret_json(path, passphrase))


def load_registry(path: str) -> dict[str, c.TerminalPublic]:
    check_permissions(path, secret=False)
    data = read_json(path)
    terms = {}
    for kid, t in data.get("terminals", {}).items():
        if not c.KEY_ID_RE.fullmatch(kid):
            raise ValueError(f"invalid key_id in registry: {kid!r}")
        terms[kid] = c.TerminalPublic.from_json(t)
    return terms


def save_registry(path: str, terminals: dict[str, c.TerminalPublic]) -> None:
    write_json_secure(path, {"protocol": c.PROTOCOL,
                             "terminals": {k: t.to_json() for k, t in sorted(terminals.items())}})
