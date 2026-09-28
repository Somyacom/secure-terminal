from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
#hpke - hibrid public key encryption 
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives import hpke
from cryptography.exceptions import InvalidSignature, InvalidTag
""" """
PROTOCOL = "SECURE-TERMINAL/v2"
H_KEY_ID = "X-Key-Id"
H_TIMESTAMP = "X-Timestamp"
H_NONCE = "X-Nonce"
H_SIGNATURE = "X-Signature"
CONTENT_TYPE = "application/vnd.secure-terminal.v2+hpke"
MAX_CLOCK_SKEW_SECONDS = 30 # допустимое расхождение часов терминала и сервера
NONCE_BYTES = 16
MAX_PLAINTEXT_BYTES = 16 * 1024 #максимальный размер JSON до шифрования
ED25519_SIG_LEN = 64
MLDSA65_SIG_LEN = 3309
#Suite - выбор конкретного алгоритма из трех этапов для hpke
#  KEM.MLKEM768_X25519 - гибридный KEM (key encapsulation mechanism), со смешением секретов от X25519 (эллиптические кривые без постквантовости) и ML-KEM(зная секрет (базис решетки) можно найти ближайшую точку к заданной, но без знания это нп-хард)
#  KDF.HKDF_SHA256 - функция выработки ключей. (берет сырой общий секрет и превращает его в криптографический ключ, подходящей длины для шифрования 
# Authenticated Encryption with Associated Data. AEAD.CHACHA20_POLY1305 - шифр, который не только шифрует, но и проверяет целостность сообщения.  
HYBRID_SIG_LEN = ED25519_SIG_LEN + MLDSA65_SIG_LEN
SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
HPKE_OVERHEAD = hpke.KEM.MLKEM768_X25519.enc_length() + 16
MAX_BODY_BYTES = MAX_PLAINTEXT_BYTES + HPKE_OVERHEAD

MLDSA_CONTEXT = PROTOCOL.encode("ascii")
# fullmatch: завершающий '\n' не пройдёт (иначе попал бы в подписываемую строку как разделитель).
KEY_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
TIMESTAMP_RE = re.compile(r"[0-9]{1,12}")
NONCE_RE = re.compile(r"[0-9a-f]{%d}" % (NONCE_BYTES * 2))
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{4498}")


def now() -> int:
    return int(time.time())


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64d_canonical(text: str) -> bytes | None:
    """Строгая каноничная кодировка: неканоничные хвостовые биты отвергаются."""
    try:
        raw = b64d(text)
    except (ValueError, TypeError):
        return None
    return raw if b64e(raw) == text else None


def fingerprint(public_json: dict) -> str:
    digest = hashlib.sha256(json.dumps(public_json, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


@dataclass(frozen=True)
class VerifyKey:
    ed: ed25519.Ed25519PublicKey
    ml: mldsa.MLDSA65PublicKey

    def verify(self, signature: bytes, message: bytes) -> bool:
        # Обе части проверяются всегда без досрочного выхода — чтобы не угадать по времени, какая неверна.
        if len(signature) != HYBRID_SIG_LEN:
            return False
        ed_sig, ml_sig = signature[:ED25519_SIG_LEN], signature[ED25519_SIG_LEN:]
        ok = True
        try:
            self.ed.verify(ed_sig, message)
        except InvalidSignature:
            ok = False
        try:
            self.ml.verify(ml_sig, message, MLDSA_CONTEXT)
        except InvalidSignature:
            ok = False
        return ok

    def to_json(self) -> dict:
        return {"ed25519": b64e(self.ed.public_bytes_raw()), "mldsa65": b64e(self.ml.public_bytes_raw())}

    @classmethod
    def from_json(cls, d: dict) -> "VerifyKey":
        return cls(ed25519.Ed25519PublicKey.from_public_bytes(b64d(d["ed25519"])),
                   mldsa.MLDSA65PublicKey.from_public_bytes(b64d(d["mldsa65"])))


@dataclass(frozen=True)
class SigningKey:
    ed: ed25519.Ed25519PrivateKey
    ml: mldsa.MLDSA65PrivateKey

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate())

    def sign(self, message: bytes) -> bytes:
        return self.ed.sign(message) + self.ml.sign(message, MLDSA_CONTEXT)

    def verify_key(self) -> VerifyKey:
        return VerifyKey(self.ed.public_key(), self.ml.public_key())

    def to_json(self) -> dict:
        return {"ed25519": b64e(self.ed.private_bytes_raw()), "mldsa65": b64e(self.ml.private_bytes_raw())}

    @classmethod
    def from_json(cls, d: dict) -> "SigningKey":
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(b64d(d["ed25519"])),
                   mldsa.MLDSA65PrivateKey.from_seed_bytes(b64d(d["mldsa65"])))


@dataclass(frozen=True)
class KemPublicKey:
    mlkem: mlkem.MLKEM768PublicKey
    x25519: x25519.X25519PublicKey

    def hpke_key(self) -> hpke.MLKEM768X25519PublicKey:
        return hpke.MLKEM768X25519PublicKey(self.mlkem, self.x25519)

    def to_json(self) -> dict:
        return {"mlkem768": b64e(self.mlkem.public_bytes_raw()), "x25519": b64e(self.x25519.public_bytes_raw())}

    @classmethod
    def from_json(cls, d: dict) -> "KemPublicKey":
        return cls(mlkem.MLKEM768PublicKey.from_public_bytes(b64d(d["mlkem768"])),
                   x25519.X25519PublicKey.from_public_bytes(b64d(d["x25519"])))


@dataclass(frozen=True)
class KemPrivateKey:
    mlkem: mlkem.MLKEM768PrivateKey
    x25519: x25519.X25519PrivateKey

    @classmethod
    def generate(cls) -> "KemPrivateKey":
        return cls(mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate())

    def hpke_key(self) -> hpke.MLKEM768X25519PrivateKey:
        return hpke.MLKEM768X25519PrivateKey(self.mlkem, self.x25519)

    def public(self) -> KemPublicKey:
        return KemPublicKey(self.mlkem.public_key(), self.x25519.public_key())

    def to_json(self) -> dict:
        return {"mlkem768": b64e(self.mlkem.private_bytes_raw()), "x25519": b64e(self.x25519.private_bytes_raw())}

    @classmethod
    def from_json(cls, d: dict) -> "KemPrivateKey":
        return cls(mlkem.MLKEM768PrivateKey.from_seed_bytes(b64d(d["mlkem768"])),
                   x25519.X25519PrivateKey.from_private_bytes(b64d(d["x25519"])))


def seal(plaintext: bytes, recipient: KemPublicKey, info: bytes) -> bytes:
    """Каждый вызов — новая капсула и новый ключ."""
    return SUITE.encrypt(plaintext, recipient.hpke_key(), info=info)


def open_sealed(ciphertext: bytes, recipient: KemPrivateKey, info: bytes) -> bytes | None:
    if len(ciphertext) < HPKE_OVERHEAD:
        return None
    try:
        return SUITE.decrypt(ciphertext, recipient.hpke_key(), info=info)
    except (InvalidTag, ValueError):
        return None


def _lines(*parts: str) -> bytes:
    return "\n".join(parts).encode("ascii")


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_to_sign(method: str, target: str, key_id: str, ts: str, nonce: str, body: bytes) -> bytes:
    return _lines(f"{PROTOCOL} REQUEST", method.upper(), target, key_id, ts, nonce, body_digest(body))


def response_to_sign(status: int, key_id: str, request_nonce: str, ts: str, body: bytes) -> bytes:
    return _lines(f"{PROTOCOL} RESPONSE", str(status), key_id, request_nonce, ts, body_digest(body))


def request_info(method: str, target: str, key_id: str, ts: str, nonce: str) -> bytes:
    return _lines(f"{PROTOCOL} REQUEST-BODY", method.upper(), target, key_id, ts, nonce)


def response_info(status: int, key_id: str, request_nonce: str, ts: str) -> bytes:
    return _lines(f"{PROTOCOL} RESPONSE-BODY", str(status), key_id, request_nonce, ts)


@dataclass
class TerminalPublic:
    sign: VerifyKey
    kem: KemPublicKey
    revoked: bool = False

    def to_json(self) -> dict:
        return {"sign": self.sign.to_json(), "kem": self.kem.to_json(), "revoked": self.revoked}

    @classmethod
    def from_json(cls, d: dict) -> "TerminalPublic":
        return cls(VerifyKey.from_json(d["sign"]), KemPublicKey.from_json(d["kem"]), bool(d.get("revoked", False)))


def terminal_public_bundle(key_id: str, t: TerminalPublic) -> dict:
    return {"type": "terminal-public", "protocol": PROTOCOL, "key_id": key_id,
            "sign": t.sign.to_json(), "kem": t.kem.to_json()}


def parse_terminal_public_bundle(d: dict) -> tuple[str, TerminalPublic]:
    if d.get("type") != "terminal-public" or d.get("protocol") != PROTOCOL:
        raise ValueError("not a terminal public key file for " + PROTOCOL)
    if not KEY_ID_RE.fullmatch(d["key_id"]):
        raise ValueError("invalid key_id")
    return d["key_id"], TerminalPublic(VerifyKey.from_json(d["sign"]), KemPublicKey.from_json(d["kem"]))


@dataclass
class ServerKeys:
    sign: SigningKey
    kem: KemPrivateKey
    terminals: dict[str, TerminalPublic] = field(default_factory=dict)

    def public_bundle(self) -> dict:
        return {"type": "server-public", "protocol": PROTOCOL,
                "sign": self.sign.verify_key().to_json(), "kem": self.kem.public().to_json()}

    def secrets_json(self) -> dict:
        return {"sign": self.sign.to_json(), "kem": self.kem.to_json()}

    def terminal(self, key_id: str) -> TerminalPublic | None:
        t = self.terminals.get(key_id)
        return None if t is None or t.revoked else t     # отозванный = неизвестный

    def revoke(self, key_id: str) -> None:
        if key_id in self.terminals:
            self.terminals[key_id].revoked = True

    def to_json(self) -> dict:
        return {"sign": self.sign.to_json(), "kem": self.kem.to_json(),
                "terminals": {k: {"sign": t.sign.to_json(), "kem": t.kem.to_json(), "revoked": t.revoked}
                              for k, t in self.terminals.items()}}

    @classmethod
    def from_json(cls, d: dict) -> "ServerKeys":
        terms = {}
        for k, t in d.get("terminals", {}).items():
            if not KEY_ID_RE.fullmatch(k):
                raise ValueError(f"invalid key_id in key file: {k!r}")
            terms[k] = TerminalPublic.from_json(t)
        return cls(SigningKey.from_json(d["sign"]), KemPrivateKey.from_json(d["kem"]), terms)


@dataclass
class TerminalKeys:
    key_id: str
    sign: SigningKey
    kem: KemPrivateKey
    server_sign: VerifyKey
    server_kem: KemPublicKey

    def to_json(self) -> dict:
        return {"key_id": self.key_id, "sign": self.sign.to_json(), "kem": self.kem.to_json(),
                "server": {"sign": self.server_sign.to_json(), "kem": self.server_kem.to_json()}}

    @classmethod
    def from_json(cls, d: dict) -> "TerminalKeys":
        if not KEY_ID_RE.fullmatch(d["key_id"]):
            raise ValueError("invalid key_id in key file")
        return cls(d["key_id"], SigningKey.from_json(d["sign"]), KemPrivateKey.from_json(d["kem"]),
                   VerifyKey.from_json(d["server"]["sign"]), KemPublicKey.from_json(d["server"]["kem"]))

    @classmethod
    def generate(cls, key_id: str, server_bundle: dict) -> "TerminalKeys":
        if not KEY_ID_RE.fullmatch(key_id):
            raise ValueError(f"invalid key_id: {key_id!r}")
        if server_bundle.get("type") != "server-public" or server_bundle.get("protocol") != PROTOCOL:
            raise ValueError("not a server public key file for " + PROTOCOL)
        return cls(key_id, SigningKey.generate(), KemPrivateKey.generate(),
                   VerifyKey.from_json(server_bundle["sign"]), KemPublicKey.from_json(server_bundle["kem"]))

    def public(self) -> TerminalPublic:
        return TerminalPublic(self.sign.verify_key(), self.kem.public())


def generate_keys(terminal_ids: list[str]) -> tuple[ServerKeys, dict[str, TerminalKeys]]:
    server = ServerKeys(SigningKey.generate(), KemPrivateKey.generate())
    terminals = {}
    for kid in terminal_ids:
        if not KEY_ID_RE.fullmatch(kid):
            raise ValueError(f"invalid key_id: {kid!r}")
        tk = TerminalKeys(kid, SigningKey.generate(), KemPrivateKey.generate(),
                          server.sign.verify_key(), server.kem.public())
        server.terminals[kid] = TerminalPublic(tk.sign.verify_key(), tk.kem.public())
        terminals[kid] = tk
    return server, terminals


def seal_request(keys: TerminalKeys, method: str, target: str, plaintext: bytes | None,
                 *, ts: int | None = None, nonce: str | None = None) -> tuple[dict[str, str], bytes]:
    ts_s = str(now() if ts is None else ts)
    nc = new_nonce() if nonce is None else nonce
    # GET без тела не шифруется: подпись покрывает хэш b"".
    body = b"" if plaintext is None else seal(
        plaintext, keys.server_kem, request_info(method, target, keys.key_id, ts_s, nc))
    sig = keys.sign.sign(request_to_sign(method, target, keys.key_id, ts_s, nc, body))
    headers = {H_KEY_ID: keys.key_id, H_TIMESTAMP: ts_s, H_NONCE: nc, H_SIGNATURE: b64e(sig)}
    if plaintext is not None:
        headers["Content-Type"] = CONTENT_TYPE
    return headers, body


def seal_response(server: ServerKeys, terminal: TerminalPublic, key_id: str, request_nonce: str,
                  status: int, plaintext: bytes, ts: int) -> tuple[dict[str, str], bytes]:
    ts_s = str(ts)
    body = seal(plaintext, terminal.kem, response_info(status, key_id, request_nonce, ts_s))
    sig = server.sign.sign(response_to_sign(status, key_id, request_nonce, ts_s, body))
    return {H_TIMESTAMP: ts_s, H_SIGNATURE: b64e(sig), "Content-Type": CONTENT_TYPE}, body


def open_response(keys: TerminalKeys, request_nonce: str, status: int,
                  headers: dict[str, str], body: bytes) -> bytes | None:
    """Проверить подпись сервера, свежесть, привязку к запросу и расшифровать. None — нельзя доверять."""
    h = {k.lower(): v for k, v in headers.items()}
    ts, sig = h.get(H_TIMESTAMP.lower()), h.get(H_SIGNATURE.lower())
    if not (ts and sig and TIMESTAMP_RE.fullmatch(ts) and SIGNATURE_RE.fullmatch(sig)):
        return None
    if abs(now() - int(ts)) > MAX_CLOCK_SKEW_SECONDS:
        return None
    if not keys.server_sign.verify(b64d(sig), response_to_sign(status, keys.key_id, request_nonce, ts, body)):
        return None
    return open_sealed(body, keys.kem, response_info(status, keys.key_id, request_nonce, ts))
