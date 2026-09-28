from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Annotated, Callable, Literal, Union

import anyio
from anyio import to_thread
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StringConstraints, ValidationError
from starlette.exceptions import HTTPException

import crypto as c
import keystore as ks
from store import EventRecord, Store, canonical_payload

log = logging.getLogger("secure_terminal.security")

HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
H_SERVER_TIME = "X-Server-Time"

CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,9}")   # только ASCII-цифры (str.isdigit пропустил бы '²')
EVENT_ID_RE = re.compile(r"[0-9a-f]{32}")

# Для неизвестного key_id подпись проверяется на этом ключе: время ответа одинаковое
DUMMY_KEY = c.SigningKey.generate().verify_key()


@dataclass(frozen=True)
class Settings:
    """Лимиты. None у частоты — лимит выключен (для тестов)."""
    ip_rate: float | None = 20.0
    ip_burst: int = 40
    key_rate: float | None = 10.0
    key_burst: int = 20
    max_nonces_per_key: int = 2_000
    max_events_per_key: int = 1_000_000
    event_retention_days: int = 0
    verify_concurrency: int = field(default_factory=lambda: os.cpu_count() or 2)
    max_verify_queue: int = 64
    registry_reload_seconds: float = 1.0


# ─── схема тела ───────────────────────────────

Key = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
Value = Union[StrictBool, Annotated[StrictInt, Field(ge=-(2**53), le=2**53)], Annotated[str, StringConstraints(max_length=256)]]


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_type: Literal["login", "logout", "operation", "status"]
    occurred_at: Annotated[StrictInt, Field(ge=1_577_836_800, le=4_102_444_800)]
    payload: Annotated[dict[Key, Value], Field(max_length=32)] = {}


# ─── вспомогательное ──────────────────────────

def safe(value: object, limit: int = 200) -> str:
    """Для логов непечатаемые символы экранируются, длина ограничена."""
    s = str(value)[:limit]
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}"
                   for ch in s)


class Reject(Exception):
    """Отказ до аутентификации (открытый ответ)."""

    def __init__(self, status: int, code: str, reason: str = "", headers: dict | None = None) -> None:
        self.status, self.code, self.reason, self.headers = status, code, reason or code, headers or {}


class SealedReject(Exception):
    """Отказ после проверки подписи: ответ зашифрован для терминала и подписан сервером."""

    def __init__(self, auth: "Auth", status: int, code: str) -> None:
        self.auth, self.status, self.code = auth, status, code


@dataclass
class Auth:
    key_id: str
    terminal: c.TerminalPublic
    method: str
    target: str
    ts: str
    nonce: str
    signature: bytes
    body: bytes
    info: bytes


def plain_error(status: int, code: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers={**HEADERS, **(headers or {})})


class RateLimiter:
    """Token bucket на ключ (IP или key_id). Таблица ограничена по размеру (LRU)."""

    def __init__(self, rate: float, burst: int, max_entries: int = 100_000,
                 now: Callable[[], float] = time.monotonic) -> None:
        self.rate, self.burst, self.max_entries, self.now = rate, burst, max_entries, now
        self.buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        t = self.now()
        tokens, last = self.buckets.pop(key, (float(self.burst), t))
        tokens = min(float(self.burst), tokens + (t - last) * self.rate)
        ok = tokens >= 1.0
        self.buckets[key] = (tokens - 1.0 if ok else tokens, t)
        if len(self.buckets) > self.max_entries:
            self.buckets.popitem(last=False)
        return ok


class IPRateLimit:
    """ASGI-прослойка: лимит по IP до чтения тела. За прокси берёт X-Forwarded-For."""

    def __init__(self, app, limiter: RateLimiter | None) -> None:
        self.app, self.limiter = app, limiter

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.limiter is not None:
            client = scope.get("client")
            ip = client[0] if client else "-"
            if not self.limiter.allow(ip):
                log.warning("rate limited ip=%s %s", safe(ip), safe(scope.get("path", "")))
                return await plain_error(429, "rate_limited", {"Retry-After": "1"})(scope, receive, send)
        return await self.app(scope, receive, send)


class Registry:
    """Реестр терминалов с горячей перезагрузкой: регистрация/отзыв без перезапуска."""

    def __init__(self, keys: c.ServerKeys, path: str | None, interval: float) -> None:
        self.keys, self.path, self.interval = keys, path, interval
        self._stamp: tuple | None = None
        self._checked = 0.0
        if path:
            self.reload(initial=True)

    def maybe_reload(self) -> None:
        if not self.path:
            return
        t = time.monotonic()
        if t - self._checked >= self.interval:
            self._checked = t
            self.reload()

    def reload(self, initial: bool = False) -> None:
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
            if stamp == self._stamp:
                return
            terms = ks.load_registry(self.path)
        except (OSError, ValueError, KeyError, TypeError, ks.KeyFileError) as e:
            if initial:
                raise
            log.error("registry reload failed, keeping previous registry: %s", safe(e))
            return
        self.keys.terminals, self._stamp = terms, stamp
        log.info("registry loaded: %d terminals, %d revoked", len(terms), sum(t.revoked for t in terms.values()))


def create_app(keys: c.ServerKeys, *, clock: Callable[[], int] = c.now, store: Store | None = None,
               settings: Settings | None = None, registry_path: str | None = None) -> FastAPI:
    settings = settings or Settings()
    store = store or Store(":memory:")
    registry = Registry(keys, registry_path, settings.registry_reload_seconds)
    ip_limiter = RateLimiter(settings.ip_rate, settings.ip_burst) if settings.ip_rate else None
    key_limiter = RateLimiter(settings.key_rate, settings.key_burst) if settings.key_rate else None
    verify_limiter = anyio.CapacityLimiter(settings.verify_concurrency)
    skew = c.MAX_CLOCK_SKEW_SECONDS
    retention = settings.event_retention_days * 86_400 or None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(IPRateLimit, limiter=ip_limiter)
    app.state.keys, app.state.store, app.state.settings, app.state.registry = keys, store, settings, registry

    # Для хранилища в памяти nonce теряются при рестарте: не принимаем запросы старше старта.
    started_at = clock()

    async def reply(auth: Auth, status: int, content: dict) -> Response:
        if status >= 400:
            log.warning("rejected request from %s: %s", auth.key_id, content.get("error"))
        plaintext = json.dumps(content, separators=(",", ":")).encode()
        headers, body = await to_thread.run_sync(
            c.seal_response, keys, auth.terminal, auth.key_id, auth.nonce, status, plaintext, clock())
        return Response(body, status_code=status, headers={**HEADERS, **headers})

    @app.exception_handler(Reject)
    async def on_reject(request: Request, e: Reject):
        log.warning("rejected %s %s: %s", request.method, safe(request.url.path), safe(e.reason))
        return plain_error(e.status, e.code, e.headers)

    @app.exception_handler(SealedReject)
    async def on_sealed_reject(request: Request, e: SealedReject):
        return await reply(e.auth, e.status, {"error": e.code})

    @app.exception_handler(HTTPException)            # 404 / 405
    async def on_http_error(request: Request, e: HTTPException):
        return plain_error(e.status_code, {404: "not_found", 405: "method_not_allowed"}.get(e.status_code, "bad_request"))

    @app.exception_handler(Exception)
    async def on_crash(request: Request, e: Exception):
        log.exception("unhandled error")
        return plain_error(500, "internal_error")

    async def authenticate(request: Request) -> Auth:
        h = request.headers
        kid, ts, nonce, sig = h.get(c.H_KEY_ID), h.get(c.H_TIMESTAMP), h.get(c.H_NONCE), h.get(c.H_SIGNATURE)
        if not (kid and ts and nonce and sig and c.KEY_ID_RE.fullmatch(kid) and c.TIMESTAMP_RE.fullmatch(ts)
                and c.NONCE_RE.fullmatch(nonce) and c.SIGNATURE_RE.fullmatch(sig)):
            raise Reject(401, "unauthorized", "bad auth headers")
        signature = c.b64d_canonical(sig)
        if signature is None:
            raise Reject(401, "unauthorized", "non-canonical signature encoding")
        now = clock()
        if abs(now - int(ts)) > skew or (not store.durable and int(ts) < started_at):
            # Проверка идёт до ключей, так что атакующий узнаёт только время сервера (X-Server-Time).
            raise Reject(401, "stale_timestamp", f"stale timestamp ({kid}, skew {int(ts) - now:+d}s)",
                         {H_SERVER_TIME: str(now)})
        cl = h.get("content-length")
        if cl is not None and (not CONTENT_LENGTH_RE.fullmatch(cl) or int(cl) > c.MAX_BODY_BYTES):
            raise Reject(413, "payload_too_large")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > c.MAX_BODY_BYTES:
                raise Reject(413, "payload_too_large")
            chunks.append(chunk)
        body = b"".join(chunks)

        # Путь подписывается как пришёл (вместе с query).
        raw_path = request.scope.get("raw_path") or request.scope["path"].encode()
        query = request.scope.get("query_string", b"")
        try:
            target = (raw_path + b"?" + query if query else raw_path).decode("ascii")
        except UnicodeDecodeError:
            raise Reject(400, "bad_request", "non-ascii path")

        registry.maybe_reload()
        terminal = keys.terminal(kid)
        signed = c.request_to_sign(request.method, target, kid, ts, nonce, body)
        # Проверка подписи — CPU: в пул потоков, с ограничением очереди.
        if verify_limiter.statistics().tasks_waiting >= settings.max_verify_queue:
            raise Reject(503, "busy", "verify queue full")
        vk = terminal.sign if terminal else DUMMY_KEY
        valid = await to_thread.run_sync(vk.verify, signature, signed, limiter=verify_limiter)
        if terminal is None or not valid:
            raise Reject(401, "unauthorized", f"bad signature or unknown key ({kid})")

        auth = Auth(kid, terminal, request.method, target, ts, nonce, signature, body,
                    c.request_info(request.method, target, kid, ts, nonce))
        if key_limiter is not None and not key_limiter.allow(kid):
            raise SealedReject(auth, 429, "rate_limited")
        result = await to_thread.run_sync(store.claim_nonce, kid, nonce, now + 2 * skew + 1, now,
                                          settings.max_nonces_per_key)
        if result == "replay":
            raise Reject(401, "unauthorized", f"replay ({kid})")
        if result == "full":                  # квота этого терминала; остальные не затронуты
            raise SealedReject(auth, 429, "rate_limited")
        return auth

    @app.get("/v1/health")
    async def health():
        return JSONResponse({"status": "ok"}, headers=HEADERS)

    @app.post("/v1/events")
    async def post_event(request: Request):
        auth = await authenticate(request)

        # Только зашифрованное тело (защита от отправки открытого JSON).
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != c.CONTENT_TYPE:
            return await reply(auth, 415, {"error": "unsupported_media_type"})

        plaintext = await to_thread.run_sync(c.open_sealed, auth.body, keys.kem, auth.info)
        if plaintext is None:
            return await reply(auth, 400, {"error": "undecryptable"})
        try:
            event = EventIn.model_validate_json(plaintext)
        except ValidationError:
            return await reply(auth, 422, {"error": "invalid_body"})

        received_at = clock()
        record = EventRecord(uuid.uuid4().hex, auth.key_id, received_at, event.event_type, event.occurred_at,
                             canonical_payload(event.payload), auth.method, auth.target, auth.ts, auth.nonce,
                             auth.signature, auth.body)
        result = await to_thread.run_sync(
            lambda: store.add_event(record, max_per_owner=settings.max_events_per_key,
                                    retention_cutoff=received_at - retention if retention else None))
        if result == "quota":
            return await reply(auth, 429, {"error": "quota_exceeded"})
        return await reply(auth, 201, {"event_id": record.event_id, "status": "accepted"})

    @app.get("/v1/events/{event_id}")
    async def get_event(event_id: str, request: Request):
        auth = await authenticate(request)
        if auth.body:
            return await reply(auth, 400, {"error": "bad_request"})

        event = await to_thread.run_sync(store.get_event, event_id, auth.key_id) \
            if EVENT_ID_RE.fullmatch(event_id) else None
        if event is None:                                               # чужое = несуществующее
            return await reply(auth, 404, {"error": "not_found"})
        return await reply(auth, 200, event)

    return app

ENV_KEYS, ENV_REGISTRY, ENV_DB = "ST_SERVER_KEYS", "ST_REGISTRY", "ST_DB"


def app_from_env() -> FastAPI:
    """Фабрика для uvicorn (каждый воркер вызывает её сам). Настройки — из переменных окружения."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    keys_path = os.environ.get(ENV_KEYS) or os.environ.get("SERVER_KEYS_FILE", "keys/server.json")
    registry = os.environ.get(ENV_REGISTRY) or None
    keys = ks.load_server_keys(keys_path)
    if registry is None and not keys.terminals:
        raise SystemExit("нет реестра терминалов: укажите --registry")
    db = os.environ.get(ENV_DB, "data/journal.db")
    os.makedirs(os.path.dirname(os.path.abspath(db)), mode=0o700, exist_ok=True)
    return create_app(keys, store=Store(db), registry_path=registry)


def tls13_context(config, default_factory) -> ssl.SSLContext:
    """Только TLS 1.3 (передаётся в uvicorn как ssl_context_factory)."""
    ctx = default_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cmd_serve(a: argparse.Namespace) -> int:
    import uvicorn
    tls = bool(a.tls_cert or a.tls_key)
    if tls and not (a.tls_cert and a.tls_key):
        sys.exit("нужны оба параметра: --tls-cert и --tls-key")
    if not tls and not _is_loopback(a.host):
        sys.exit(f"отказ: без TLS сервер слушает только loopback, а не {a.host}. "
                 "Укажите --tls-cert/--tls-key или поставьте TLS-прокси и --behind-proxy")
    if a.behind_proxy and (tls or not _is_loopback(a.host)):
        sys.exit("--behind-proxy: сервер слушает 127.0.0.1 без TLS, TLS держит прокси")
    for path in (a.keys, a.registry):
        if not os.path.exists(path):
            sys.exit(f"нет файла {path} (см. keytool.py server-init)")
    os.makedirs(os.path.dirname(os.path.abspath(a.db)), mode=0o700, exist_ok=True)
    if a.passphrase_file:
        os.environ[ks.PASSPHRASE_ENV] = a.passphrase_file
    # Ключи и пароль проверяем заранее, в основном процессе.
    try:
        ks.load_server_keys(a.keys)
        ks.load_registry(a.registry)
    except (ks.KeyFileError, OSError, ValueError, KeyError) as e:
        sys.exit(f"ошибка ключей: {e}")
    os.environ.update({ENV_KEYS: a.keys, ENV_REGISTRY: a.registry, ENV_DB: a.db})

    uvicorn.run("server:app_from_env", factory=True, host=a.host, port=a.port, workers=a.workers,
                server_header=False, proxy_headers=a.behind_proxy,
                forwarded_allow_ips="127.0.0.1,::1" if a.behind_proxy else "",
                limit_concurrency=a.limit_concurrency, timeout_keep_alive=5,
                ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key,
                ssl_context_factory=tls13_context if tls else None)
    return 0


def cmd_verify_journal(a: argparse.Namespace) -> int:
    if a.passphrase_file:
        os.environ[ks.PASSPHRASE_ENV] = a.passphrase_file
    terms = ks.load_registry(a.registry)
    server_kem = ks.load_server_keys(a.keys).kem if a.keys else None
    if not os.path.exists(a.db):
        sys.exit(f"нет базы {a.db}")
    n, errors, head = Store(a.db).verify_journal(terms, server_kem)
    for e in errors:
        print("FAIL", e)
    print(f"записей: {n}, ошибок: {len(errors)}, головной хеш: {head.hex()}")
    if not a.keys:
        print("(содержимое не сверялось с шифртекстом: для этого добавьте --keys server.json)")
    return 1 if errors else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SECURE-TERMINAL/v2 server")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="запустить сервер")
    s.add_argument("--keys", default="keys/server.json")
    s.add_argument("--registry", default="keys/terminals.json", help="реестр терминалов (перечитывается на лету)")
    s.add_argument("--db", default="data/journal.db")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--workers", type=int, default=1)
    s.add_argument("--tls-cert", help="сертификат (PEM, цепочка)")
    s.add_argument("--tls-key", help="закрытый ключ сертификата (PEM)")
    s.add_argument("--behind-proxy", action="store_true", help="за nginx: брать IP клиента из X-Forwarded-For")
    s.add_argument("--limit-concurrency", type=int, default=256)
    s.add_argument("--passphrase-file", help="файл с паролем, если server.json зашифрован")
    s.set_defaults(fn=cmd_serve)

    v = sub.add_parser("verify-journal", help="проверить журнал: цепочку хешей и подписи терминалов")
    v.add_argument("--db", default="data/journal.db")
    v.add_argument("--registry", default="keys/terminals.json")
    v.add_argument("--keys", help="server.json — чтобы сверить сохранённые поля с шифртекстом")
    v.add_argument("--passphrase-file")
    v.set_defaults(fn=cmd_verify_journal)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
