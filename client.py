from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time

import httpx

import crypto as c
import keystore as ks

# Пути только из простых символов: тогда httpx отправит их без URL-кодирования.
SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9/_.-]*")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
H_SERVER_TIME = "x-server-time"
class TerminalError(Exception):
    def __init__(self, status: int, code: str, signed: bool, skew: int | None = None) -> None:
        msg = f"{status} {code} (signed={signed})"
        if skew is not None:
            msg += f": часы терминала {'спешат' if skew > 0 else 'отстают'} на {abs(skew)} с, синхронизируйте время (NTP)"
        super().__init__(msg)
        self.status, self.code, self.signed, self.skew = status, code, signed, skew


def make_http(base_url: str, ca_file: str | None = None, timeout: float = 5.0) -> httpx.Client:
    """Транспорт: http:// только до localhost; TLS не ниже 1.3 с проверкой сертификата"""
    url = httpx.URL(base_url)
    if url.scheme == "http":
        if url.host not in LOOPBACK_HOSTS:
            raise ValueError(f"незащищённый http:// разрешён только для localhost, используйте https:// ({base_url})")
    elif url.scheme != "https":
        raise ValueError(f"неподдерживаемая схема: {url.scheme}")
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return httpx.Client(base_url=base_url, timeout=timeout, verify=ctx, follow_redirects=False)


class TerminalClient:
    def __init__(self, base_url: str, keys: c.TerminalKeys, *, http: httpx.Client | None = None,
                 ca_file: str | None = None) -> None:
        self.keys = keys
        self.http = http or make_http(base_url, ca_file)    # в тестах подменяется

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        if not SAFE_PATH_RE.fullmatch(path):
            raise ValueError(f"unsafe path: {path!r}")

        plaintext = None if body is None else json.dumps(body).encode()
        headers, wire_body = c.seal_request(self.keys, method, path, plaintext)
        resp = self.http.request(method, path, content=wire_body, headers=headers)

        # Ответ зашифрован и подписан — проверяем и расшифровываем.
        if resp.headers.get("content-type", "").startswith(c.CONTENT_TYPE):
            data = c.open_response(self.keys, headers[c.H_NONCE], resp.status_code, dict(resp.headers), resp.content)
            if data is None:
                raise TerminalError(resp.status_code, "response_not_authentic", signed=False)
            try:
                result = json.loads(data)
            except ValueError:
                result = None
            if not isinstance(result, dict):
                raise TerminalError(resp.status_code, "malformed_response", signed=True)
            if resp.is_success:
                return result
            raise TerminalError(resp.status_code, str(result.get("error", "unknown")), signed=True)

        # Открытый ответ: успехом быть не может (подделка), ошибке верим лишь условно.
        if resp.is_success:
            raise TerminalError(resp.status_code, "response_not_authentic", signed=False)
        try:
            code = str(resp.json()["error"])
        except (ValueError, KeyError, TypeError):
            code = "unknown"
        skew = None
        server_time = resp.headers.get(H_SERVER_TIME, "")
        if code == "stale_timestamp" and c.TIMESTAMP_RE.fullmatch(server_time):
            skew = int(headers[c.H_TIMESTAMP]) - int(server_time)
        raise TerminalError(resp.status_code, code, signed=False, skew=skew)

    def send_event(self, event_type: str, payload: dict | None = None) -> str:
        body = {"event_type": event_type, "occurred_at": int(time.time()), "payload": payload or {}}
        return self.call("POST", "/v1/events", body)["event_id"]

    def get_event(self, event_id: str) -> dict:
        return self.call("GET", f"/v1/events/{event_id}")


def _hex(b: bytes, n: int = 12) -> str:
    return b[:n].hex() + ("…" if len(b) > n) else ""

def _safe(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def parse_payload(items: list[str]) -> dict:
    payload = {}
    for item in items:
        k, sep, v = item.partition("=")
        if not sep or not k:
            raise ValueError(f"ожидается ключ=значение, получено {item!r}")
        payload[k] = int(v) if v.isascii() and v.lstrip("-").isdigit() and v not in ("", "-") else v
    return payload


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SECURE-TERMINAL/v2 client")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("explain", help="разбор одного запроса по шагам (без сервера)")

    def common(p):
        p.add_argument("--keys", required=True, help="файл ключей терминала (keys/<key_id>.json)")
        p.add_argument("--url", default=os.environ.get("ST_URL", "http://127.0.0.1:8000"),
                       help="адрес сервера; http:// только для localhost (или переменная ST_URL)")
        p.add_argument("--ca", default=os.environ.get("ST_CA_FILE"),
                       help="сертификат CA сервера: доверять только ему (или переменная ST_CA_FILE)")
        p.add_argument("--passphrase-file", help="файл с паролем, если ключи зашифрованы")

    s = sub.add_parser("send", help="отправить событие")
    common(s)
    s.add_argument("event_type", choices=["login", "logout", "operation", "status"])
    s.add_argument("--payload", nargs="+", default=[], metavar="K=V",
                   help="поля события; указывайте после типа события")
    g = sub.add_parser("get", help="прочитать своё событие")
    common(g)
    g.add_argument("event_id")
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.passphrase_file:
        os.environ[ks.PASSPHRASE_ENV] = a.passphrase_file
    try:
        payload = parse_payload(a.payload) if a.command == "send" else None
        client = TerminalClient(a.url, ks.load_terminal_keys(a.keys), ca_file=a.ca)
        if a.command == "send":
            print(json.dumps({"event_id": client.send_event(a.event_type, payload)}))
        else:
            print(json.dumps(client.get_event(a.event_id), ensure_ascii=False))
    except TerminalError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (ks.KeyFileError, ValueError, OSError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except httpx.HTTPError as e:
        print(f"error: сеть/TLS: {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
