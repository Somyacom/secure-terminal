"""
test_all.py - все автотесты:  python -m pytest -q

Разделы:
    1. криптография (crypto.py): гибридная подпись, HPKE, форматы
    2. сервер: подлинность, целостность, конфиденциальность, повтор, некорректный ввод
    3. клиент: полный цикл и защита от подмены ответов
"""
from __future__ import annotations

import json
import random
import time

import httpx
import pytest
from fastapi.testclient import TestClient

import crypto as c
import server
from client import TerminalClient, TerminalError
from server import Settings, create_app
from store import Store

# В тестах лимиты частоты выключены (кроме тестов самих лимитов): иначе сотни быстрых
# запросов одного TestClient упрутся в лимит по IP.
TEST_SETTINGS = Settings(ip_rate=None, key_rate=None)
class Clock:
    """Управляемые часы: реальное время + сдвиг, который тест может менять."""

    def __init__(self) -> None:
        self.offset = 0

    def __call__(self) -> int:
        return int(time.time()) + self.offset


@pytest.fixture(scope="module")
def all_keys():
    # Генерация ключей ML-DSA/ML-KEM быстрая, но одного набора на модуль достаточно.
    return c.generate_keys(["term-a", "term-b"])


@pytest.fixture
def server_keys(all_keys):
    # Свежая копия реестра на каждый тест (тест отзыва ключа меняет его).
    return c.ServerKeys.from_json(all_keys[0].to_json())


@pytest.fixture
def ta(all_keys):
    return all_keys[1]["term-a"]


@pytest.fixture
def tb(all_keys):
    return all_keys[1]["term-b"]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(server_keys, clock):
    return create_app(server_keys, clock=clock, settings=TEST_SETTINGS)


@pytest.fixture
def http(app):
    # raise_server_exceptions=False — видим ответ сервера (в т.ч. 500), а не исключение.
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def event(**over) -> dict:
    ev = {"event_type": "login", "occurred_at": int(time.time()), "payload": {"shift": 1}}
    ev.update(over)
    return ev


def send(http, keys, method, path, plaintext=None, *, raw_body=None, sign_body=None, sign_path=None,
         ts=None, nonce=None, headers=None):
    """Отправить запрос как терминал. Параметры позволяют «сломать» что-то одно:
    raw_body — отправить эти байты вместо шифртекста (и подписать их);
    sign_body / sign_path — подписать одно, а отправить другое."""
    if isinstance(plaintext, dict):
        plaintext = json.dumps(plaintext).encode()
    h, body = c.seal_request(keys, method, sign_path or path, plaintext, ts=ts, nonce=nonce)
    if raw_body is not None:
        body = raw_body
        h["Content-Type"] = c.CONTENT_TYPE      # конверт заявлен как зашифрованный
        sig = keys.sign.sign(c.request_to_sign(method, sign_path or path, keys.key_id,
                                               h[c.H_TIMESTAMP], h[c.H_NONCE], body))
        h[c.H_SIGNATURE] = c.b64e(sig)
    if sign_body is not None:                  # подписываем sign_body, отправляем body
        sig = keys.sign.sign(c.request_to_sign(method, sign_path or path, keys.key_id,
                                               h[c.H_TIMESTAMP], h[c.H_NONCE], sign_body))
        h[c.H_SIGNATURE] = c.b64e(sig)
    h.update(headers or {})
    resp = http.request(method, path, content=body, headers=h)
    resp.nonce = h[c.H_NONCE]                  # запомним для проверки ответа
    return resp


def opened(keys, resp) -> dict:
    """Проверить подпись и расшифровать ответ сервера; упасть, если он не подлинный."""
    pt = c.open_response(keys, resp.nonce, resp.status_code, dict(resp.headers), resp.content)
    assert pt is not None, "response is not authentic"
    return json.loads(pt)


def assert_plain_error(resp, status, code):
    """Открытая ошибка до аутентификации: только код, без деталей и подписи."""
    assert resp.status_code == status
    assert resp.json() == {"error": code}
    assert c.H_SIGNATURE not in resp.headers
    assert "Traceback" not in resp.text


def assert_sealed_error(keys, resp, status, code):
    """Ошибка после аутентификации: зашифрована для терминала и подписана сервером."""
    assert resp.status_code == status
    assert opened(keys, resp) == {"error": code}
def test_hybrid_signature_roundtrip_and_size(ta):
    sig = ta.sign.sign(b"msg")
    assert len(sig) == c.HYBRID_SIG_LEN == 3373
    assert ta.sign.verify_key().verify(sig, b"msg")
    assert len(c.b64e(sig)) == 4498 and c.SIGNATURE_RE.fullmatch(c.b64e(sig))


def test_hybrid_signature_requires_both_parts(ta, tb):
    vk = ta.sign.verify_key()
    good, other = ta.sign.sign(b"msg"), tb.sign.sign(b"msg")
    assert not vk.verify(good[:64] + other[64:], b"msg")          # чужая ML-DSA
    assert not vk.verify(other[:64] + good[64:], b"msg")          # чужая Ed25519
    assert not vk.verify(good[:64] + bytes(c.MLDSA65_SIG_LEN), b"msg")
    assert not vk.verify(good[:64], b"msg")                        # отрезанная половина
    assert not vk.verify(good + b"\x00", b"msg")                   # лишний байт
    assert not vk.verify(good, b"msX")


def test_mldsa_context_binds_protocol(ta):
    # Подпись ML-DSA без контекста протокола не принимается как наша.
    raw = ta.sign.ed.sign(b"m") + ta.sign.ml.sign(b"m")            # без MLDSA_CONTEXT
    assert not ta.sign.verify_key().verify(raw, b"m")


def test_ed25519_part_is_deterministic_vector():
    # Ed25519 детерминирован: фиксированный seed + сообщение → фиксированная подпись.
    # Сверено через `openssl pkeyutl -sign -rawin` (см. README).
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    msg = c.request_to_sign("POST", "/v1/events", "term-001", "1760000000",
                            "00112233445566778899aabbccddeeff", b"")
    assert msg.split(b"\n")[-1] == b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sk.sign(msg).hex() == (
        "0350b99e9e77fb2796adcadf5a8c5d86c537dcd49a44202c4d345148ca461573"
        "dfaf485e21a69a3b8ef0f0e64634c53552c33fae81dc1d6eb2d39ab0992b9f03")


def test_hpke_roundtrip_and_binding(server_keys):
    pub = server_keys.kem.public()
    ct = c.seal(b"secret", pub, b"info-1")
    assert b"secret" not in ct
    assert len(ct) == len(b"secret") + c.HPKE_OVERHEAD
    assert c.open_sealed(ct, server_keys.kem, b"info-1") == b"secret"
    assert c.open_sealed(ct, server_keys.kem, b"info-2") is None                 # другой контекст
    assert c.open_sealed(ct[:-1] + bytes([ct[-1] ^ 1]), server_keys.kem, b"info-1") is None
    assert c.open_sealed(ct[:10], server_keys.kem, b"info-1") is None             # обрезан
    assert c.seal(b"secret", pub, b"i") != c.seal(b"secret", pub, b"i")          # каждый раз новый


def test_response_binding_is_in_signature_and_in_encryption(server_keys, ta):
    # Привязка ответа к запросу продублирована: и в подписи, и в HPKE info.
    # Проверяем каждый слой отдельно, чтобы ослабление любого из них было заметно.
    n1, n2 = c.new_nonce(), c.new_nonce()
    term = server_keys.terminal("term-a")
    h, body = c.seal_response(server_keys, term, "term-a", n1, 201, b"{}", c.now())
    sig, ts = c.b64d(h[c.H_SIGNATURE]), h[c.H_TIMESTAMP]
    vk = server_keys.sign.verify_key()
    assert vk.verify(sig, c.response_to_sign(201, "term-a", n1, ts, body))
    assert not vk.verify(sig, c.response_to_sign(201, "term-a", n2, ts, body))    # другой запрос
    assert not vk.verify(sig, c.response_to_sign(200, "term-a", n1, ts, body))    # другой статус
    assert c.open_sealed(body, ta.kem, c.response_info(201, "term-a", n1, ts)) == b"{}"
    assert c.open_sealed(body, ta.kem, c.response_info(201, "term-a", n2, ts)) is None


def test_strict_formats_reject_trailing_newline():
    # Раньше `^…$` с .match пропускал завершающий '\n'; теперь fullmatch.
    assert not c.KEY_ID_RE.fullmatch("term-a\n")
    assert not c.NONCE_RE.fullmatch("0" * 32 + "\n")
    assert not c.TIMESTAMP_RE.fullmatch("1760000000\n")


def test_keys_json_roundtrip(all_keys):
    server, terms = all_keys
    s2 = c.ServerKeys.from_json(json.loads(json.dumps(server.to_json())))
    t2 = c.TerminalKeys.from_json(json.loads(json.dumps(terms["term-a"].to_json())))
    sig = t2.sign.sign(b"x")
    assert s2.terminal("term-a").sign.verify(sig, b"x")
    # В реестре сервера нет секретов терминала: только публичные ключи.
    pub_json = server.to_json()["terminals"]["term-a"]
    assert pub_json["sign"] == terms["term-a"].sign.verify_key().to_json()
    assert pub_json["kem"] == terms["term-a"].kem.public().to_json()
    secrets_of_terminal = set(terms["term-a"].sign.to_json().values()) | set(terms["term-a"].kem.to_json().values())
    assert not any(s in json.dumps(server.to_json()) for s in secrets_of_terminal)


def test_nonce_quota_is_per_terminal_and_fails_closed(server_keys, ta, tb, clock):
    # Квота живых nonce у каждого терминала своя: переполнение → отказ (а не «забывание»,
    # иначе откроется повтор), и только для этого терминала. Раньше лимит был общий (H-2).
    app = create_app(server_keys, clock=clock, settings=Settings(ip_rate=None, key_rate=None, max_nonces_per_key=1))
    with TestClient(app) as http:
        assert send(http, ta, "POST", "/v1/events", event()).status_code == 201
        assert_sealed_error(ta, send(http, ta, "POST", "/v1/events", event()), 429, "rate_limited")
        assert send(http, tb, "POST", "/v1/events", event()).status_code == 201
def test_health_is_public(http):
    r = http.get("/v1/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_valid_event_accepted_response_sealed(http, ta):
    r = send(http, ta, "POST", "/v1/events", event(payload={"card_last4": "1234"}))
    assert r.status_code == 201
    assert r.headers["content-type"].startswith(c.CONTENT_TYPE)
    assert b"accepted" not in r.content                            # ответ зашифрован
    data = opened(ta, r)
    assert data["status"] == "accepted" and len(data["event_id"]) == 32


def test_owner_reads_event_other_terminal_cannot(http, ta, tb):
    eid = opened(ta, send(http, ta, "POST", "/v1/events", event()))["event_id"]
    r = send(http, ta, "GET", f"/v1/events/{eid}")
    assert r.status_code == 200 and opened(ta, r)["event_type"] == "login"
    r2 = send(http, tb, "GET", f"/v1/events/{eid}")
    r3 = send(http, tb, "GET", "/v1/events/" + "0" * 32)
    assert_sealed_error(tb, r2, 404, "not_found")
    assert_sealed_error(tb, r3, 404, "not_found")                  # чужое = несуществующее

def test_missing_auth_headers(http):
    assert_plain_error(http.post("/v1/events", json=event()), 401, "unauthorized")


def test_unknown_key_id(http, ta):
    r = send(http, ta, "POST", "/v1/events", event(), headers={c.H_KEY_ID: "term-x"})
    assert_plain_error(r, 401, "unauthorized")


def test_signed_by_other_terminal_under_my_key_id(http, ta, tb):
    # term-b подписал своим ключом, но назвался term-a.
    h, body = c.seal_request(tb, "POST", "/v1/events", json.dumps(event()).encode())
    h[c.H_KEY_ID] = "term-a"
    assert_plain_error(http.post("/v1/events", content=body, headers=h), 401, "unauthorized")


def test_revoked_key(http, app, ta):
    app.state.keys.revoke("term-a")
    assert_plain_error(send(http, ta, "POST", "/v1/events", event()), 401, "unauthorized")


def test_forged_signature_only_classic_part_valid(http, ta):
    # Атакующий с квантовым компьютером подделал бы только Ed25519 - ML-DSA не даст.
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    sig = c.b64d(h[c.H_SIGNATURE])
    h[c.H_SIGNATURE] = c.b64e(sig[:64] + bytes(c.MLDSA65_SIG_LEN))
    assert_plain_error(http.post("/v1/events", content=body, headers=h), 401, "unauthorized")


@pytest.mark.parametrize("header,value", [
    (c.H_KEY_ID, "term a"), (c.H_KEY_ID, "x" * 65), (c.H_KEY_ID, "../etc"),
    (c.H_TIMESTAMP, "-1"), (c.H_TIMESTAMP, "1e9"), (c.H_TIMESTAMP, "9" * 13),
    (c.H_NONCE, "short"), (c.H_NONCE, "G" * 32), (c.H_NONCE, "AA" * 16),
    (c.H_SIGNATURE, "zz"), (c.H_SIGNATURE, "A" * 4497), (c.H_SIGNATURE, "+" * 4498),
])
def test_malformed_auth_headers(http, ta, header, value):
    r = send(http, ta, "POST", "/v1/events", event(), headers={header: value})
    assert_plain_error(r, 401, "unauthorized")
def test_tampered_ciphertext_rejected(http, ta):
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    bad = body[:-1] + bytes([body[-1] ^ 1])
    assert_plain_error(http.post("/v1/events", content=bad, headers=h), 401, "unauthorized")


def test_signature_for_other_path_method_query(http, ta):
    eid = opened(ta, send(http, ta, "POST", "/v1/events", event()))["event_id"]
    assert_plain_error(send(http, ta, "GET", f"/v1/events/{eid}", sign_path="/v1/events/" + "f" * 32),
                       401, "unauthorized")
    assert_plain_error(send(http, ta, "POST", "/v1/events?x=1", event(), sign_path="/v1/events"),
                       401, "unauthorized")
    h, body = c.seal_request(ta, "PUT", "/v1/events", json.dumps(event()).encode())
    assert_plain_error(http.post("/v1/events", content=body, headers=h), 401, "unauthorized")

def test_plaintext_json_is_not_accepted(http, ta):
    # «Даунгрейд»: валидно подписанный, но НЕзашифрованный JSON.
    r = send(http, ta, "POST", "/v1/events", raw_body=json.dumps(event()).encode(),
             headers={"Content-Type": "application/json"})
    assert_sealed_error(ta, r, 415, "unsupported_media_type")
    r = send(http, ta, "POST", "/v1/events", raw_body=json.dumps(event()).encode())
    assert_sealed_error(ta, r, 400, "undecryptable")


def test_ciphertext_resigned_by_other_terminal_not_decryptable(http, ta, tb):
    # term-b перехватил шифртекст term-a и отправил его от своего имени со своей подписью.
    # Подпись верна (это подпись term-b), но key_id вшит в HPKE info → расшифровка невозможна.
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    r = send(http, tb, "POST", "/v1/events", raw_body=body, ts=int(h[c.H_TIMESTAMP]))
    assert_sealed_error(tb, r, 400, "undecryptable")


def test_ciphertext_moved_to_other_path_not_decryptable(http, ta):
    h, body = c.seal_request(ta, "POST", "/v1/other", json.dumps(event()).encode())
    r = send(http, ta, "POST", "/v1/events", raw_body=body)
    assert_sealed_error(ta, r, 400, "undecryptable")


def test_response_readable_only_by_its_terminal(http, ta, tb):
    r = send(http, ta, "POST", "/v1/events", event())
    assert c.open_response(tb, r.nonce, r.status_code, dict(r.headers), r.content) is None

def test_replay_rejected(http, ta):
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    assert http.post("/v1/events", content=body, headers=h).status_code == 201
    assert_plain_error(http.post("/v1/events", content=body, headers=h), 401, "unauthorized")


def test_stale_and_future_timestamps(http, ta, clock):
    for ts in (clock() - c.MAX_CLOCK_SKEW_SECONDS - 5, clock() + c.MAX_CLOCK_SKEW_SECONDS + 5):
        r = send(http, ta, "POST", "/v1/events", event(), ts=ts)
        assert_plain_error(r, 401, "stale_timestamp")
        assert int(r.headers[server.H_SERVER_TIME]) == clock()      # подсказка для диагностики часов


def test_replay_after_nonce_expiry_rejected_by_time(http, ta, clock):
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode(), ts=clock())
    assert http.post("/v1/events", content=body, headers=h).status_code == 201
    clock.offset = 3 * c.MAX_CLOCK_SKEW_SECONDS
    assert_plain_error(http.post("/v1/events", content=body, headers=h), 401, "stale_timestamp")


def test_replay_across_restart_memory_store(server_keys, ta, clock):
    # Хранилище в памяти: nonce теряются, поэтому запросы старше старта процесса отвергаются.
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode(), ts=clock())
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS)) as c1:
        assert c1.post("/v1/events", content=body, headers=h).status_code == 201
    clock.offset = 5
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS)) as c2:
        assert_plain_error(c2.post("/v1/events", content=body, headers=h), 401, "stale_timestamp")


def test_replay_across_restart_durable_store(server_keys, ta, clock, tmp_path):
    # Файл SQLite: nonce переживают рестарт, повтор ловится именно как повтор.
    db = str(tmp_path / "j.db")
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode(), ts=clock())
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db))) as c1:
        assert c1.post("/v1/events", content=body, headers=h).status_code == 201
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db))) as c2:
        assert_plain_error(c2.post("/v1/events", content=body, headers=h), 401, "unauthorized")


def test_failed_signature_does_not_burn_nonce(http, ta, tb):
    nonce = c.new_nonce()
    bad = send(http, tb, "POST", "/v1/events", event(), nonce=nonce, headers={c.H_KEY_ID: "term-a"})
    assert bad.status_code == 401
    assert send(http, ta, "POST", "/v1/events", event(), nonce=nonce).status_code == 201

@pytest.mark.parametrize("plaintext", [
    b"", b"not json", b"[]", b"null", b"{", b"\xff\xfe\x00",
    b'{"event_type":"login"}',
    b'{"event_type":"drop table","occurred_at":1760000000}',
    b'{"event_type":"login","occurred_at":"1760000000"}',
    b'{"event_type":"login","occurred_at":1760000000.5}',
    b'{"event_type":"login","occurred_at":1}',
    b'{"event_type":"login","occurred_at":1760000000,"is_admin":true}',
    b'{"event_type":"login","occurred_at":1760000000,"payload":{"x":{"nested":1}}}',
    b'{"event_type":"login","occurred_at":1760000000,"payload":{"Bad Key":1}}',
    b'{"event_type":"login","occurred_at":1760000000,"payload":{"x":"' + b"a" * 300 + b'"}}',
    b'{"event_type":"login","occurred_at":1760000000,"payload":{"x":1e400}}',
    b"[" * 5000 + b"]" * 5000,
])
def test_invalid_plaintext_rejected_cleanly(http, ta, plaintext):
    assert_sealed_error(ta, send(http, ta, "POST", "/v1/events", plaintext), 422, "invalid_body")


def test_too_many_payload_keys(http, ta):
    ev = event(payload={f"k{i}": i for i in range(33)})
    assert_sealed_error(ta, send(http, ta, "POST", "/v1/events", ev), 422, "invalid_body")


def test_body_too_large(http, ta):
    assert_plain_error(send(http, ta, "POST", "/v1/events", b"a" * (c.MAX_PLAINTEXT_BYTES + 10)),
                       413, "payload_too_large")


def test_body_too_large_without_content_length(app, ta):
    # Тело приходит кусками без Content-Length (chunked): лимит должен сработать по факту чтения,
    # а не только по заявленному размеру. Вызываем ASGI-приложение напрямую.
    import asyncio
    auth_headers = c.seal_request(ta, "POST", "/v1/events", b"{}")[0]
    scope = {"type": "http", "method": "POST", "path": "/v1/events", "raw_path": b"/v1/events",
             "query_string": b"", "headers": [(k.lower().encode(), v.encode()) for k, v in auth_headers.items()]}
    chunks = [b"x" * 4096] * (c.MAX_BODY_BYTES // 4096 + 5)     # суммарно больше лимита
    sent = []

    async def receive():
        return {"type": "http.request", "body": chunks.pop() if chunks else b"", "more_body": bool(chunks)}

    async def send_(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send_))
    assert sent[0]["status"] == 413


def test_non_ascii_digit_content_length(app, ta):
    # Раньше str.isdigit() пропускал '²' и int() падал → 500. Теперь строгий regex → 413.
    # HTTP-клиент такой заголовок не отправит, поэтому вызываем ASGI-приложение напрямую.
    import asyncio
    from server import CONTENT_LENGTH_RE
    assert "²".isdigit() and not CONTENT_LENGTH_RE.fullmatch("²")
    auth_headers = c.seal_request(ta, "POST", "/v1/events", b"{}")[0]
    scope = {"type": "http", "method": "POST", "path": "/v1/events", "raw_path": b"/v1/events",
             "query_string": b"", "headers": [(b"content-length", "²".encode("latin-1"))]
             + [(k.lower().encode(), v.encode()) for k, v in auth_headers.items()]}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send_(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send_))
    assert sent[0]["status"] == 413


def test_unknown_route_and_method_and_docs(http):
    assert_plain_error(http.get("/admin"), 404, "not_found")
    assert_plain_error(http.delete("/v1/events"), 405, "method_not_allowed")
    assert http.get("/docs").status_code == 404
    assert http.get("/openapi.json").status_code == 404


def test_weird_event_ids_never_500(http, ta):
    for eid in ("..%2f..%2fetc", "A" * 1000, "%00", "'or'1'='1", "G" * 32):
        assert send(http, ta, "GET", f"/v1/events/{eid}").status_code in (401, 404)


def test_internal_error_is_not_leaked(http, ta, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail /var/db/password")
    monkeypatch.setattr(server.uuid, "uuid4", boom)
    r = send(http, ta, "POST", "/v1/events", event())
    assert r.status_code == 500 and r.json() == {"error": "internal_error"} and "secret" not in r.text


def test_random_fuzz_never_500(http, ta):
    rnd = random.Random(1337)
    for i in range(200):
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300)))
        if i % 2:
            r = send(http, ta, "POST", "/v1/events", blob)          # мусор внутри валидного конверта
        else:
            r = http.post("/v1/events", content=blob, headers={
                c.H_KEY_ID: "term-a", c.H_TIMESTAMP: str(rnd.randint(0, 10 ** 12)),
                c.H_NONCE: blob.hex()[:32], c.H_SIGNATURE: c.b64e(blob)[:4498]})
        assert r.status_code < 500, (r.status_code, blob)

def make_client(http, keys):
    return TerminalClient("http://testserver", keys, http=http)


def test_client_roundtrip(http, ta):
    cl = make_client(http, ta)
    eid = cl.send_event("operation", {"amount": 150, "currency": "RUB", "ok": True})
    assert cl.get_event(eid)["payload"] == {"amount": 150, "currency": "RUB", "ok": True}


def test_client_signed_validation_error(http, ta):
    with pytest.raises(TerminalError) as e:
        make_client(http, ta).send_event("unknown_type")
    assert (e.value.status, e.value.code, e.value.signed) == (422, "invalid_body", True)


def test_client_unsigned_rejection(http, ta, app):
    app.state.keys.revoke("term-a")
    with pytest.raises(TerminalError) as e:
        make_client(http, ta).send_event("login")
    assert (e.value.status, e.value.code, e.value.signed) == (401, "unauthorized", False)


def test_client_rejects_wrong_pinned_server_key(http, ta, tb):
    # Терминал с «закреплённым» ключом другого сервера не поверит ответу.
    fake_server, _ = c.generate_keys([])
    evil = c.TerminalKeys(ta.key_id, ta.sign, ta.kem, fake_server.sign.verify_key(), ta.server_kem)
    with pytest.raises(TerminalError, match="response_not_authentic"):
        make_client(http, evil).send_event("login")


def _mitm(http, mutate):
    """Посредник между клиентом и сервером без ключей: может менять ответы."""
    class Proxy(httpx.BaseTransport):
        def handle_request(self, request):
            return mutate(http.send(request))
    return httpx.Client(base_url="http://testserver", transport=Proxy())


def test_client_rejects_modified_response(http, ta):
    def mutate(r):
        body = r.content[:-1] + bytes([r.content[-1] ^ 1])
        return httpx.Response(r.status_code, headers=r.headers, content=body)
    with pytest.raises(TerminalError, match="response_not_authentic"):
        make_client(_mitm(http, mutate), ta).send_event("login")


def test_client_rejects_unsealed_success(http, ta):
    with pytest.raises(TerminalError, match="response_not_authentic"):
        make_client(_mitm(http, lambda r: httpx.Response(200, json={"event_id": "f" * 32})), ta).send_event("login")


def test_client_rejects_replayed_old_response(http, ta):
    captured = {}

    def mutate(r):
        if "first" not in captured:
            captured["first"] = r
            return r
        old = captured["first"]
        return httpx.Response(old.status_code, headers=old.headers, content=old.content)

    cl = make_client(_mitm(http, mutate), ta)
    cl.send_event("login")
    with pytest.raises(TerminalError, match="response_not_authentic"):
        cl.send_event("logout")

import logging
import os
import subprocess
import sys

import keystore as ks
from client import make_http
from store import EventRecord


def test_ip_rate_limit_before_any_work(server_keys, ta, clock, monkeypatch):
    # Лимит по IP срабатывает раньше проверки подписи: при превышении подпись вообще не считается.
    calls = []
    real = c.VerifyKey.verify
    monkeypatch.setattr(c.VerifyKey, "verify", lambda self, *a: calls.append(1) or real(self, *a))
    app = create_app(server_keys, clock=clock, settings=Settings(ip_rate=0.001, ip_burst=3, key_rate=None))
    with TestClient(app) as http:
        codes = [send(http, ta, "POST", "/v1/events", event()).status_code for _ in range(5)]
        r = http.post("/v1/events", content=b"x", headers={c.H_KEY_ID: "nobody"})
    assert codes == [201, 201, 201, 429, 429]
    assert_plain_error(r, 429, "rate_limited")
    assert len(calls) == 3


def test_verify_queue_full_is_503_busy(server_keys, ta, clock):
    app = create_app(server_keys, clock=clock, settings=Settings(ip_rate=None, key_rate=None, max_verify_queue=0))
    with TestClient(app) as http:
        assert_plain_error(send(http, ta, "POST", "/v1/events", event()), 503, "busy")


def test_signature_verified_off_event_loop(server_keys, ta, clock, monkeypatch):
    # Подпись проверяется в пуле потоков, а не в потоке event loop.
    import threading
    seen = []
    real = c.VerifyKey.verify
    monkeypatch.setattr(c.VerifyKey, "verify", lambda self, *a: seen.append(threading.current_thread().name) or real(self, *a))
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS)) as http:
        loop_thread = http.portal.call(lambda: threading.current_thread().name)
        assert send(http, ta, "POST", "/v1/events", event()).status_code == 201
    assert seen and all(name != loop_thread for name in seen)


def test_rate_limiter_table_is_bounded():
    rl = server.RateLimiter(1.0, 1, max_entries=100)
    for i in range(1000):
        rl.allow(f"10.0.{i // 256}.{i % 256}")
    assert len(rl.buckets) == 100

def test_key_rate_limit_is_per_terminal(server_keys, ta, tb, clock):
    app = create_app(server_keys, clock=clock, settings=Settings(ip_rate=None, key_rate=0.001, key_burst=2))
    with TestClient(app) as http:
        assert [send(http, ta, "POST", "/v1/events", event()).status_code for _ in range(2)] == [201, 201]
        assert_sealed_error(ta, send(http, ta, "POST", "/v1/events", event()), 429, "rate_limited")
        assert send(http, tb, "POST", "/v1/events", event()).status_code == 201


def test_event_quota_is_per_terminal(server_keys, ta, tb, clock):
    app = create_app(server_keys, clock=clock, settings=Settings(ip_rate=None, key_rate=None, max_events_per_key=2))
    with TestClient(app) as http:
        for _ in range(2):
            assert send(http, ta, "POST", "/v1/events", event()).status_code == 201
        assert_sealed_error(ta, send(http, ta, "POST", "/v1/events", event()), 429, "quota_exceeded")
        assert send(http, tb, "POST", "/v1/events", event()).status_code == 201


def test_retention_frees_quota_and_keeps_chain_valid(server_keys, ta, clock, tmp_path):
    store = Store(str(tmp_path / "j.db"))
    app = create_app(server_keys, clock=clock, store=store,
                     settings=Settings(ip_rate=None, key_rate=None, max_events_per_key=2, event_retention_days=1))
    with TestClient(app) as http:
        for _ in range(2):
            assert send(http, ta, "POST", "/v1/events", event()).status_code == 201
        clock.offset = 2 * 86_400
        assert send(http, ta, "POST", "/v1/events", event(), ts=clock()).status_code == 201   # старые удалены
    n, errors, _ = store.verify_journal(server_keys.terminals, server_keys.kem)
    assert (n, errors) == (1, [])

def test_replay_into_other_worker_rejected(server_keys, ta, clock, tmp_path):
    # Два «воркера» с общим файлом SQLite: повтор во второй ловится, событие видно из обоих.
    db = str(tmp_path / "j.db")
    w1 = TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db)))
    w2 = TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db)))
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    r1 = w1.post("/v1/events", content=body, headers=h)
    assert r1.status_code == 201
    assert_plain_error(w2.post("/v1/events", content=body, headers=h), 401, "unauthorized")
    r1.nonce = h[c.H_NONCE]
    eid = opened(ta, r1)["event_id"]
    assert opened(ta, send(w2, ta, "GET", f"/v1/events/{eid}"))["event_type"] == "login"


def test_concurrent_claims_single_winner(tmp_path):
    # Одинаковый nonce из многих потоков и двух соединений: принимается ровно один.
    import concurrent.futures
    db = str(tmp_path / "j.db")
    stores = [Store(db), Store(db)]
    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        results = list(ex.map(lambda i: stores[i % 2].claim_nonce("t", "n" * 32, 10_000, 1, 100), range(32)))
    assert results.count("ok") == 1 and results.count("replay") == 31

def test_client_refuses_plain_http_to_remote_host():
    with pytest.raises(ValueError, match="https"):
        make_http("http://st.example.ru")
    with pytest.raises(ValueError):
        make_http("ftp://st.example.ru")
    assert make_http("http://127.0.0.1:8000") and make_http("http://localhost:8000")


def test_client_tls_context_is_strict(tmp_path):
    import ssl as ssl_
    cl = make_http("https://st.example.ru")
    ctx = cl._transport._pool._ssl_context
    assert ctx.minimum_version == ssl_.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl_.CERT_REQUIRED and ctx.check_hostname


def test_server_refuses_network_without_tls(tmp_path):
    r = subprocess.run([sys.executable, "server.py", "serve", "--host", "0.0.0.0", "--keys", "x", "--registry", "y"],
                       capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)), timeout=60)
    assert r.returncode != 0 and "TLS" in r.stderr

def run_keytool(tmp_path, *args, input=None):
    return subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "keytool.py"), *args],
                          capture_output=True, text=True, cwd=tmp_path, timeout=60, input=input)


@pytest.mark.skipif(os.name != "posix", reason="права POSIX")
def test_keytool_device_flow_permissions_and_no_overwrite(tmp_path):
    srv, term = tmp_path / "srv", tmp_path / "term"
    assert run_keytool(tmp_path, "server-init", "--dir", str(srv)).returncode == 0
    assert oct(srv.stat().st_mode & 0o777) == "0o700"
    for f in ("server.json", "terminals.json", "server.pub.json"):
        assert (srv / f).stat().st_mode & 0o077 == 0
    r = run_keytool(tmp_path, "server-init", "--dir", str(srv))                     # повторно — отказ
    assert r.returncode != 0 and "уже существует" in r.stderr
    r = run_keytool(tmp_path, "terminal-init", "t1", "--server-pub", str(srv / "server.pub.json"), "--dir", str(term))
    assert r.returncode == 0
    fp = r.stdout.split("отпечаток терминала:")[1].strip()
    # секрет терминала на сервер не попадает: регистрируется только .pub.json
    r = run_keytool(tmp_path, "register", str(term / "t1.pub.json"), "--dir", str(srv), "--yes")
    assert r.returncode == 0 and fp in r.stdout
    tk = ks.load_terminal_keys(str(term / "t1.json"))
    registry = ks.load_registry(str(srv / "terminals.json"))
    assert registry["t1"].sign.verify(tk.sign.sign(b"m"), b"m")
    assert "t1" in run_keytool(tmp_path, "list", "--dir", str(srv)).stdout
    assert run_keytool(tmp_path, "revoke", "t1", "--dir", str(srv)).returncode == 0
    assert ks.load_registry(str(srv / "terminals.json"))["t1"].revoked


@pytest.mark.skipif(os.name != "posix", reason="права POSIX")
def test_secure_write_fixes_mode_and_load_refuses_open_secret(tmp_path):
    p = tmp_path / "k.json"
    p.write_text("{}")
    os.chmod(p, 0o644)
    ks.write_json_secure(str(p), {"a": 1})
    assert p.stat().st_mode & 0o777 == 0o600                    # раньше оставалось 0644
    os.chmod(p, 0o644)
    with pytest.raises(ks.KeyFileError, match="chmod"):
        ks.load_secret_json(str(p))
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    ks.write_json_secure(str(link), {"b": 2})                   # ссылка заменяется, цель не трогается
    assert target.read_text() == "keep" and not link.is_symlink()


def test_encrypted_keyfile(tmp_path, ta, monkeypatch):
    pw_file = tmp_path / "pw"
    pw_file.write_text("correct horse battery\n")
    os.chmod(pw_file, 0o600)
    monkeypatch.setenv(ks.PASSPHRASE_ENV, str(pw_file))
    path = tmp_path / "t.json"
    ks.save_secret(str(path), ta.to_json(), ks.get_passphrase())
    raw = path.read_text()
    assert ta.sign.to_json()["ed25519"] not in raw and ks.KEYFILE_FORMAT in raw
    assert ks.load_terminal_keys(str(path)).key_id == ta.key_id
    pw_file.write_text("wrong password here")
    with pytest.raises(ks.KeyFileError, match="неверный пароль"):
        ks.load_terminal_keys(str(path))
    blob = json.loads(raw)
    blob["kdf"]["n"] = 2 ** 30                                  # подложенные параметры scrypt
    with pytest.raises(ks.KeyFileError, match="scrypt"):
        ks.decrypt_json(blob, b"whatever")

def _journal(server_keys, ta, tb, clock, tmp_path, n=3):
    store = Store(str(tmp_path / "j.db"))
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=store)) as http:
        for i in range(n):
            assert send(http, ta if i % 2 == 0 else tb, "POST", "/v1/events", event(payload={"i": i})).status_code == 201
    return store


def test_journal_keeps_verifiable_evidence(server_keys, ta, tb, clock, tmp_path):
    store = _journal(server_keys, ta, tb, clock, tmp_path)
    n, errors, head = store.verify_journal(server_keys.terminals, server_keys.kem)
    assert (n, errors) == (3, []) and len(head) == 32
    # Проверка работает и по одному лишь публичному реестру (без секретов сервера)
    assert store.verify_journal(ks_registry_copy(server_keys))[1] == []


def ks_registry_copy(server_keys):
    return {k: c.TerminalPublic.from_json(t.to_json()) for k, t in server_keys.terminals.items()}


@pytest.mark.parametrize("attack,expect", [
    ("UPDATE events SET payload='{\"i\":99}' WHERE seq=2", "изменена"),
    ("DELETE FROM events WHERE seq=2", "разрыв цепочки"),
    ("UPDATE events SET signature=zeroblob(3373) WHERE seq=1", "изменена"),
])
def test_journal_detects_tampering(server_keys, ta, tb, clock, tmp_path, attack, expect):
    store = _journal(server_keys, ta, tb, clock, tmp_path)
    store.db.execute(attack)
    errors = store.verify_journal(server_keys.terminals, server_keys.kem)[1]
    assert any(expect in e for e in errors), errors


def test_journal_detects_rehashed_forgery(server_keys, ta, tb, clock, tmp_path):
    # Атакующий с доступом к БД правит поле и пересчитывает всю цепочку: хеши сойдутся,
    # но сохранённые поля перестанут совпадать с подписанным шифртекстом.
    from store import row_hash
    store = _journal(server_keys, ta, tb, clock, tmp_path)
    store.db.execute("UPDATE events SET payload='{\"i\":99}' WHERE seq=1")
    prev = bytes(32)
    for row in store.db.execute("SELECT * FROM events ORDER BY seq").fetchall():
        h = row_hash(prev, EventRecord(*row[1:13]))
        store.db.execute("UPDATE events SET prev_hash=?, row_hash=? WHERE seq=?", (prev, h, row[0]))
        prev = h
    errors = store.verify_journal(server_keys.terminals, server_keys.kem)[1]
    assert any("не совпадают с подписанным" in e for e in errors), errors


def test_events_survive_restart(server_keys, ta, clock, tmp_path):
    db = str(tmp_path / "j.db")
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db))) as http:
        eid = opened(ta, send(http, ta, "POST", "/v1/events", event()))["event_id"]
    with TestClient(create_app(server_keys, clock=clock, settings=TEST_SETTINGS, store=Store(db))) as http:
        assert opened(ta, send(http, ta, "GET", f"/v1/events/{eid}"))["event_type"] == "login"


def test_control_chars_escaped_in_log(http, caplog):
    with caplog.at_level(logging.WARNING, logger="secure_terminal.security"):
        http.get("/v1/events/%1b[31mFAKE%1b[0m")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "\x1b" not in text and "\\x1b[31mFAKE" in text

def test_registry_hot_reload_revocation(server_keys, ta, tb, clock, tmp_path):
    reg = str(tmp_path / "terminals.json")
    ks.save_registry(reg, {k: c.TerminalPublic.from_json(t.to_json()) for k, t in server_keys.terminals.items()})
    keys_only = c.ServerKeys(server_keys.sign, server_keys.kem)
    app = create_app(keys_only, clock=clock, registry_path=reg,
                     settings=Settings(ip_rate=None, key_rate=None, registry_reload_seconds=0))
    with TestClient(app) as http:
        assert send(http, ta, "POST", "/v1/events", event()).status_code == 201
        terms = ks.load_registry(reg)
        terms["term-a"].revoked = True
        ks.save_registry(reg, terms)
        assert_plain_error(send(http, ta, "POST", "/v1/events", event()), 401, "unauthorized")
        assert send(http, tb, "POST", "/v1/events", event()).status_code == 201
        with open(reg, "w") as f:                               # испорченный файл: прежний реестр в силе
            f.write("{broken")
        os.chmod(reg, 0o600)
        assert send(http, tb, "POST", "/v1/events", event()).status_code == 201


def test_client_reports_clock_skew(http, ta, monkeypatch):
    import client as client_mod
    monkeypatch.setattr(c, "now", lambda: int(time.time()) - 120)        # часы терминала отстают
    with pytest.raises(TerminalError) as e:
        make_client(http, ta).send_event("login")
    assert e.value.code == "stale_timestamp" and -125 <= e.value.skew <= -115
    assert "отстают" in str(e.value)
def test_non_canonical_signature_encoding_rejected(http, ta):
    h, body = c.seal_request(ta, "POST", "/v1/events", json.dumps(event()).encode())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    sig = h[c.H_SIGNATURE]
    alt = sig[:-1] + alphabet[alphabet.index(sig[-1]) ^ 1]
    assert c.b64d(alt) == c.b64d(sig)                         # те же байты, другая запись
    assert_plain_error(http.post("/v1/events", content=body, headers={**h, c.H_SIGNATURE: alt}), 401, "unauthorized")


def test_cli_argument_parsing():
    from client import build_parser, parse_payload
    a = build_parser().parse_args(["send", "--keys", "k.json", "--url", "https://h", "operation",
                                   "--payload", "amount=150", "currency=RUB"])
    assert (a.command, a.event_type, a.url) == ("send", "operation", "https://h")
    assert parse_payload(a.payload) == {"amount": 150, "currency": "RUB"}
    a = build_parser().parse_args(["get", "--keys", "k.json", "f" * 32])
    assert a.event_id == "f" * 32
    with pytest.raises(ValueError):
        parse_payload(["novalue"])
    with pytest.raises(SystemExit):
        build_parser().parse_args(["send", "operation"])            # без --keys


@pytest.mark.skipif(os.name != "posix", reason="права POSIX")
def test_journal_file_is_private(tmp_path):
    Store(str(tmp_path / "j.db"))
    assert (tmp_path / "j.db").stat().st_mode & 0o077 == 0
