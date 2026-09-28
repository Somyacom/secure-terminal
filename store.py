from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass

import crypto as c

SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces(
    key_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (key_id, nonce)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(expires_at);
CREATE TABLE IF NOT EXISTS events(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE, owner TEXT NOT NULL, received_at INTEGER NOT NULL,
    event_type TEXT NOT NULL, occurred_at INTEGER NOT NULL, payload TEXT NOT NULL,
    method TEXT NOT NULL, target TEXT NOT NULL, ts TEXT NOT NULL, nonce TEXT NOT NULL,
    signature BLOB NOT NULL, ciphertext BLOB NOT NULL,
    prev_hash BLOB NOT NULL, row_hash BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS events_owner ON events(owner);
CREATE TABLE IF NOT EXISTS owner_counts(owner TEXT PRIMARY KEY, n INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
"""
GENESIS = bytes(32)                      # prev_hash первой записи журнала
JOURNAL_DOMAIN = b"SECURE-TERMINAL/v2 JOURNAL\n"
NONCE_PURGE_EVERY = 5                    # сек между чистками истёкших nonce
EVENT_PURGE_EVERY = 60                   # сек между чистками по сроку хранения


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    owner: str
    received_at: int
    event_type: str
    occurred_at: int
    payload_json: str        # канонический JSON: sort_keys, без пробелов
    method: str
    target: str
    ts: str
    nonce: str
    signature: bytes
    ciphertext: bytes


def canonical_payload(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def row_hash(prev: bytes, r: EventRecord) -> bytes:
    doc = {"event_id": r.event_id, "owner": r.owner, "received_at": r.received_at,
           "event_type": r.event_type, "occurred_at": r.occurred_at, "payload": r.payload_json,
           "method": r.method, "target": r.target, "ts": r.ts, "nonce": r.nonce,
           "signature": c.b64e(r.signature), "ciphertext_sha256": hashlib.sha256(r.ciphertext).hexdigest()}
    return hashlib.sha256(JOURNAL_DOMAIN + prev + json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).digest()


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self.durable = path != ":memory:"
        if self.durable and not os.path.exists(path):
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))   # журнал — только владельцу
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
        self.lock = threading.Lock()     # одно соединение на процесс
        self.db.execute("PRAGMA busy_timeout=10000")
        if self.durable:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")      # не терять при сбое питания
        self.db.executescript(SCHEMA)
        self._nonce_purged_at = 0
        self._events_purged_at = 0

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def _tx(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            self.db.execute("COMMIT")

    def claim_nonce(self, key_id: str, nonce: str, expires_at: int, now: int, max_per_key: int) -> str:
        """'ok' | 'replay' | 'full' (квота на терминал — один не может заблокировать остальных)"""
        with self._tx() as db:
            if now - self._nonce_purged_at >= NONCE_PURGE_EVERY:
                db.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
                self._nonce_purged_at = now
            row = db.execute("SELECT expires_at FROM nonces WHERE key_id=? AND nonce=?", (key_id, nonce)).fetchone()
            if row and row[0] > now:
                return "replay"
            live = db.execute("SELECT COUNT(*) FROM nonces WHERE key_id=? AND expires_at > ?",
                              (key_id, now)).fetchone()[0]
            if live >= max_per_key:
                return "full"
            db.execute("INSERT OR REPLACE INTO nonces VALUES (?, ?, ?)", (key_id, nonce, expires_at))
            return "ok"


    def add_event(self, r: EventRecord, *, max_per_owner: int, retention_cutoff: int | None = None) -> str:
        """'ok' | 'quota' (у терминала исчерпана квота хранения)"""
        with self._tx() as db:
            if retention_cutoff is not None and r.received_at - self._events_purged_at >= EVENT_PURGE_EVERY:
                self._purge(db, retention_cutoff)
                self._events_purged_at = r.received_at
            row = db.execute("SELECT n FROM owner_counts WHERE owner=?", (r.owner,)).fetchone()
            if row and row[0] >= max_per_owner:
                return "quota"
            last = db.execute("SELECT row_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last[0] if last else self._anchor(db)
            db.execute("INSERT INTO events(event_id, owner, received_at, event_type, occurred_at, payload,"
                       " method, target, ts, nonce, signature, ciphertext, prev_hash, row_hash)"
                       " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (r.event_id, r.owner, r.received_at, r.event_type, r.occurred_at, r.payload_json,
                        r.method, r.target, r.ts, r.nonce, r.signature, r.ciphertext, prev, row_hash(prev, r)))
            db.execute("INSERT INTO owner_counts VALUES (?, 1) ON CONFLICT(owner) DO UPDATE SET n = n + 1", (r.owner,))
            return "ok"

    def get_event(self, event_id: str, owner: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT event_type, occurred_at, payload, received_at FROM events"
                                  " WHERE event_id=? AND owner=?", (event_id, owner)).fetchone()
        if row is None:
            return None
        return {"event_type": row[0], "occurred_at": row[1], "payload": json.loads(row[2]), "received_at": row[3]}

    def count_events(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    @staticmethod
    def _anchor(db) -> bytes:
        row = db.execute("SELECT v FROM meta WHERE k='anchor'").fetchone()
        return row[0] if row else GENESIS

    def _purge(self, db, cutoff: int) -> None:
        """Хеш последней удалённой записи становится якорем, цепочка оставшихся проверяется."""
        last = db.execute("SELECT seq, row_hash FROM events WHERE seq = "
                          "(SELECT MAX(seq) FROM events WHERE received_at < ?)", (cutoff,)).fetchone()
        if not last:
            return
        seq, h = last
        for owner, n in db.execute("SELECT owner, COUNT(*) FROM events WHERE seq <= ? GROUP BY owner", (seq,)).fetchall():
            db.execute("UPDATE owner_counts SET n = n - ? WHERE owner = ?", (n, owner))
        db.execute("DELETE FROM events WHERE seq <= ?", (seq,))
        db.execute("INSERT INTO meta VALUES ('anchor', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (h,))

    def verify_journal(self, terminals: dict[str, c.TerminalPublic],
                       server_kem: c.KemPrivateKey | None = None) -> tuple[int, list[str], bytes]:
        """Проверить цепочку хешей, подпись терминала и (если дан ключ) сверку полей с шифртекстом."""
        errors: list[str] = []
        with self.lock:
            prev = self._anchor(self.db)
            rows = self.db.execute("SELECT seq, event_id, owner, received_at, event_type, occurred_at, payload,"
                                   " method, target, ts, nonce, signature, ciphertext, prev_hash, row_hash"
                                   " FROM events ORDER BY seq").fetchall()
        for row in rows:
            seq, stored_prev, stored_hash = row[0], row[13], row[14]
            r = EventRecord(*row[1:13])
            where = f"seq={seq} event_id={r.event_id}"
            if stored_prev != prev:
                errors.append(f"{where}: разрыв цепочки (запись удалена или вставлена)")
            if row_hash(stored_prev, r) != stored_hash:
                errors.append(f"{where}: запись изменена после сохранения")
            prev = stored_hash
            term = terminals.get(r.owner)
            if term is None:
                errors.append(f"{where}: терминал {r.owner} отсутствует в реестре")
                continue
            signed = c.request_to_sign(r.method, r.target, r.owner, r.ts, r.nonce, r.ciphertext)
            if not term.sign.verify(r.signature, signed):
                errors.append(f"{where}: подпись терминала не сходится")
                continue
            if server_kem is not None:
                pt = c.open_sealed(r.ciphertext, server_kem, c.request_info(r.method, r.target, r.owner, r.ts, r.nonce))
                try:
                    ev = json.loads(pt) if pt is not None else None
                except ValueError:
                    ev = None
                if not ev or (ev.get("event_type"), ev.get("occurred_at"), canonical_payload(ev.get("payload", {}))) \
                        != (r.event_type, r.occurred_at, r.payload_json):
                    errors.append(f"{where}: сохранённые поля не совпадают с подписанным шифртекстом")
        return len(rows), errors, prev
