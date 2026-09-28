"""Управление ключами SECURE-TERMINAL/v2 (server-init, terminal-init, register, revoke, list, demo)"""
from __future__ import annotations

import argparse
import os
import sys

import crypto as c
import keystore as ks


def _p(dir_: str, name: str) -> str:
    return os.path.join(dir_, name)


def _passphrase(a) -> bytes | None:
    if not getattr(a, "encrypt", False):
        return None
    if a.passphrase_file:
        os.environ[ks.PASSPHRASE_ENV] = a.passphrase_file
    return ks.get_passphrase(confirm=True)


def _refuse_overwrite(path: str, force: bool) -> None:
    """Перезапись сломает все выпущенные ключи"""
    if os.path.exists(path) and not force:
        sys.exit(f"отказ: {path} уже существует. Перезапись сломает все выпущенные ключи; "
                 f"если это действительно нужно, добавьте --force")


def server_init(a) -> None:
    ks.ensure_dir(a.dir)
    for name in ("server.json", "terminals.json"):
        _refuse_overwrite(_p(a.dir, name), a.force)
    pw = _passphrase(a)
    server = c.ServerKeys(c.SigningKey.generate(), c.KemPrivateKey.generate())
    ks.save_secret(_p(a.dir, "server.json"), server.secrets_json(), pw)
    ks.write_json_secure(_p(a.dir, "server.pub.json"), server.public_bundle())
    ks.save_registry(_p(a.dir, "terminals.json"), {})
    print(f"written {a.dir}/server.json          секретные ключи сервера{' (зашифрованы)' if pw else ''}")
    print(f"written {a.dir}/server.pub.json      раздать на терминалы")
    print(f"written {a.dir}/terminals.json       реестр терминалов (пустой)")
    print(f"отпечаток сервера: {c.fingerprint(server.public_bundle())}")


def terminal_init(a) -> None:
    bundle = ks.read_json(a.server_pub)
    tk = c.TerminalKeys.generate(a.key_id, bundle)
    ks.ensure_dir(a.dir)
    secret, public = _p(a.dir, f"{a.key_id}.json"), _p(a.dir, f"{a.key_id}.pub.json")
    _refuse_overwrite(secret, a.force)
    pw = _passphrase(a)
    ks.save_secret(secret, tk.to_json(), pw)
    pub = c.terminal_public_bundle(a.key_id, tk.public())
    ks.write_json_secure(public, pub)
    print(f"written {secret}   секретные ключи терминала{' (зашифрованы)' if pw else ''}")
    print(f"written {public}   отправить на сервер для регистрации")
    print(f"закреплён сервер:   {c.fingerprint(bundle)}")
    print(f"отпечаток терминала: {c.fingerprint(pub)}")


def register(a) -> None:
    kid, pub = c.parse_terminal_public_bundle(ks.read_json(a.pubfile))
    path = _p(a.dir, "terminals.json")
    terms = ks.load_registry(path)
    if kid in terms and not a.replace:
        sys.exit(f"отказ: {kid} уже зарегистрирован (для замены ключа: --replace)")
    print(f"терминал {kid}, отпечаток {c.fingerprint(c.terminal_public_bundle(kid, pub))}")
    if not a.yes:
        if not sys.stdin.isatty():
            sys.exit("сверьте отпечаток с терминалом и повторите с --yes")
        if input("Отпечаток совпадает с показанным на терминале? [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
            sys.exit("отменено")
    terms[kid] = pub
    ks.save_registry(path, terms)
    print(f"зарегистрирован {kid}; работающий сервер подхватит изменение сам")


def set_revoked(a, revoked: bool) -> None:
    path = _p(a.dir, "terminals.json")
    terms = ks.load_registry(path)
    if a.key_id not in terms:
        sys.exit(f"нет терминала {a.key_id}")
    terms[a.key_id].revoked = revoked
    ks.save_registry(path, terms)
    print(f"{a.key_id}: {'отозван' if revoked else 'восстановлен'}; работающий сервер применит изменение в течение секунды")


def list_terminals(a) -> None:
    for kid, t in sorted(ks.load_registry(_p(a.dir, "terminals.json")).items()):
        state = "REVOKED" if t.revoked else "active"
        print(f"{kid:<24} {state:<8} {c.fingerprint(c.terminal_public_bundle(kid, t))}")


def demo(a) -> None:
    """Всё на одной машине — только для проверки. В эксплуатации: server-init / terminal-init / register"""
    a.force = getattr(a, "force", False)
    server_init(a)
    server_pub = _p(a.dir, "server.pub.json")
    for kid in a.key_ids:
        tk = c.TerminalKeys.generate(kid, ks.read_json(server_pub))
        _refuse_overwrite(_p(a.dir, f"{kid}.json"), a.force)
        ks.save_secret(_p(a.dir, f"{kid}.json"), tk.to_json(), None)
        terms = ks.load_registry(_p(a.dir, "terminals.json"))
        terms[kid] = tk.public()
        ks.save_registry(_p(a.dir, "terminals.json"), terms)
        print(f"written {a.dir}/{kid}.json  (зарегистрирован)")


def main() -> int:
    ap = argparse.ArgumentParser(description="SECURE-TERMINAL/v2 key tool")
    sub = ap.add_subparsers(dest="command", required=True)

    def dir_arg(p):
        p.add_argument("--dir", default="keys", help="папка ключей (по умолчанию keys)")

    def enc_args(p):
        p.add_argument("--encrypt", action="store_true", help="зашифровать секретный файл паролем")
        p.add_argument("--passphrase-file", help="взять пароль из файла, а не с клавиатуры")
        p.add_argument("--force", action="store_true", help="перезаписать существующие ключи")

    p = sub.add_parser("server-init", help="создать ключи сервера (на сервере)")
    dir_arg(p); enc_args(p); p.set_defaults(fn=server_init)

    p = sub.add_parser("terminal-init", help="создать ключи терминала (на терминале)")
    p.add_argument("key_id")
    p.add_argument("--server-pub", required=True, help="server.pub.json, полученный с сервера")
    dir_arg(p); enc_args(p); p.set_defaults(fn=terminal_init)

    p = sub.add_parser("register", help="зарегистрировать терминал по его .pub.json (на сервере)")
    p.add_argument("pubfile")
    p.add_argument("--replace", action="store_true", help="заменить ключ уже зарегистрированного терминала")
    p.add_argument("--yes", action="store_true", help="отпечаток сверен, не спрашивать")
    dir_arg(p); p.set_defaults(fn=register)

    for name, flag, help_ in (("revoke", True, "отозвать терминал"), ("restore", False, "снять отзыв")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("key_id")
        dir_arg(p); p.set_defaults(fn=lambda a, f=flag: set_revoked(a, f))

    p = sub.add_parser("list", help="список терминалов")
    dir_arg(p); p.set_defaults(fn=list_terminals)

    p = sub.add_parser("demo", help="всё на одной машине (только для проверки)")
    p.add_argument("key_ids", nargs="+")
    p.add_argument("--force", action="store_true")
    dir_arg(p); p.set_defaults(fn=demo)

    a = ap.parse_args()
    try:
        a.fn(a)
    except (ks.KeyFileError, ValueError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
