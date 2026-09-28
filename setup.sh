#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1) venv =="
[ -d .venv ] || python3 -m venv .venv
echo "   ok"

echo "== 2) зависимости =="
.venv/bin/pip install -q -r requirements.txt
echo "   ok"

echo "== 3) ключи (если ещё нет) =="
if [ -f keys/server.json ]; then
    echo "   уже есть keys/server.json — пропускаю"
else
    .venv/bin/python keytool.py demo term-001 term-002 --dir keys
fi

echo
echo "Готово. Запустите сервер:  ./run.sh"
echo "В другом терминале отправьте событие:"
echo "  ./.venv/bin/python client.py send --url http://127.0.0.1:8000 --keys keys/term-001.json operation --payload amount=150 currency=RUB"