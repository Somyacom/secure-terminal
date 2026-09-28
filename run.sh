#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec ./.venv/bin/python server.py serve \
    --keys keys/server.json \
    --registry keys/terminals.json \
    --db data/journal.db \
    --host 127.0.0.1 --port 8000 --workers 1