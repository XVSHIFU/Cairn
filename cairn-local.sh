#!/usr/bin/env bash
# Cairn local-mode helpers (server + dispatcher on host)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$PATH"
cd "$ROOT"
mkdir -p "$ROOT/datas/cairn" "$ROOT/datas/runs" "$ROOT/datas"

start() {
  if curl -sf http://127.0.0.1:8000/projects >/dev/null 2>&1; then
    echo "server already up on :8000"
  else
    nohup uv run --project cairn cairn serve --host 127.0.0.1 --port 8000 \
      >"$ROOT/datas/server.log" 2>&1 &
    echo "server pid=$!"
    for i in $(seq 1 20); do
      curl -sf http://127.0.0.1:8000/projects >/dev/null 2>&1 && break
      sleep 0.5
    done
  fi
  if pgrep -f 'cairn dispatch --config dispatch.yaml' >/dev/null 2>&1; then
    echo "dispatcher already running"
  else
    nohup uv run --project cairn cairn dispatch --config dispatch.yaml \
      >"$ROOT/datas/dispatcher.log" 2>&1 &
    echo "dispatcher pid=$!"
  fi
  echo "API:  http://127.0.0.1:8000/docs"
  echo "logs: $ROOT/datas/server.log  $ROOT/datas/dispatcher.log"
}

stop() {
  pkill -f 'cairn dispatch --config dispatch.yaml' 2>/dev/null || true
  pkill -f 'cairn serve --host 127.0.0.1 --port 8000' 2>/dev/null || true
  # also match bare serve
  pkill -f '/cairn/.venv/bin/cairn serve' 2>/dev/null || true
  pkill -f '/cairn/.venv/bin/cairn dispatch' 2>/dev/null || true
  echo "stopped (best effort)"
}

status() {
  echo "== processes =="
  pgrep -af 'cairn (serve|dispatch)' || echo "(none)"
  echo "== api =="
  curl -sf http://127.0.0.1:8000/projects && echo || echo "server not responding"
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
