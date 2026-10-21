#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v uv >/dev/null 2>&1; then
  printf 'Error: uv is required. Install it before starting the backend.\n' >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  printf 'Error: npm is required. Install Node.js before starting the frontend.\n' >&2
  exit 1
fi

if [ ! -x "$ROOT_DIR/frontend/node_modules/.bin/vite" ]; then
  printf 'Error: frontend dependencies are missing. Run "npm install" in %s/frontend first.\n' "$ROOT_DIR" >&2
  exit 1
fi

(
  cd "$ROOT_DIR" || exit
  exec uv run uvicorn src.api.main:app --host 127.0.0.1 --port 8000
) &
backend_pid=$!

(
  cd "$ROOT_DIR/frontend" || exit
  exec npm run dev -- --host 127.0.0.1 --port 5173
) &
frontend_pid=$!

cleanup() {
  trap - EXIT INT TERM
  kill "$backend_pid" "$frontend_pid" 2>/dev/null || true
  wait "$backend_pid" 2>/dev/null || true
  wait "$frontend_pid" 2>/dev/null || true
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Frontend: http://127.0.0.1:5173\n'
printf 'Backend:  http://127.0.0.1:8000\n'
printf 'Press Ctrl+C to stop both services.\n'

while :; do
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    wait "$backend_pid"
    status=$?
    printf 'Backend exited (status %s); stopping frontend.\n' "$status" >&2
    exit "$status"
  fi

  if ! kill -0 "$frontend_pid" 2>/dev/null; then
    wait "$frontend_pid"
    status=$?
    printf 'Frontend exited (status %s); stopping backend.\n' "$status" >&2
    exit "$status"
  fi

  sleep 1
done
