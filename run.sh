#!/usr/bin/env bash
set -euo pipefail

# Launch PPC Forward Service with environment from .env
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

BACKGROUND=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --background|-b)
      BACKGROUND=1
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--background|-b]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--background|-b]" >&2
      exit 1
      ;;
  esac
done

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

if [[ -z "${ADMIN_API_KEY:-}" ]]; then
  echo "ADMIN_API_KEY must be set (see .env)" >&2
  exit 1
fi

PORT=${PORT:-8080}
if [[ $BACKGROUND -eq 1 ]]; then
  LOG_FILE=${LOG_FILE:-"$SCRIPT_DIR/server.log"}
  touch "$LOG_FILE"
  echo "Starting server in background on port ${PORT} (log: $LOG_FILE)"
  nohup go run . >>"$LOG_FILE" 2>&1 &
  bg_pid=$!
  disown "$bg_pid" 2>/dev/null || true
  echo "Background PID: $bg_pid"
  exit 0
fi

echo "Starting server on port ${PORT}"
exec go run .
