#!/usr/bin/env bash
set -euo pipefail

# Launch PPC Forward Service with environment from .env
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

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
echo "Starting server on port ${PORT}"
exec go run .

