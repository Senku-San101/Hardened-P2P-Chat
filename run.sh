#!/usr/bin/env bash
# Launcher: activates the venv and starts the chat app.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${REPO_DIR}/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "Virtualenv missing. Run ./install.sh first." >&2
  exit 1
fi
exec "${VENV}/bin/python" -m chatapp "$@"
