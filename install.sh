#!/usr/bin/env bash
#
# install.sh - Install all dependencies for the zero-trust P2P Tor chat
# on Debian 11 (Bullseye) or later, amd64.
#
# Idempotent: safe to re-run. Requires root/sudo for apt + tor setup.
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"

log() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "This step needs root. Re-run with: sudo ./install.sh"
    exit 1
  fi
}

require_debian() {
  if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
    warn "Non-Debian system detected. Proceeding, but packages may differ."
  fi
}

install_apt_deps() {
  log "Updating apt and installing system packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # tor: onion service + control port
  # snowflake-client: maintained pluggable transport (Debian 12+ provides it;
  #   on Bullseye it ships via the Tor Project repo / backports).
  apt-get install -y \
    tor \
    python3 python3-venv python3-pip python3-dev \
    build-essential libffi-dev libssl-dev \
    ca-certificates wget gpg

  if ! apt-get install -y snowflake-client 2>/dev/null; then
    warn "snowflake-client not in default repos."
    warn "Add the Tor Project repository or Debian backports, then:"
    warn "    apt-get install snowflake-client"
    warn "The app expects the binary at /usr/bin/snowflake-client"
  fi
}

setup_venv() {
  log "Creating Python virtualenv at ${VENV_DIR}..."
  # Build the venv as the invoking (non-root) user when run via sudo.
  local run_as="${SUDO_USER:-root}"
  sudo -u "${run_as}" python3 -m venv "${VENV_DIR}" 2>/dev/null || python3 -m venv "${VENV_DIR}"
  sudo -u "${run_as}" "${VENV_DIR}/bin/pip" install --upgrade pip 2>/dev/null \
    || "${VENV_DIR}/bin/pip" install --upgrade pip
  sudo -u "${run_as}" "${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/requirements.txt" 2>/dev/null \
    || "${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/requirements.txt"
}

prepare_runtime_dirs() {
  log "Preparing per-user runtime directory (no secrets are committed)..."
  local run_as="${SUDO_USER:-root}"
  local home; home="$(eval echo "~${run_as}")"
  local base="${home}/.zt-chat"
  mkdir -p "${base}/runtime" "${base}/onion_auth" "${base}/state"
  chmod 700 "${base}" "${base}/runtime" "${base}/onion_auth" "${base}/state"
  chown -R "${run_as}:${run_as}" "${base}"
  log "Runtime base: ${base}"
}

verify_tor() {
  if command -v tor >/dev/null 2>&1; then
    log "tor found: $(tor --version | head -n1)"
  else
    err "tor not installed."; exit 1
  fi
  if command -v snowflake-client >/dev/null 2>&1; then
    log "snowflake-client found: $(command -v snowflake-client)"
  else
    warn "snowflake-client missing - install it before running the app."
  fi
}

main() {
  require_root
  require_debian
  install_apt_deps
  setup_venv
  prepare_runtime_dirs
  verify_tor
  log "Done. Launch the app with:"
  log "    ./run.sh"
}

main "$@"
