#!/usr/bin/env bash
# Least-invasive r2b install. User-space only.
#   No sudo, no ~/.config, no clone unless R2B_CLONE=1, no flavor overlay.
#
#   git clone https://github.com/sandbornm/r2brief.git
#   cd r2brief && ./scripts/install.sh
#
# Optional: R2B_FLAVOR=full ./scripts/install.sh
#           R2B_CLONE=1 R2B_DIR=$HOME/src/r2brief ./scripts/install.sh
set -euo pipefail

# C.UTF-8 is not a valid locale name on every supported host (notably macOS).
# The setup output is ASCII, so use the portable POSIX locale for child tools.
export LANG=C
export LC_ALL=C

INSTALL_STARTED_AT="$(date +%s)"

here() {
  local src="${BASH_SOURCE[0]:-}"
  if [[ -n "$src" && -f "$src" ]]; then
    cd "$(dirname "$src")/.." && pwd
  else
    pwd
  fi
}

in_checkout() {
  [[ -f "$1/pyproject.toml" && -d "$1/src/r2b" ]]
}

ROOT=""
if in_checkout "$(pwd)"; then
  ROOT="$(pwd)"
elif ROOT="$(here)" && in_checkout "$ROOT"; then
  :
else
  if [[ "${R2B_CLONE:-0}" != "1" ]]; then
    echo "[!] not an r2b checkout. cd into the repo and rerun, or:" >&2
    echo "    git clone https://github.com/sandbornm/r2brief.git && cd r2brief && ./scripts/install.sh" >&2
    echo "    (set R2B_CLONE=1 to let this script clone into \$R2B_DIR)" >&2
    exit 1
  fi
  DEST="${R2B_DIR:-$PWD/r2brief}"
  if [[ ! -d "$DEST/.git" ]]; then
    git clone "${R2B_REPO:-https://github.com/sandbornm/r2brief.git}" "$DEST"
  fi
  ROOT="$DEST"
fi
cd "$ROOT"

if ! command -v uv >/dev/null 2>&1; then
  echo "[*] uv (user-space)"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${PATH}"
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "[!] uv not on PATH. Add \$HOME/.local/bin and rerun." >&2
  exit 1
fi

FLAVOR="${R2B_FLAVOR:-}"
echo "[*] python extras (no sudo, no home config)"
if [[ -n "$FLAVOR" ]]; then
  R2B_FLAVOR="$FLAVOR" "$ROOT/scripts/setup_backend.sh"
else
  "$ROOT/scripts/setup_backend.sh"
fi

echo
echo "[*] smoke"
uv run --no-sync --python 3.11 r2b env --json >/dev/null
SETUP_ARGS=(setup --json)
if [[ -n "$FLAVOR" ]]; then
  SETUP_ARGS+=(--flavor "$FLAVOR")
fi
uv run --no-sync --python 3.11 r2b "${SETUP_ARGS[@]}" | \
  uv run --no-sync --python 3.11 python -c \
    "import json,sys; p=json.load(sys.stdin); print('flavor', p['flavor'], 'extra', p['uv_extra'])"

if ! command -v radare2 >/dev/null 2>&1 && ! command -v r2 >/dev/null 2>&1; then
  echo "[.] radare2 not on PATH — brief still installs; install r2 when you want analysis:" >&2
  echo "    sudo apt-get install -y radare2 file libmagic-dev" >&2
  echo "    # brew install radare2 libmagic" >&2
fi

echo
INSTALL_ELAPSED="$(( $(date +%s) - INSTALL_STARTED_AT ))"
echo "ready in ${INSTALL_ELAPSED}s. LICENSE=MIT  notices=NOTICE.md"
echo "  uv run r2b brief /bin/ls --quick --json"
echo "  optional model: configure config/local.toml (see README)"
