#!/usr/bin/env bash
# reap installer — run on any Kali (or Linux) instance after cloning/copying the
# project. Two install modes:
#   * default  : an isolated project .venv + the `reap` command (activate to use)
#   * --pipx   : a global, editable `reap` command via pipx (no activation needed)
set -euo pipefail

usage() {
  cat <<'EOF'
reap installer

  ./install.sh [flags]

Flags (combine freely):
  --pipx           global, editable `reap` command via pipx (no venv activation)
  --db             + DB login backends (mysql / postgres / mongo / mssql)
  --win            + Windows/AD backends (SMB + pass-the-hash + GPP decrypt)
  --full           + all optional backends (db + win)
  --with-pwncat    also set up pwncat-vl in its own venv + a version lockfile
  --trusted-host   pass pip --trusted-host (use behind a TLS-intercepting proxy)
  -h, --help       this help

Examples:
  ./install.sh                              local .venv, core only
  ./install.sh --full                       local .venv + all extras
  ./install.sh --pipx --full                global editable command + all extras
  ./install.sh --pipx --full --trusted-host global + extras behind a corporate proxy
EOF
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
PYTHON="${PYTHON:-python3}"

WITH_PWNCAT=0
USE_PIPX=0
EXTRA=""            # "" | db | win | full
PIP_ARGS=""         # extra pip args (e.g. --trusted-host ...)

for arg in "$@"; do
  case "$arg" in
    --pipx) USE_PIPX=1 ;;
    --db) EXTRA="db" ;;
    --win) EXTRA="win" ;;
    --full) EXTRA="full" ;;
    --with-pwncat) WITH_PWNCAT=1 ;;
    --trusted-host)
      PIP_ARGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $arg"; echo; usage; exit 2 ;;
  esac
done

# Packages behind each extra — kept in sync with pyproject.toml's [project.optional-dependencies].
case "$EXTRA" in
  db)   EXTRA_PKGS="pymysql psycopg2-binary pymongo pymssql" ;;
  win)  EXTRA_PKGS="impacket cryptography" ;;
  full) EXTRA_PKGS="pymysql psycopg2-binary pymongo pymssql impacket cryptography" ;;
  *)    EXTRA_PKGS="" ;;
esac

if [[ "$USE_PIPX" == "1" ]]; then
  if ! command -v pipx >/dev/null 2>&1; then
    echo "[!] pipx not found. Install it first, e.g.:"
    echo "      sudo apt install -y pipx && pipx ensurepath   # then open a new shell"
    exit 1
  fi
  PIPX_PIPARGS=()
  [[ -n "$PIP_ARGS" ]] && PIPX_PIPARGS=(--pip-args "$PIP_ARGS")
  echo "[*] Installing reap globally via pipx (editable)"
  pipx install --force --editable "${PIPX_PIPARGS[@]}" "$HERE"
  if [[ -n "$EXTRA_PKGS" ]]; then
    echo "[*] Injecting '$EXTRA' extras into reap: $EXTRA_PKGS"
    # shellcheck disable=SC2086
    pipx inject reap $EXTRA_PKGS "${PIPX_PIPARGS[@]}"
  fi
  echo
  echo "[+] reap installed globally (pipx, editable)."
  echo "    run:     reap"
  echo "    update:  refresh the ~/reap source (git pull / rsync) — code is live, no reinstall"
else
  SPEC="."
  [[ -n "$EXTRA" ]] && SPEC=".[$EXTRA]"
  echo "[*] Creating venv -> .venv"
  "$PYTHON" -m venv .venv
  # shellcheck disable=SC1091
  . .venv/bin/activate
  # shellcheck disable=SC2086
  pip install $PIP_ARGS --upgrade pip wheel >/dev/null
  echo "[*] Installing reap ($SPEC)"
  # shellcheck disable=SC2086
  pip install $PIP_ARGS -e "$SPEC"
  echo
  echo "[+] reap installed."
  echo "    activate:  source $HERE/.venv/bin/activate"
  echo "    run:       reap            (or: python -m reap)"
fi
echo

if [[ "$WITH_PWNCAT" == "1" ]]; then
  PWNVENV="$HOME/.reap-pwncat"
  echo "[*] Installing pwncat-vl in its own venv -> $PWNVENV"
  "$PYTHON" -m venv "$PWNVENV"
  # shellcheck disable=SC2086
  "$PWNVENV/bin/pip" install $PIP_ARGS --upgrade pip >/dev/null
  # shellcheck disable=SC2086
  "$PWNVENV/bin/pip" install $PIP_ARGS pwncat-vl
  "$PWNVENV/bin/pip" freeze | grep -i pwncat > "$HERE/requirements-pwncat.lock" || true
  echo "[+] pwncat-vl installed. Pin captured in requirements-pwncat.lock:"
  cat "$HERE/requirements-pwncat.lock" 2>/dev/null || true
  echo "    run it with: $PWNVENV/bin/pwncat-cs"
fi
