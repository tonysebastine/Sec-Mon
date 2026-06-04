#!/usr/bin/env bash
# =============================================================================
# Security Monitor - aaPanel plugin installer
# Target: Debian 13, aaPanel 8.0.3, MariaDB
# Usage:  sudo bash install.sh install
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
PLUGIN_NAME="sec_mon"
PANEL_DIR="/www/server/panel"
PANEL_PLUGIN_DIR="${PANEL_DIR}/plugin/${PLUGIN_NAME}"
PANEL_DATA_DIR="${PANEL_DIR}/data"
PY_BIN="$(command -v python3 || command -v python)"

cd "${PANEL_PLUGIN_DIR}"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()  { echo -e "\033[1;32m[sec_mon]\033[0m $*"; }
warn() { echo -e "\033[1;33m[sec_mon]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[sec_mon]\033[0m $*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Please run as root: sudo bash $0 install"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# aaPanel detection
# -----------------------------------------------------------------------------
panel_installed() {
    # Check directory and key aaPanel binaries
    [[ -d "${PANEL_DIR}" ]] && \
    [[ -f "${PANEL_DIR}/BTPanel/__init__.py" || -f "${PANEL_DIR}/BTPanel" ]]
}

# -----------------------------------------------------------------------------
# Locate aaPanel DB credentials
# Tries multiple config file locations used across aaPanel versions.
# -----------------------------------------------------------------------------
find_panel_config() {
    local candidates=(
        "${PANEL_DIR}/config/db.json"          # newer aaPanel
        "${PANEL_DIR}/data/db.conf"             # older aaPanel
        "${PANEL_DIR}/config/config.json"
        "${PANEL_DATA_DIR}/db.conf"
        "/root/.config/bt/db.json"
    )
    for f in "${candidates[@]}"; do
        if [[ -f "${f}" ]]; then
            echo "${f}"
            return 0
        fi
    done
    return 1
}

# -----------------------------------------------------------------------------
# Read aaPanel's MariaDB credentials (supports multiple aaPanel versions)
# -----------------------------------------------------------------------------
read_panel_db() {
    local cfg
    if ! cfg=$(find_panel_config); then
        err "Could not locate aaPanel DB config."
        err "Searched: ${PANEL_DIR}/config/db.json, ${PANEL_DATA_DIR}/db.conf, etc."
        err "If your aaPanel uses a non-standard path, set DB_HOST/DB_USER/DB_PASS env vars."
        exit 1
    fi
    log "Found aaPanel DB config: ${cfg}"

    # Try JSON format first (newer aaPanel)
    if [[ "${cfg}" == *.json ]]; then
        DB_USER=$(python3 -c "import json,sys; d=json.load(open('${cfg}')); print(d.get('mysql_username', d.get('user', 'root')))" 2>/dev/null || echo "root")
        DB_PASS=$(python3 -c "import json,sys; d=json.load(open('${cfg}')); print(d.get('mysql_password', d.get('password', '')))" 2>/dev/null || echo "")
        DB_HOST=$(python3 -c "import json,sys; d=json.load(open('${cfg}')); print(d.get('mysql_host', d.get('host', '127.0.0.1')))" 2>/dev/null || echo "127.0.0.1")
        DB_PORT=$(python3 -c "import json,sys; d=json.load(open('${cfg}')); print(d.get('mysql_port', d.get('port', 3306)))" 2>/dev/null || echo "3306")
    else
        # Legacy Python-dict format (older aaPanel)
        DB_USER=$(awk -F"'" '/mysql_username/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${cfg}" 2>/dev/null || true)
        DB_PASS=$(awk -F"'" '/mysql_password/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${cfg}" 2>/dev/null || true)
        DB_HOST=$(awk -F"'" '/mysql_host/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${cfg}" 2>/dev/null || true)
        DB_PORT=$(awk -F"'" '/mysql_port/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${cfg}" 2>/dev/null || true)
    fi

    # Fallbacks
    DB_USER="${DB_USER:-root}"
    DB_PASS="${DB_PASS:-}"
    DB_HOST="${DB_HOST:-127.0.0.1}"
    DB_PORT="${DB_PORT:-3306}"

    # Allow env var overrides
    DB_USER="${DB_USER_OVERRIDE:-$DB_USER}"
    DB_PASS="${DB_PASS_OVERRIDE:-$DB_PASS}"
    DB_HOST="${DB_HOST_OVERRIDE:-$DB_HOST}"
    DB_PORT="${DB_PORT_OVERRIDE:-$DB_PORT}"

    export DB_USER DB_PASS DB_HOST DB_PORT
    log "DB target: ${DB_USER}@${DB_HOST}:${DB_PORT}"
}

# -----------------------------------------------------------------------------
# Steps
# -----------------------------------------------------------------------------
install_python_deps() {
    log "Installing Python dependencies..."
    if "${PY_BIN}" -m pip install --quiet --break-system-packages -r requirements.txt 2>/dev/null; then
        log "Python dependencies installed."
    elif "${PY_BIN}" -m pip install --quiet -r requirements.txt 2>/dev/null; then
        log "Python dependencies installed."
    else
        err "Failed to install Python dependencies. Please install manually:"
        err "  ${PY_BIN} -m pip install -r ${PANEL_PLUGIN_DIR}/requirements.txt"
        exit 1
    fi
}

create_dirs() {
    log "Creating runtime directories..."
    mkdir -p logs data data/offsets config
    touch logs/app.log logs/daemon.log logs/error.log
    chmod 750 logs data
}

seed_config() {
    if [[ ! -f "config/config.json" ]]; then
        log "Seeding config/config.json from default..."
        cp config/default.json config/config.json
        chmod 640 config/config.json
    else
        log "config/config.json already exists, leaving untouched."
    fi
}

create_database() {
    log "Creating MariaDB database '${PLUGIN_NAME}'..."
    DB_USER="${DB_USER}" DB_PASS="${DB_PASS}" "${PY_BIN}" - <<PYEOF
import pymysql, os, sys
try:
    conn = pymysql.connect(host=os.environ.get("DB_HOST","127.0.0.1"),
                           port=int(os.environ.get("DB_PORT","3306")),
                           user=os.environ.get("DB_USER","root"),
                           password=os.environ.get("DB_PASS",""),
                           charset="utf8mb4")
    with conn.cursor() as c:
        c.execute(f"CREATE DATABASE IF NOT EXISTS \`${PLUGIN_NAME}\` "
                  f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    conn.commit()
    conn.close()
    print("OK")
except Exception as e:
    print(f"ERR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

apply_schema() {
    log "Applying database/schema.sql..."
    DB_USER="${DB_USER}" DB_PASS="${DB_PASS}" "${PY_BIN}" - <<PYEOF
import pymysql, os, sys
with open("database/schema.sql", "r", encoding="utf-8") as f:
    sql = f.read()
statements = [s.strip() for s in sql.split(";") if s.strip()
              and not s.strip().startswith("--")]
conn = pymysql.connect(host=os.environ.get("DB_HOST","127.0.0.1"),
                       port=int(os.environ.get("DB_PORT","3306")),
                       user=os.environ.get("DB_USER","root"),
                       password=os.environ.get("DB_PASS",""),
                       database="${PLUGIN_NAME}", charset="utf8mb4")
try:
    with conn.cursor() as c:
        for stmt in statements:
            c.execute(stmt)
    conn.commit()
finally:
    conn.close()
print("OK")
PYEOF
}

set_permissions() {
    log "Setting ownership and permissions..."
    chown -R root:root "${PANEL_PLUGIN_DIR}"
    find "${PANEL_PLUGIN_DIR}" -type d -exec chmod 750 {} \;
    find "${PANEL_PLUGIN_DIR}" -type f -exec chmod 640 {} \;
    chmod 750 install.sh uninstall.sh
    chmod 770 logs data
}

print_summary() {
    cat <<EOF

==============================================================================
 Security Monitor 1.0.0 installed
==============================================================================
 Plugin path : ${PANEL_PLUGIN_DIR}
 Database    : ${PLUGIN_NAME}@${DB_HOST}:${DB_PORT}
 Config      : ${PANEL_PLUGIN_DIR}/config/config.json
 Logs        : ${PANEL_PLUGIN_DIR}/logs/
 Data        : ${PANEL_PLUGIN_DIR}/data/

 Next steps:
   1. Reload aaPanel:   sudo bt reload
   2. Open aaPanel UI -> App Store -> "Security Monitor" (My Plugins)
   3. Open the plugin to access the dashboard.

 To uninstall:
   sudo bash ${PANEL_PLUGIN_DIR}/uninstall.sh uninstall
==============================================================================
EOF
}

# -----------------------------------------------------------------------------
# Entry
# -----------------------------------------------------------------------------
ACTION="${1:-install}"

require_root
if ! panel_installed; then
    err "aaPanel not detected at ${PANEL_DIR}. Aborting."
    err "If aaPanel is installed at a different path, set PANEL_DIR env var."
    exit 1
fi
read_panel_db

case "${ACTION}" in
    install)
        install_python_deps
        create_dirs
        seed_config
        create_database
        apply_schema
        set_permissions
        print_summary
        ;;
    reinstall)
        warn "Reinstall: preserving config and data, refreshing schema"
        create_dirs
        apply_schema
        set_permissions
        print_summary
        ;;
    *)
        err "Unknown action: ${ACTION}"
        echo "Usage: $0 {install|reinstall}" >&2
        exit 1
        ;;
esac