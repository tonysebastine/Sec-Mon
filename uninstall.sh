#!/usr/bin/env bash
# =============================================================================
# Security Monitor - aaPanel plugin uninstaller
# Usage:  sudo bash uninstall.sh uninstall [--keep-db] [--keep-config]
# =============================================================================
set -euo pipefail

PLUGIN_NAME="sec_mon"
PANEL_PLUGIN_DIR="/www/server/panel/plugin/${PLUGIN_NAME}"
PANEL_DATA_DIR="/www/server/panel/data"
PANEL_CONFIG="${PANEL_DATA_DIR}/db.conf"
PY_BIN="$(command -v python3 || command -v python)"

KEEP_DB=0
KEEP_CONFIG=0
for arg in "$@"; do
    case "${arg}" in
        --keep-db)     KEEP_DB=1 ;;
        --keep-config) KEEP_CONFIG=1 ;;
        *) ;;
    esac
done

cd "${PANEL_PLUGIN_DIR}"

log()  { echo -e "\033[1;32m[sec_mon]\033[0m $*"; }
warn() { echo -e "\033[1;33m[sec_mon]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[sec_mon]\033[0m $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "Please run as root: sudo bash $0 uninstall"
    exit 1
fi

# -----------------------------------------------------------------------------
# Read aaPanel DB credentials (same logic as install.sh)
# -----------------------------------------------------------------------------
read_panel_db() {
    DB_USER=$(awk -F"'" '/mysql_username/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${PANEL_CONFIG}" 2>/dev/null || true)
    DB_PASS=$(awk -F"'" '/mysql_password/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${PANEL_CONFIG}" 2>/dev/null || true)
    DB_HOST=$(awk -F"'" '/mysql_host/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${PANEL_CONFIG}" 2>/dev/null || true)
    DB_PORT=$(awk -F"'" '/mysql_port/{for(i=1;i<=NF;i++){if($i=="'"'"'"){print $(i+2);exit}}}' "${PANEL_CONFIG}" 2>/dev/null || true)
    DB_HOST="${DB_HOST:-127.0.0.1}"
    DB_PORT="${DB_PORT:-3306}"
    export DB_USER DB_PASS DB_HOST DB_PORT
}

stop_background_workers() {
    log "Stopping any background workers..."
    pkill -f "sec_mon.*daemon" 2>/dev/null || true
    pkill -f "sec_mon.*ingester" 2>/dev/null || true
    if [[ -f "data/sec_mon.pid" ]]; then
        local pid
        pid=$(cat "data/sec_mon.pid" 2>/dev/null || echo "")
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
        fi
        rm -f "data/sec_mon.pid"
    fi
}

drop_database() {
    if [[ ${KEEP_DB} -eq 1 ]]; then
        warn "--keep-db specified: leaving database '${PLUGIN_NAME}' intact"
        return
    fi
    log "Dropping MariaDB database '${PLUGIN_NAME}'..."
    "${PY_BIN}" - <<PYEOF
import pymysql, sys
try:
    conn = pymysql.connect(host="${DB_HOST}", port=int("${DB_PORT}"),
                           user="${DB_USER}", password="${DB_PASS}",
                           charset="utf8mb4")
    with conn.cursor() as c:
        c.execute(f"DROP DATABASE IF EXISTS \`${PLUGIN_NAME}\`;")
    conn.commit()
    conn.close()
    print("OK")
except Exception as e:
    print(f"ERR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

remove_files() {
    log "Removing plugin files at ${PANEL_PLUGIN_DIR}..."
    cd /
    rm -rf "${PANEL_PLUGIN_DIR}"
}

remove_config_only() {
    if [[ ${KEEP_CONFIG} -eq 1 ]]; then
        warn "--keep-config specified: leaving config/config.json"
        return
    fi
    rm -f "${PANEL_PLUGIN_DIR}/config/config.json" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Entry
# -----------------------------------------------------------------------------
ACTION="${1:-uninstall}"

if [[ ! -f "${PANEL_CONFIG}" ]]; then
    warn "aaPanel config not found, will still remove plugin files."
fi

case "${ACTION}" in
    uninstall)
        stop_background_workers
        read_panel_db
        drop_database
        remove_files
        log "Security Monitor uninstalled."
        log "Reload aaPanel to refresh the plugin list: sudo bt reload"
        ;;
    *)
        err "Unknown action: ${ACTION}"
        echo "Usage: $0 uninstall [--keep-db] [--keep-config]" >&2
        exit 1
        ;;
esac
