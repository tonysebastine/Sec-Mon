#!/usr/bin/env bash
# =============================================================================
# Security Monitor - aaPanel plugin registration helper
# Run AFTER install.sh if the plugin doesn't appear in aaPanel UI.
# Usage:  sudo bash register.sh
# =============================================================================
set -euo pipefail

PLUGIN_NAME="sec_mon"
PANEL_DIR="/www/server/panel"
PANEL_PLUGIN_DIR="${PANEL_DIR}/plugin/${PLUGIN_NAME}"

log()  { echo -e "\033[1;32m[sec_mon]\033[0m $*"; }
err()  { echo -e "\033[1;31m[sec_mon]\033[0m $*" >&2; }

[[ $EUID -eq 0 ]] || { err "Run as root: sudo bash $0"; exit 1; }
[[ -d "${PANEL_DIR}" ]] || { err "aaPanel not found at ${PANEL_DIR}"; exit 1; }
[[ -f "${PANEL_PLUGIN_DIR}/info.json" ]] || { err "Plugin not installed"; exit 1; }

# Force reload of plugin metadata
log "Touching info.json to update mtime..."
touch "${PANEL_PLUGIN_DIR}/info.json"

# Remove Python bytecode cache so aaPanel sees the new files
log "Clearing bytecode cache..."
find "${PANEL_PLUGIN_DIR}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Trigger aaPanel plugin rescan
log "Restarting aaPanel..."
if [[ -x /etc/init.d/bt ]]; then
    /etc/init.d/bt restart
else
    pkill -f "BTPanel" 2>/dev/null || true
    nohup "${PANEL_DIR}/BTPanel" start >/dev/null 2>&1 &
fi

# Optional: write to plugin.json registry if aaPanel uses one
PLUGIN_REGISTRY="${PANEL_DIR}/data/plugin.json"
if [[ -f "${PLUGIN_REGISTRY}" ]]; then
    log "Updating plugin registry..."
    if command -v python3 >/dev/null 2>&1; then
        python3 <<PYEOF
import json, os
reg_file = "${PLUGIN_REGISTRY}"
try:
    with open(reg_file, 'r') as f:
        data = json.load(f)
except:
    data = {}
if 'plugins' not in data:
    data['plugins'] = []
# Add our plugin if not present
if not any(p.get('name') == '${PLUGIN_NAME}' for p in data['plugins']):
    data['plugins'].append({
        'name': '${PLUGIN_NAME}',
        'title': 'Security Monitor',
        'version': '1.0.0',
        'path': '${PLUGIN_PLUGIN_DIR}',
        'installed': True,
    })
with open(reg_file, 'w') as f:
    json.dump(data, f, indent=2)
print(f"Plugin registered: ${{reg_file}}")
PYEOF
    fi
fi

log "Done. Try reloading aaPanel UI (Ctrl+Shift+R) and look in App Store -> My Plugins."
log "If still not visible, check: tail -f /www/server/panel/logs/error.log"