#!/bin/bash
# ============================================================
# Arma Reforger Panel — All-in-One Installer v5.0 (LGSM edition)
# https://github.com/BitstreamLabs/arma-reforger-panel
#
# Modes:
#   sudo bash install.sh               — full install (LGSM instance(s) + panel)
#   sudo bash install.sh --panel-only  — install panel only (LGSM instances already exist)
#   sudo bash install.sh --add-server  — register one more existing LGSM instance
#   sudo bash install.sh --update      — update panel files only
#
# Every managed server is a LinuxGSM (https://linuxgsm.com) Arma Reforger
# ("armarserver") instance. The panel drives each one entirely through its
# own instance script (`./<id> start|stop|restart|monitor`) — this installer
# never touches the game binary directly.
# ============================================================

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
ARMA_USER="arma"
ARMA_HOME="/home/arma"
SERVERS_ROOT="/home/arma/servers"
PANEL_DIR="/home/arma/panel"
PANEL_PORT="8888"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="full"
case "$1" in
    --panel-only) MODE="panel" ;;
    --add-server) MODE="add-server" ;;
    --update)     MODE="update" ;;
esac

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║   Arma Reforger Panel — Installer v5.0 (LGSM)   ║${NC}"
echo -e "${BOLD}${CYAN}║   github.com/BitstreamLabs                       ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

case "$MODE" in
    full)        echo -e "  Mode: ${GREEN}Full install${NC} (LinuxGSM instance(s) + Panel)" ;;
    panel)       echo -e "  Mode: ${YELLOW}Panel only${NC} (register existing LGSM instances)" ;;
    add-server)  echo -e "  Mode: ${YELLOW}Add server${NC} (register one more LGSM instance)" ;;
    update)      echo -e "  Mode: ${CYAN}Update${NC} (panel files only)" ;;
esac
echo ""

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run as root: sudo bash install.sh${NC}"
    exit 1
fi

# ── OS check ──────────────────────────────────────────────────────────────────
if ! grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}WARNING: This installer is tested on Ubuntu 20.04/22.04/24.04 and Debian 11+ (LGSM's supported distros).${NC}"
    read -p "  Continue anyway? [y/N]: " CONTINUE
    [[ "$CONTINUE" =~ ^[Yy]$ ]] || exit 1
fi

# ── UPDATE mode ───────────────────────────────────────────────────────────────
if [[ "$MODE" == "update" ]]; then
    echo -e "${YELLOW}Updating panel files...${NC}"
    if [ ! -d "$PANEL_DIR" ]; then
        echo -e "${RED}ERROR: Panel not found at ${PANEL_DIR}${NC}"
        echo -e "  Run the full installer first: sudo bash install.sh"
        exit 1
    fi
    # Read existing user from panel service
    EXISTING_USER=$(grep "^User=" /etc/systemd/system/arma-panel.service 2>/dev/null | cut -d= -f2 || echo "arma")
    PANEL_DIR_EXISTING=$(grep "^WorkingDirectory=" /etc/systemd/system/arma-panel.service 2>/dev/null | cut -d= -f2 || echo "$PANEL_DIR")
    cp "$SCRIPT_DIR/app.py"     "$PANEL_DIR_EXISTING/"
    cp "$SCRIPT_DIR/index.html" "$PANEL_DIR_EXISTING/"
    cp "$SCRIPT_DIR/login.html" "$PANEL_DIR_EXISTING/"
    cp "$SCRIPT_DIR/static/"*   "$PANEL_DIR_EXISTING/static/"
    chown -R "$EXISTING_USER:$EXISTING_USER" "$PANEL_DIR_EXISTING"
    systemctl restart arma-panel
    echo -e "${GREEN}✓ Panel updated and restarted.${NC}"
    echo ""
    exit 0
fi

# ── Shared helper: register a server into servers.json ────────────────────────
# Usage: register_server <panel_dir> <id> <name> <lgsm_dir>
# Derives serverfiles/profile/log/workshop paths from LGSM's default Arma
# Reforger template (config json at serverfiles/<id>_config.json, profile at
# serverfiles/profiles/server) unless that layout doesn't exist, in which
# case the entry is still written — edit servers.json by hand if your layout
# differs.
register_server() {
    local panel_dir="$1" id="$2" name="$3" lgsm_dir="$4"
    python3 - "$panel_dir/servers.json" "$id" "$name" "$lgsm_dir" << 'PYEOF'
import json, os, sys

servers_file, sid, name, lgsm_dir = sys.argv[1:5]
serverfiles = os.path.join(lgsm_dir, "serverfiles")
profile_dir = os.path.join(serverfiles, "profiles", "server")

entry = {
    "id": sid,
    "name": name,
    "lgsm_dir": lgsm_dir,
    "server_config": os.path.join(serverfiles, f"{sid}_config.json"),
    "profile_dir":   profile_dir,
    "log_dir":       os.path.join(profile_dir, "logs"),
    "workshop_dir":  os.path.join(profile_dir, "addons"),
}

try:
    with open(servers_file) as f:
        servers = json.load(f)
    if not isinstance(servers, list):
        servers = []
except (OSError, json.JSONDecodeError):
    servers = []

servers = [s for s in servers if s.get("id") != sid]
servers.append(entry)

with open(servers_file, "w") as f:
    json.dump(servers, f, indent=2)

print(f"      Registered '{sid}' -> {servers_file}")
PYEOF
}

# ── Shared helper: write config.json for a freshly auto-installed instance ────
# LGSM ships a default Arma Reforger config only once the instance is first
# started; we write it ourselves up front so name/password/ports are set
# before that first start.
write_instance_config() {
    local config_path="$1" server_name="$2" game_password="$3" admin_password="$4" \
          max_players="$5" game_port="$6" public_ip="$7"
    mkdir -p "$(dirname "$config_path")"
    cat > "$config_path" << EOF
{
	"bindAddress": "0.0.0.0",
	"bindPort": ${game_port},
	"publicAddress": "${public_ip}",
	"publicPort": ${game_port},
	"a2s": {
		"address": "${public_ip}",
		"port": 17777
	},
	"game": {
		"name": "${server_name}",
		"password": "${game_password}",
		"passwordAdmin": "${admin_password}",
		"scenarioId": "{ECC61978EDCC2B5A}Missions/23_Campaign.conf",
		"maxPlayers": ${max_players},
		"visible": true,
		"crossPlatform": true,
		"supportedPlatforms": ["PLATFORM_PC", "PLATFORM_XBL"],
		"gameProperties": {
			"serverMaxViewDistance": 2500,
			"serverMinGrassDistance": 50,
			"networkViewDistance": 1000,
			"disableThirdPerson": false,
			"fastValidation": true,
			"battlEye": true
		},
		"mods": []
	}
}
EOF
}

# ── Shared helper: install one LGSM instance under $SERVERS_ROOT/<id> ─────────
install_lgsm_instance() {
    local user="$1" id="$2" root="$3"
    mkdir -p "$root"
    chown "$user:$user" "$root"
    echo -e "      ${DIM}Downloading LinuxGSM and installing instance '${id}'...${NC}"
    sudo -u "$user" bash -c "
        cd '$root' &&
        curl -sLo linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh &&
        bash linuxgsm.sh $id &&
        yes | ./$id auto-install
    "
}

# ── Cron: LGSM's own crash-restart mechanism ───────────────────────────────────
# LGSM recommends a cron job running `./<id> monitor` rather than a systemd
# Restart=on-failure unit — monitor checks the tmux session LGSM launched and
# restarts it if it died, using LGSM's own startup parameters every time.
add_monitor_cron() {
    local user="$1" root="$2" id="$3"
    local line="*/5 * * * * ${root}/${id} monitor > /dev/null 2>&1"
    ( sudo -u "$user" crontab -l 2>/dev/null | grep -vF "${root}/${id} monitor" ; echo "$line" ) | sudo -u "$user" crontab -
    echo -e "      ${GREEN}✓${NC} Cron monitor installed for '${id}' (every 5 min)."
}

# ── ADD-SERVER mode ─────────────────────────────────────────────────────────────
if [[ "$MODE" == "add-server" ]]; then
    if [ ! -f "$PANEL_DIR/servers.json" ] && [ ! -d "$PANEL_DIR" ]; then
        echo -e "${RED}ERROR: Panel not found. Run the full installer first.${NC}"
        exit 1
    fi
    read -p "  Panel directory [$PANEL_DIR]: " INPUT_PANEL_DIR
    PANEL_DIR="${INPUT_PANEL_DIR:-$PANEL_DIR}"
    EXISTING_USER=$(grep "^User=" /etc/systemd/system/arma-panel.service 2>/dev/null | cut -d= -f2 || echo "$ARMA_USER")

    read -p "  New instance id (LGSM script name, e.g. armarserver2): " NEW_ID
    read -p "  Display name [$NEW_ID]: " NEW_NAME
    NEW_NAME="${NEW_NAME:-$NEW_ID}"
    read -p "  Install a fresh LGSM instance now, or register an existing one? [install/existing]: " NEW_MODE
    NEW_MODE="${NEW_MODE:-install}"

    if [[ "$NEW_MODE" == "existing" ]]; then
        read -p "  LGSM directory for '$NEW_ID': " NEW_DIR
        if [ ! -f "$NEW_DIR/$NEW_ID" ]; then
            echo -e "${RED}ERROR: No instance script found at ${NEW_DIR}/${NEW_ID}${NC}"
            exit 1
        fi
    else
        NEW_DIR="$SERVERS_ROOT/$NEW_ID"
        install_lgsm_instance "$EXISTING_USER" "$NEW_ID" "$NEW_DIR"
        read -p "  Server name [$NEW_NAME]: " CFG_NAME; CFG_NAME="${CFG_NAME:-$NEW_NAME}"
        read -p "  Game password (empty = public): " CFG_GPW
        read -p "  Admin password: " CFG_APW
        while [ -z "$CFG_APW" ]; do echo -e "  ${RED}Admin password cannot be empty.${NC}"; read -p "  Admin password: " CFG_APW; done
        read -p "  Max players [32]: " CFG_MAX; CFG_MAX="${CFG_MAX:-32}"
        read -p "  Game port [2001]: " CFG_PORT; CFG_PORT="${CFG_PORT:-2001}"
        read -p "  Public IP (leave empty to auto-detect): " CFG_IP
        [ -z "$CFG_IP" ] && CFG_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
        write_instance_config "$NEW_DIR/serverfiles/${NEW_ID}_config.json" "$CFG_NAME" "$CFG_GPW" "$CFG_APW" "$CFG_MAX" "$CFG_PORT" "$CFG_IP"
        chown "$EXISTING_USER:$EXISTING_USER" "$NEW_DIR/serverfiles/${NEW_ID}_config.json"
        add_monitor_cron "$EXISTING_USER" "$NEW_DIR" "$NEW_ID"
    fi

    register_server "$PANEL_DIR" "$NEW_ID" "$NEW_NAME" "$NEW_DIR"
    chown "$EXISTING_USER:$EXISTING_USER" "$PANEL_DIR/servers.json"
    systemctl restart arma-panel
    echo -e "${GREEN}✓ Server '${NEW_ID}' registered and panel restarted.${NC}"
    exit 0
fi

# ── Collect configuration ─────────────────────────────────────────────────────
echo -e "${BOLD}━━━ Configuration ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "$MODE" == "full" ]]; then
    read -p "  System user for all servers + panel [arma]: " INPUT_USER
    ARMA_USER="${INPUT_USER:-arma}"
    ARMA_HOME="/home/$ARMA_USER"
    SERVERS_ROOT="$ARMA_HOME/servers"
    PANEL_DIR="$ARMA_HOME/panel"
fi

echo ""
echo -e "  ${CYAN}Panel settings:${NC}"
read -p "  Panel web password: " PANEL_PASSWORD
while [ -z "$PANEL_PASSWORD" ]; do
    echo -e "  ${RED}Panel password cannot be empty.${NC}"
    read -p "  Panel web password: " PANEL_PASSWORD
done
read -p "  Panel port [8888]: " INPUT_PORT
PANEL_PORT="${INPUT_PORT:-8888}"

if [[ "$MODE" == "panel" ]]; then
    read -p "  Arma system user (owns the LGSM instances) [$ARMA_USER]: " INPUT_ARMA_USER
    ARMA_USER="${INPUT_ARMA_USER:-$ARMA_USER}"
    ARMA_HOME="/home/$ARMA_USER"
    PANEL_DIR="$ARMA_HOME/panel"
fi

# Servers to register — collected into parallel arrays either by installing
# fresh LGSM instances (full mode) or pointing at existing ones (panel mode).
SERVER_IDS=()
SERVER_NAMES=()
SERVER_DIRS=()

if [[ "$MODE" == "full" ]]; then
    echo ""
    echo -e "  ${CYAN}Game server(s):${NC} each one becomes a separate LinuxGSM instance."
    PUBLIC_IP=""
    ADD_MORE="y"
    while [[ "$ADD_MORE" =~ ^[Yy]$ ]]; do
        echo ""
        read -p "  Instance id (LGSM script name, e.g. armarserver1): " SID
        while [[ ! "$SID" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || [[ " ${SERVER_IDS[*]} " == *" $SID "* ]]; do
            echo -e "  ${RED}Must be 1-32 chars of letters/digits/-/_ and unique.${NC}"
            read -p "  Instance id: " SID
        done
        read -p "  Server name [$SID]: " SNAME; SNAME="${SNAME:-$SID}"
        read -p "  Game password (leave empty for public): " SGPW
        read -p "  Admin password: " SAPW
        while [ -z "$SAPW" ]; do echo -e "  ${RED}Admin password cannot be empty.${NC}"; read -p "  Admin password: " SAPW; done
        read -p "  Max players [32]: " SMAX; SMAX="${SMAX:-32}"
        read -p "  Game port [2001]: " SPORT; SPORT="${SPORT:-2001}"
        if [ -z "$PUBLIC_IP" ]; then
            read -p "  Public IP (leave empty to auto-detect): " PUBLIC_IP
            if [ -z "$PUBLIC_IP" ]; then
                PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
                echo -e "  ${DIM}Auto-detected: $PUBLIC_IP${NC}"
            fi
        fi
        SERVER_IDS+=("$SID"); SERVER_NAMES+=("$SNAME"); SERVER_DIRS+=("$SERVERS_ROOT/$SID")
        eval "CFG_GPW_$SID=\"\$SGPW\""; eval "CFG_APW_$SID=\"\$SAPW\""
        eval "CFG_MAX_$SID=\"\$SMAX\""; eval "CFG_PORT_$SID=\"\$SPORT\""
        read -p "  Add another server? [y/N]: " ADD_MORE
    done
    if [ ${#SERVER_IDS[@]} -eq 0 ]; then
        echo -e "${RED}ERROR: At least one server is required for a full install.${NC}"
        exit 1
    fi
fi

if [[ "$MODE" == "panel" ]]; then
    echo ""
    echo -e "  ${CYAN}Existing LGSM instance(s) to register:${NC}"
    ADD_MORE="y"
    while [[ "$ADD_MORE" =~ ^[Yy]$ ]]; do
        echo ""
        read -p "  Instance id (LGSM script name): " SID
        read -p "  Display name [$SID]: " SNAME; SNAME="${SNAME:-$SID}"
        read -p "  LGSM directory (contains ./${SID}): " SDIR
        if [ ! -f "$SDIR/$SID" ]; then
            echo -e "  ${RED}No instance script found at ${SDIR}/${SID} — skipping.${NC}"
        else
            SERVER_IDS+=("$SID"); SERVER_NAMES+=("$SNAME"); SERVER_DIRS+=("$SDIR")
        fi
        read -p "  Add another? [y/N]: " ADD_MORE
    done
fi

# ── Confirm ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  System user   : ${CYAN}$ARMA_USER${NC}"
for i in "${!SERVER_IDS[@]}"; do
    echo -e "  Server        : ${CYAN}${SERVER_NAMES[$i]}${NC} (${SERVER_IDS[$i]}) @ ${SERVER_DIRS[$i]}"
done
echo -e "  Panel dir     : ${CYAN}$PANEL_DIR${NC}"
echo -e "  Panel port    : ${CYAN}$PANEL_PORT${NC}"
echo ""
read -p "  Proceed? [Y/n]: " CONFIRM
[[ "$CONFIRM" =~ ^[Nn]$ ]] && exit 0
echo ""

# ── FULL MODE: system user + dependencies + LGSM instance(s) ──────────────────
if [[ "$MODE" == "full" ]]; then

    echo -e "${YELLOW}[1/4] Creating system user '${ARMA_USER}'...${NC}"
    if id "$ARMA_USER" &>/dev/null; then
        echo -e "      ${DIM}User already exists — skipping.${NC}"
    else
        useradd -m -s /bin/bash "$ARMA_USER"
        echo -e "      ${GREEN}✓ Done.${NC}"
    fi

    echo -e "${YELLOW}[2/4] Installing dependencies (LGSM needs these for Arma Reforger)...${NC}"
    dpkg --add-architecture i386
    apt-get update -qq
    # Flask/bcrypt via apt (not pip) to avoid Ubuntu 24.04's "Cannot uninstall
    # blinker" conflict with apt-managed packages. `tmux`, `lib32gcc-s1` and
    # `curl` are LGSM's own Arma Reforger requirements.
    apt-get install -y -qq python3 curl tmux lib32gcc-s1 binutils python3-flask python3-bcrypt cron
    echo -e "      ${GREEN}✓ Done.${NC}"

    echo -e "${YELLOW}[3/4] Installing LinuxGSM instance(s)...${NC}"
    for i in "${!SERVER_IDS[@]}"; do
        sid="${SERVER_IDS[$i]}"; sdir="${SERVER_DIRS[$i]}"
        echo -e "  ${CYAN}→ ${sid}${NC}"
        install_lgsm_instance "$ARMA_USER" "$sid" "$sdir"
        gpw_var="CFG_GPW_$sid"; apw_var="CFG_APW_$sid"; max_var="CFG_MAX_$sid"; port_var="CFG_PORT_$sid"
        write_instance_config "$sdir/serverfiles/${sid}_config.json" "${SERVER_NAMES[$i]}" \
            "${!gpw_var}" "${!apw_var}" "${!max_var}" "${!port_var}" "$PUBLIC_IP"
        chown -R "$ARMA_USER:$ARMA_USER" "$sdir"
        add_monitor_cron "$ARMA_USER" "$sdir" "$sid"
    done
    echo -e "      ${GREEN}✓ LGSM instance(s) installed.${NC}"

fi  # end full mode

# ── PANEL install (both full and panel-only modes) ────────────────────────────
PANEL_STEP=4
if [[ "$MODE" == "panel" ]]; then PANEL_STEP=1; fi
TOTAL_STEPS=4
if [[ "$MODE" == "panel" ]]; then TOTAL_STEPS=1; fi

echo -e "${YELLOW}[${PANEL_STEP}/${TOTAL_STEPS}] Installing management panel...${NC}"

if [[ "$MODE" == "panel" ]]; then
    apt-get update -qq
    apt-get install -y -qq python3 binutils python3-flask python3-bcrypt cron
fi

mkdir -p "$PANEL_DIR/static"

for f in app.py index.html login.html; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        cp "$SCRIPT_DIR/$f" "$PANEL_DIR/"
    else
        echo -e "      ${RED}WARNING: $f not found in script directory.${NC}"
    fi
done
for f in manifest.json service-worker.js icon-192.png icon-512.png; do
    if [ -f "$SCRIPT_DIR/static/$f" ]; then
        cp "$SCRIPT_DIR/static/$f" "$PANEL_DIR/static/"
    fi
done

# Hash the panel password with bcrypt so it isn't stored in plaintext.
PANEL_PASSWORD_HASH=$(python3 -c "
import bcrypt, sys
print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())
" "$PANEL_PASSWORD" 2>/dev/null || true)

cat > "$PANEL_DIR/config.env" << EOF
# bcrypt-hashed admin password. Generated at install time.
PANEL_PASSWORD_HASH=${PANEL_PASSWORD_HASH}
PANEL_PORT=${PANEL_PORT}
EOF
chmod 600 "$PANEL_DIR/config.env"

# Seed servers.json with everything collected above.
echo "[]" > "$PANEL_DIR/servers.json"
for i in "${!SERVER_IDS[@]}"; do
    register_server "$PANEL_DIR" "${SERVER_IDS[$i]}" "${SERVER_NAMES[$i]}" "${SERVER_DIRS[$i]}"
done

chown -R "$ARMA_USER:$ARMA_USER" "$PANEL_DIR"

cat > /etc/systemd/system/arma-panel.service << EOF
[Unit]
Description=Arma Reforger Management Panel
After=network.target

[Service]
Type=simple
User=${ARMA_USER}
WorkingDirectory=${PANEL_DIR}
ExecStart=/usr/bin/python3 ${PANEL_DIR}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable arma-panel
systemctl restart arma-panel

# Make sure cron is actually running (Debian/Ubuntu minimal images sometimes ship it disabled).
systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true

echo -e "      ${GREEN}✓ Panel installed and started.${NC}"

# ── Final summary ─────────────────────────────────────────────────────────────
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
fi

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║           Installation complete!                 ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
if [ ${#SERVER_IDS[@]} -gt 0 ]; then
echo -e "  ${BOLD}Arma Reforger Server(s):${NC}"
for i in "${!SERVER_IDS[@]}"; do
    sid="${SERVER_IDS[$i]}"; sdir="${SERVER_DIRS[$i]}"
    echo -e "    ${CYAN}${SERVER_NAMES[$i]}${NC} (${sid})"
    echo -e "      Start   : ${YELLOW}cd ${sdir} && ./${sid} start${NC}"
    echo -e "      Details : ${YELLOW}cd ${sdir} && ./${sid} details${NC}"
    echo -e "      Console : ${YELLOW}cd ${sdir} && ./${sid} console${NC}  ${DIM}(exit with CTRL+b d)${NC}"
done
echo ""
fi
echo -e "  ${BOLD}Management Panel:${NC}"
echo -e "    URL      : ${CYAN}http://${PUBLIC_IP}:${PANEL_PORT}${NC}"
echo -e "    Password : ${DIM}(the one you entered — it has been bcrypt-hashed in config.env)${NC}"
echo -e "    Restart  : ${YELLOW}sudo systemctl restart arma-panel${NC}"
echo -e "    Logs     : ${YELLOW}sudo journalctl -u arma-panel -f${NC}"
echo ""
echo -e "  ${BOLD}Crash recovery:${NC} each instance has a cron job running"
echo -e "  ${YELLOW}./<id> monitor${NC} every 5 minutes — LGSM's own restart-if-dead check."
echo -e "  View it with: ${YELLOW}sudo -u ${ARMA_USER} crontab -l${NC}"
echo ""
echo -e "  ${BOLD}Add another server later:${NC}"
echo -e "    ${YELLOW}sudo bash install.sh --add-server${NC}"
echo ""
echo -e "  ${BOLD}Update panel in the future:${NC}"
echo -e "    ${YELLOW}git pull && sudo bash install.sh --update${NC}"
echo ""
echo -e "${BOLD}${YELLOW}⚠  Firewall — action required${NC}"
echo -e "  This installer does ${BOLD}not${NC} touch your firewall. Open the following ports"
echo -e "  yourself so players (and you) can reach each server and the panel:"
echo ""
for i in "${!SERVER_IDS[@]}"; do
    port_var="CFG_PORT_${SERVER_IDS[$i]}"
    p="${!port_var:-2001}"
    echo -e "    ${CYAN}sudo ufw allow ${p}/udp${NC}      ${DIM}# ${SERVER_NAMES[$i]} — game port${NC}"
done
if [ ${#SERVER_IDS[@]} -gt 0 ]; then
    echo -e "    ${CYAN}sudo ufw allow 17777/udp${NC}              ${DIM}# A2S server-browser query${NC}"
fi
echo -e "    ${CYAN}sudo ufw allow ${PANEL_PORT}/tcp${NC}        ${DIM}# Panel web UI${NC}"
echo -e "    ${CYAN}sudo ufw reload${NC}"
echo ""
echo -e "  ${DIM}Tip: bind the panel to 127.0.0.1 and SSH-tunnel instead of opening${NC}"
echo -e "  ${DIM}${PANEL_PORT}/tcp publicly — even with the hashed password, HTTP is sniffable.${NC}"
echo ""
