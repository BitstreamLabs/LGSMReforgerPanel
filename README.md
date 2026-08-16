# Arma Reforger Server Management Panel

A lightweight, self-hosted web panel for managing one or more **Arma Reforger
dedicated servers** running under [LinuxGSM](https://linuxgsm.com) on Linux.
The panel drives each server entirely through its own LGSM instance script
(`./<id> start|stop|restart`) — it never spawns or kills the game binary
directly, and it never touches raw SteamCMD.

---

## Features

- **Multi-server** — manage any number of LGSM Arma Reforger instances from
  one panel; switch between them from a dropdown in the header
- **LGSM-native control** — Start/Stop/Restart shell out to each server's own
  `./<instance>` script, so panel-issued and manually-issued commands behave
  identically
- **Crash recovery via LGSM** — the installer sets up a cron job running
  `./<instance> monitor` per server, LGSM's own restart-if-dead check
- **Real-time monitoring** — live CPU and RAM charts, updated every 3 seconds,
  scoped to the selected server's process
- **Live log streaming** — console logs with colour-coded output (errors,
  warnings, network events), tailed from that server's own log directory
- **Mission selector** — 41 built-in missions including all vanilla and RHS —
  Status Quo scenarios, plus auto-discovery from installed mods
- **Mod management** — add and remove Workshop mods directly from the panel,
  per server
- **Config editor** — edit server name, scenario, passwords without touching
  the filesystem
- **PWA support** — installable as a native app on Android and iOS

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 20.04 / 22.04 / 24.04, Debian 11+ (LGSM's supported distros) |
| Architecture | x86_64 |
| RAM | 4 GB minimum per server, 8 GB+ recommended |
| Disk | 20 GB free per server (Arma Reforger server is ~15 GB) |
| Python | 3.10+ (installed automatically) |

---

## How it fits together

Every server the panel manages is an independent [LinuxGSM](https://linuxgsm.com)
instance — a script named after the instance (e.g. `armarserver1`) living in
its own directory, with LGSM's standard layout underneath it:

```
<lgsm_dir>/
├── armarserver1                       # the LGSM instance script itself
├── lgsm/                              # LGSM's own config + data
└── serverfiles/
    ├── armarserver1_config.json       # this instance's Arma config.json
    ├── ArmaReforgerServer             # the game binary (SteamCMD-managed)
    └── profiles/server/
        ├── logs/logs_<ts>/console.log # session logs the panel tails
        ├── addons/                    # downloaded workshop mods
        └── .save/                     # session persistence saves
```

The panel keeps a `servers.json` file listing every instance it knows about
(id, display name, and the paths above). Nothing in that file is guessed at
runtime — `id` doubles as the LGSM script name, so the panel can always shell
out to `<lgsm_dir>/<id> start|stop|restart|monitor` for that server.

---

## Installation

### Option A — Full install (recommended for a fresh VPS)

Installs LinuxGSM, one or more Arma Reforger instances through it, and the
management panel. You'll be asked to add servers in a loop — add as many as
you want to run on this host.

```bash
git clone https://github.com/BitstreamLabs/arma-reforger-panel.git
cd arma-reforger-panel
sudo bash install.sh
```

The installer will ask you for:
- System user (default: `arma`) — owns every LGSM instance and the panel
- Panel web password and port
- Per server: instance id (the LGSM script name), display name, game
  password, admin password, max players, game port

After install, each server lives at `/home/<user>/servers/<instance-id>/`
and the panel is reachable at:
```
http://YOUR_SERVER_IP:8888
```

---

### Option B — Panel only (LGSM instances already exist)

If you already have one or more LGSM Arma Reforger instances running and
only want the web panel:

```bash
git clone https://github.com/BitstreamLabs/arma-reforger-panel.git
cd arma-reforger-panel
sudo bash install.sh --panel-only
```

You'll be asked for each existing instance's id and its LGSM directory (the
one containing `./<id>`).

---

### Option C — Add a server to an existing panel install

```bash
sudo bash install.sh --add-server
```

Either installs a brand-new LGSM instance and registers it, or just
registers an LGSM instance you already set up by hand.

---

### Option D — Update panel files only

After pulling a new version from GitHub:

```bash
git pull
sudo bash install.sh --update
```

This copies updated panel files and restarts the service. `config.env` and
`servers.json` are preserved.

---

## Configuration

`config.env` holds panel-wide settings only:

```env
# Bcrypt hash of your panel admin password. install.sh generates this
# automatically. To set/rotate it manually:
#   pip install bcrypt
#   python3 -c 'import bcrypt,getpass; \
#     print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())'
PANEL_PASSWORD_HASH=

# Port the panel listens on
PANEL_PORT=8888
```

Every server-specific setting lives in `servers.json` instead — either edit
it by hand or use the **Manage Servers** panel in the UI:

```json
[
  {
    "id": "armarserver1",
    "name": "Main Conflict Server",
    "lgsm_dir": "/home/arma/servers/armarserver1",
    "server_config": "/home/arma/servers/armarserver1/serverfiles/armarserver1_config.json",
    "profile_dir": "/home/arma/servers/armarserver1/serverfiles/profiles/server",
    "log_dir": "/home/arma/servers/armarserver1/serverfiles/profiles/server/logs",
    "workshop_dir": "/home/arma/servers/armarserver1/serverfiles/profiles/server/addons"
  }
]
```

`id` must match the LGSM instance script's filename exactly — the panel uses
it both as the process-scoping key and to build `<lgsm_dir>/<id> <command>`.

After editing `config.env`, restart the panel:
```bash
sudo systemctl restart arma-panel
```

---

## Useful Commands

```bash
# ── Panel ──────────────────────────────────────────────────
sudo systemctl status arma-panel      # check panel status
sudo systemctl restart arma-panel     # restart panel
sudo journalctl -u arma-panel -f      # live panel logs

# ── Arma Server (per LGSM instance) ───────────────────────
cd /home/arma/servers/<instance-id>
./<instance-id> start                 # start this server
./<instance-id> stop                  # stop this server
./<instance-id> details               # status, config paths, ports
./<instance-id> console               # attach to the live tmux console
                                       # (detach with CTRL+b d — don't close the pane)
./<instance-id> monitor               # LGSM's crash-restart check (also runs via cron)
./<instance-id> update                # check for and apply game updates

# ── Update ─────────────────────────────────────────────────
git pull && sudo bash install.sh --update
```

Crash recovery is handled by a cron job the installer sets up per server —
`*/5 * * * * <lgsm_dir>/<id> monitor` — rather than a systemd unit. View it
with `sudo -u <user> crontab -l`.

---

## HTTPS / Domain (optional)

To access the panel over HTTPS with a custom domain, use nginx as a reverse
proxy with a Let's Encrypt certificate.

Nginx config example:
```nginx
location / {
    proxy_pass http://127.0.0.1:8888;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_read_timeout 3600;
}
```

If you use **HestiaCP**, add a subdomain through its web interface — it
handles SSL automatically.

---

## Project Structure

```
arma-reforger-panel/
├── app.py               # Flask backend — API, LGSM process control, metrics
├── index.html           # Main panel UI — server switcher + dashboard
├── login.html            # Login screen
├── config.env            # Panel-wide settings (excluded from git)
├── config.env.example     # Config template
├── servers.json          # Registered LGSM instances (excluded from git)
├── install.sh            # LGSM-based installer (full / panel-only / add-server / update)
├── static/
│   ├── manifest.json        # PWA manifest
│   ├── service-worker.js    # PWA service worker
│   ├── icon-192.png         # App icon
│   └── icon-512.png         # App icon (large)
└── README.md
```

---

## RHS — Status Quo

The panel includes mission IDs for all RHS — Status Quo scenarios. They
appear automatically in the mission dropdown once you add the
[RHS mod](https://reforger.armaplatform.com/workshop/595F2BF2F44836FB-RHS-Status-Quo)
to a server.

---

## Contributing

Pull requests and issues are welcome. Open an issue on GitHub if you run
into problems or want to suggest a feature.

---

## License

MIT — free to use, modify and distribute.

---

*Fork maintained by [BitstreamLabs](https://github.com/BitstreamLabs), based
on the original panel by [Mateusz Gołębiewski](https://mateuszgolebiewski.pl).*
