"""
Arma Reforger Server Management Panel — LGSM multi-server edition
https://github.com/BitstreamLabs/arma-reforger-panel

Manages one or more local LinuxGSM (https://linuxgsm.com) Arma Reforger
("armarserver") instances from a single panel. Each instance is described by
a record in servers.json; the panel drives it entirely through its LGSM
instance script (`./<id> start|stop|restart`) rather than spawning or
killing the game binary itself.

Local fork — modifications:
  - Bcrypt-hashed admin password + constant-time verification + rate limiting
  - CSRF protection on state-changing routes
  - Persistent SECRET_KEY (sessions survive panel restart)
  - Bulk mod import via pasted JSON array or uploaded JSON file
  - Auto-discovery of scenarios from installed mods (`.pak` strings scan, mtime-cached)
  - Multi-server support driven by LGSM instance scripts (servers.json)
"""

from flask import Flask, request, jsonify, session, redirect, Response, send_from_directory
import bcrypt
import hmac
import re
import secrets
import subprocess
import os
import json
import threading
import time
import glob

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def load_env(path="config.env"):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip().strip('"').strip("'")
    return env

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_cfg = load_env(os.path.join(_BASE_DIR, "config.env"))

# Backwards-compatible password handling: prefer the bcrypt hash; if only the
# plaintext PANEL_PASSWORD is set (old configs), hash it in-memory at startup.
PANEL_PASSWORD_HASH = _cfg.get("PANEL_PASSWORD_HASH", "").strip()
_LEGACY_PLAINTEXT   = _cfg.get("PANEL_PASSWORD", "").strip()
if not PANEL_PASSWORD_HASH and _LEGACY_PLAINTEXT:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(_LEGACY_PLAINTEXT.encode(), bcrypt.gensalt()).decode()
    print("[panel] WARNING: config.env uses legacy plaintext PANEL_PASSWORD. "
          "Re-run install.sh --update or replace it with PANEL_PASSWORD_HASH=...", flush=True)
if not PANEL_PASSWORD_HASH:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode()
    print("[panel] WARNING: no panel password set. Defaulting to 'changeme'.", flush=True)

PANEL_PORT = int(_cfg.get("PANEL_PORT", 8888))

# Persistent secret key so sessions survive panel restarts.
_SECRET_FILE = os.path.join(_BASE_DIR, ".panel-secret")
def _load_or_create_secret():
    try:
        if os.path.exists(_SECRET_FILE):
            with open(_SECRET_FILE, "rb") as f:
                data = f.read().strip()
                if len(data) >= 32:
                    return data
    except OSError:
        pass
    data = secrets.token_bytes(48)
    try:
        with open(_SECRET_FILE, "wb") as f:
            f.write(data)
        os.chmod(_SECRET_FILE, 0o600)
    except OSError as e:
        print(f"[panel] WARNING: could not persist session secret ({e}); using ephemeral one.", flush=True)
    return data

app = Flask(__name__, static_folder='static')
app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # set True if you put HTTPS in front
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB cap on uploads
)


# ─── SERVERS (servers.json) ───────────────────────────────────────────────────
#
# Each server is an independent LinuxGSM instance living in its own root
# directory (`lgsm_dir`), with an instance script named after its `id`
# (`<lgsm_dir>/<id>`). Under LGSM's default Arma Reforger template:
#   config json   : <lgsm_dir>/serverfiles/<id>_config.json
#   profile dir   : <lgsm_dir>/serverfiles/profiles/server
#   session logs  : <profile_dir>/logs/logs_<ts>/console.log
#   workshop dir  : <profile_dir>/addons
# These are used as defaults when a server is registered, but every path is
# stored explicitly (not re-derived at runtime) so a non-standard layout can
# be edited in servers.json / the Manage Servers UI.

_SERVERS_FILE = os.path.join(_BASE_DIR, "servers.json")
_SERVERS_LOCK = threading.Lock()

_SERVER_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')


def load_servers():
    try:
        with open(_SERVERS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_servers(servers):
    with _SERVERS_LOCK:
        tmp = _SERVERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(servers, f, indent=2)
        os.replace(tmp, _SERVERS_FILE)


def get_server(server_id):
    if not server_id:
        return None
    for s in load_servers():
        if s.get("id") == server_id:
            return s
    return None


def derive_server_paths(lgsm_dir, server_id):
    """LGSM's default Arma Reforger layout for a fresh instance."""
    serverfiles = os.path.join(lgsm_dir, "serverfiles")
    profile_dir = os.path.join(serverfiles, "profiles", "server")
    return {
        "server_config": os.path.join(serverfiles, f"{server_id}_config.json"),
        "profile_dir":   profile_dir,
        "log_dir":       os.path.join(profile_dir, "logs"),
        "workshop_dir":  os.path.join(profile_dir, "addons"),
    }


def _instance_script(server):
    return os.path.join(server["lgsm_dir"], server["id"])


# ─── SECURITY HELPERS ─────────────────────────────────────────────────────────

def _client_ip():
    # Honor X-Forwarded-For only when behind a reverse proxy; otherwise use remote_addr
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip() or "unknown"


_LOGIN_BUCKETS: dict[str, list[float]] = {}
_LOGIN_WINDOW_SEC = 60.0
_LOGIN_MAX_ATTEMPTS = 5

def _login_rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = [t for t in _LOGIN_BUCKETS.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    if len(bucket) >= _LOGIN_MAX_ATTEMPTS:
        _LOGIN_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _LOGIN_BUCKETS[ip] = bucket
    return True


def _verify_password(plain: str) -> bool:
    if not plain:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), PANEL_PASSWORD_HASH.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _ensure_csrf() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def _csrf_required() -> Response | None:
    """Check CSRF token from header or body. Returns an error Response or None."""
    expected = session.get("csrf")
    supplied = (
        request.headers.get("X-CSRF-Token", "")
        or (request.get_json(silent=True) or {}).get("_csrf", "")
        or request.form.get("_csrf", "")
    )
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({"ok": False, "error": "CSRF token invalid"}), 403
    return None


def _require_server():
    """Resolve the server referenced by the request (query string for GET,
    JSON body / form for POST). Returns (server, error_response)."""
    sid = request.args.get("server") or ""
    if not sid:
        body = request.get_json(silent=True) or {}
        sid = body.get("server_id") or request.form.get("server_id") or ""
    server = get_server(sid)
    if not server:
        return None, (jsonify({"ok": False, "error": "Unknown or missing server id"}), 400)
    return server, None


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

# ─── MISSIONS ─────────────────────────────────────────────────────────────────
#
# Hardcoded Bohemia/vanilla scenarios used as a fallback when a server's
# install can't be scanned (e.g. misconfigured paths). When the server install
# IS scannable, dynamic discovery from its addons folder supersedes this list.

AVAILABLE_MISSIONS = [
    # Everon
    {"id": "{ECC61978EDCC2B5A}Missions/23_Campaign.conf",              "name": "Conflict — Everon"},
    {"id": "{C700DB41F0C546E1}Missions/23_Campaign_NorthCentral.conf", "name": "Conflict — Northern Everon"},
    {"id": "{28802845ADA64D52}Missions/23_Campaign_SWCoast.conf",      "name": "Conflict — Southern Everon"},
    {"id": "{94992A3D7CE4FF8A}Missions/23_Campaign_Western.conf",      "name": "Conflict — Western Everon"},
    {"id": "{FDE33AFE2ED7875B}Missions/23_Campaign_Montignac.conf",    "name": "Conflict — Montignac"},
    {"id": "{0220741028718E7F}Missions/23_Campaign_HQC_Everon.conf",   "name": "Conflict: HQ Commander — Everon"},
    {"id": "{59AD59368755F41A}Missions/21_GM_Eden.conf",               "name": "Game Master — Everon"},
    {"id": "{DFAC5FABD11F2390}Missions/26_CombatOpsEveron.conf",       "name": "Combat Ops — Everon"},
    # Capture & Hold
    {"id": "{3F2E005F43DBD2F8}Missions/CAH_Briars_Coast.conf",         "name": "Capture & Hold — Briars Coast"},
    {"id": "{F1A1BEA67132113E}Missions/CAH_Castle.conf",               "name": "Capture & Hold — Montfort Castle"},
    {"id": "{589945FB9FA7B97D}Missions/CAH_Concrete_Plant.conf",       "name": "Capture & Hold — Concrete Plant"},
    {"id": "{9405201CBD22A30C}Missions/CAH_Factory.conf",              "name": "Capture & Hold — Almara Factory"},
    {"id": "{1CD06B409C6FAE56}Missions/CAH_Forest.conf",               "name": "Capture & Hold — Simon's Wood"},
    {"id": "{7C491B1FCC0FF0E1}Missions/CAH_LeMoule.conf",              "name": "Capture & Hold — Le Moule"},
    {"id": "{6EA2E454519E5869}Missions/CAH_Military_Base.conf",        "name": "Capture & Hold — Camp Blake"},
    # Showcase / SP
    {"id": "{C47A1A6245A13B26}Missions/SP01_ReginaV2.conf",            "name": "Elimination"},
    {"id": "{0648CDB32D6B02B3}Missions/SP02_AirSupport.conf",          "name": "Air Support"},
    # Arland
    {"id": "{C41618FD18E9D714}Missions/23_Campaign_Arland.conf",       "name": "Conflict — Arland"},
    {"id": "{68D1240A11492545}Missions/23_Campaign_HQC_Arland.conf",   "name": "Conflict: HQ Commander — Arland"},
    {"id": "{2BBBE828037C6F4B}Missions/22_GM_Arland.conf",             "name": "Game Master — Arland"},
    {"id": "{DAA03C6E6099D50F}Missions/24_CombatOps.conf",             "name": "Combat Ops — Arland"},
    # Kolguyev
    {"id": "{F45C6C15D31252E6}Missions/27_GM_Cain.conf",               "name": "Game Master — Kolguyev"},
    {"id": "{BB5345C22DD2B655}Missions/23_Campaign_HQC_Cain.conf",     "name": "Conflict: HQ Commander — Kolguyev"},
    {"id": "{CB347F2F10065C9C}Missions/CombatOpsCain.conf",            "name": "Combat Ops — Kolguyev"},
    {"id": "{2B4183DF23E88249}Missions/CAH_Morton.conf",               "name": "Capture & Hold — Morton"},
    # Operation Omega
    {"id": "{10B8582BAD9F7040}Missions/Scenario01_Intro.conf",         "name": "Operation Omega 01: Over The Hills And Far Away"},
    {"id": "{1D76AF6DC4DF0577}Missions/Scenario02_Steal.conf",         "name": "Operation Omega 02: Radio Check"},
    {"id": "{D1647575BCEA5A05}Missions/Scenario03_Villa.conf",         "name": "Operation Omega 03: Light In The Dark"},
    {"id": "{6D224A109B973DD8}Missions/Scenario04_Sabotage.conf",      "name": "Operation Omega 04: Red Silence"},
    {"id": "{FA2AB0181129CB16}Missions/Scenario05_Hill.conf",          "name": "Operation Omega 05: Cliffhanger"},
]
# Add a "source" tag so the UI can group by origin.
for _m in AVAILABLE_MISSIONS:
    _m.setdefault("source", "vanilla")


# Friendly display names for scenarios discovered via .rdb (which only gives
# us the filename, not the publisher's display name). Used as an override when
# the .rdb scan finds a known scenario ID. Anything not listed here falls back
# to the cleaned-up filename derived from the path.
_SCENARIO_NAME_OVERRIDES = {
    # RHS — Status Quo
    "{AAD43C10045857C1}Missions/RHS_Conflict.conf":              ("Conflict — Everon (RHS)",                 64),
    "{B694A77592CB69E0}Missions/RHS_ConflictWithoutAIs.conf":    ("Conflict — Everon, no AI (RHS)",          64),
    "{9909DB7ECEA05535}Missions/RHS_Conflict_East.conf":         ("Conflict — Everon East (RHS)",            40),
    "{2F5DD5ACC14120A9}Missions/RHS_Conflict_NorthCentral.conf": ("Conflict — Everon North Central (RHS)",   64),
    "{57B154A20B8B283E}Missions/RHS_Conflict_SWCoast.conf":      ("Conflict — Everon SW Coast (RHS)",        64),
    "{367A7800D147878A}Missions/RHS_Conflict_West.conf":         ("Conflict — Everon West (RHS)",            40),
    "{7577640CD42A00BD}Missions/RHS_Conflict_Arland.conf":       ("Conflict — Arland (RHS)",                 64),
    "{C5EAD55037EB4751}Missions/RHS_CombatOps_MSV.conf":         ("Combat Ops — Arland, MSV vs FIA (RHS)",   16),
    "{D10B11A71A36FCF5}Missions/RHS_CombatOps_USMC_vs_MSV.conf": ("Combat Ops — Arland, USMC vs MSV (RHS)",  16),
    "{68A6FBF43B801FF6}Missions/RHS_ShowcaseBasic.conf":         ("Showcase Mission (RHS)",                   6),
    "{217436B52D34E4BD}Missions/RHS_Showcase_GM.conf":           ("Showcase Mission, Game Master (RHS)",     36),
}


# ─── SCENARIO AUTO-DISCOVERY (workshop meta) ─────────────────────────────────
#
# Reforger workshop mods unpack to <workshop_dir>/<Name>_<HEXID>/. Each addon
# ships a `meta` file (UTF-8-with-BOM JSON) that contains the workshop
# metadata, including a `versions[].scenarios[]` array. Each scenario entry
# is a dict with at least `name` and `gameId` (the full {HEX16}Missions/...
# .conf identifier we need). This is far more reliable than scanning the
# binary .pak file — and the `meta` file is tiny, so the scan is instant.
#
# Results are cached per-server (different instances can have different mods
# installed) by addon dir mtime to avoid re-reading unchanged files.

_SCENARIO_GAME_ID_RE = re.compile(r'^\{[0-9A-Fa-f]{16}\}.+\.conf$')


def _scan_cache_file(server):
    return os.path.join(_BASE_DIR, f".scenario-cache-{server['id']}.json")


def _scan_cache_load(server):
    try:
        with open(_scan_cache_file(server)) as f:
            data = json.load(f)
        return data.get("mods", {}), data.get("mtimes", {})
    except (OSError, json.JSONDecodeError):
        return {}, {}


def _scan_cache_save(server, mods, mtimes):
    try:
        with open(_scan_cache_file(server), "w") as f:
            json.dump({"mods": mods, "mtimes": mtimes, "saved_at": time.time()}, f)
    except OSError as e:
        print(f"[panel] WARNING: could not write scenario cache: {e}", flush=True)


_SCAN_LOCKS: dict[str, threading.Lock] = {}
_SCAN_LOCKS_GUARD = threading.Lock()
_LAST_SCAN_RESULTS: dict[str, dict] = {}


def _scan_lock(server_id):
    with _SCAN_LOCKS_GUARD:
        lock = _SCAN_LOCKS.setdefault(server_id, threading.Lock())
    return lock


def _candidate_addon_roots(server):
    """Locations to scan for addons. Each entry is (path, is_vanilla).
    `is_vanilla=True` means anything found there is Bohemia-shipped game
    content (this instance's bundled addons), not a workshop mod."""
    lgsm_dir     = server.get("lgsm_dir", "")
    workshop_dir = server.get("workshop_dir", "")
    profile_dir  = server.get("profile_dir", "")
    serverfiles  = os.path.join(lgsm_dir, "serverfiles") if lgsm_dir else ""

    roots = []
    if workshop_dir:
        roots.append((workshop_dir, False))
    if profile_dir:
        roots.append((os.path.join(profile_dir, "addons"), False))
    # Bohemia-shipped game content (Conflict, GM, CAH, Operation Omega, etc.)
    if serverfiles:
        roots.extend([
            (os.path.join(serverfiles, "Addons"), True),
            (os.path.join(serverfiles, "addons"), True),
            (serverfiles,                          True),  # falls back to walking the install
        ])
    seen, out = set(), []
    for path, vanilla in roots:
        if path and path not in seen and os.path.isdir(path):
            seen.add(path)
            out.append((path, vanilla))
    return out


def _find_addons(root, max_depth=4):
    """Walk `root` up to `max_depth` levels and yield (addon_dir, meta_or_None,
    rdb_or_None) for every directory that looks like a Reforger addon (i.e.
    contains a `meta` JSON, a `resourceDatabase.rdb`, or an `addon.gproj`)."""
    if not root or not os.path.isdir(root):
        return
    root = os.path.abspath(root)
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        meta_file = os.path.join(dirpath, "meta") if "meta" in filenames else None
        rdb_file = os.path.join(dirpath, "resourceDatabase.rdb") if "resourceDatabase.rdb" in filenames else None
        gproj = "addon.gproj" in filenames
        if meta_file or rdb_file or gproj:
            # Don't descend into addon dirs further (their inner files aren't more addons)
            dirnames[:] = []
            if meta_file or rdb_file:
                yield dirpath, meta_file, rdb_file


def _addon_name_from_gproj(addon_dir):
    """Pull a friendly display name from addon.gproj (TITLE or ID field)."""
    gproj = os.path.join(addon_dir, "addon.gproj")
    if not os.path.isfile(gproj):
        return None
    try:
        with open(gproj, encoding="utf-8", errors="replace") as f:
            text = f.read(2048)
    except OSError:
        return None
    m = re.search(r'TITLE\s+"([^"]+)"', text) or re.search(r'ID\s+"([^"]+)"', text)
    return m.group(1).strip() if m else None


# Case-insensitive: most mods use "Missions/", but at least one confirmed
# real-world mod ("WARFARE - VANILLA") ships its .rdb with lowercase
# "missions/" — Reforger itself is apparently fine with either, since it's
# the engine's own generated resource database either way.
_RDB_PATH_RE = re.compile(rb'Missions/[A-Za-z0-9_./\-]+\.conf', re.IGNORECASE)

def _scenarios_from_rdb(rdb_path, source_label):
    """Fallback: parse `resourceDatabase.rdb` for scenario records.

    The dedicated-server workshop downloader strips `meta.versions[].scenarios`
    on Linux (just an empty list), so we can't rely on the JSON for those.
    The .rdb file ships next to data.pak in every addon and contains the
    asset directory in a simple length-prefixed binary format. Each scenario
    asset record looks like:
        <4-byte LE length>  <path bytes>  <\\0>  <6-byte padding>  <8-byte LE GUID>  …
    where the LE length equals len(path) + 1 (counting the null terminator).
    The 8-byte GUID is little-endian, so we reverse it for the {HEX16} display.

    We rely on the path-prefix `Missions/` to filter for scenarios, then
    validate each candidate by checking the length prefix matches; this
    rejects stray substring hits in unrelated records.
    """
    try:
        with open(rdb_path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    out = []
    seen = set()
    for m in _RDB_PATH_RE.finditer(data):
        ps, pe = m.start(), m.end()
        if ps < 4:
            continue
        path_len_field = int.from_bytes(data[ps - 4:ps], "little")
        if path_len_field != (pe - ps) + 1:
            continue  # not a length-prefixed record — likely a substring inside something else
        if pe >= len(data) or data[pe] != 0:
            continue
        guid_start = pe + 7  # 1 null byte + 6-byte padding
        if guid_start + 8 > len(data):
            continue
        guid_bytes = data[guid_start:guid_start + 8]
        # Reject obviously-bogus GUIDs (all-zero / all-0xFF fillers).
        if guid_bytes == b"\x00" * 8 or guid_bytes == b"\xff" * 8:
            continue
        guid_hex = guid_bytes[::-1].hex().upper()  # little-endian → big-endian display
        path_str = m.group(0).decode("ascii", errors="replace")
        sid = "{" + guid_hex + "}" + path_str
        if sid in seen:
            continue
        seen.add(sid)
        out.append({
            "id": sid,
            "name": path_str.split("/")[-1].replace(".conf", ""),
            "description": "",
            "player_count": None,
            "source": source_label or "mod",
        })
    return out


def _scenarios_from_meta(meta_path):
    """Parse a workshop `meta` file and return a list of scenario dicts:
       [{id, name, description, player_count, source}, ...]
       The `meta` file is UTF-8 with BOM and contains the workshop publisher
       metadata. Scenarios appear under meta.versions[].scenarios[].
    """
    try:
        with open(meta_path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return [], None

    m = (data.get("meta") or {})
    mod_name = (m.get("name") or "").strip()

    # Pull scenarios from the latest version (versions[0]) — that's what's installed.
    versions = m.get("versions") or []
    raw_scenarios = []
    if versions and isinstance(versions, list):
        raw_scenarios = versions[0].get("scenarios") or []
    if not raw_scenarios:
        # Some older meta layouts have a top-level scenarios array.
        raw_scenarios = m.get("scenarios") or []
    if not isinstance(raw_scenarios, list):
        return [], mod_name

    out = []
    for s in raw_scenarios:
        if not isinstance(s, dict):
            continue
        sid = (s.get("gameId") or "").strip()
        if not sid or not _SCENARIO_GAME_ID_RE.match(sid):
            continue
        out.append({
            "id":           sid,
            "name":         (s.get("name") or sid.split("/")[-1].replace(".conf", "")).strip(),
            "description":  (s.get("description") or "").strip()[:300],
            "player_count": s.get("playerCount") if isinstance(s.get("playerCount"), int) else None,
            "source":       mod_name or "mod",
        })
    return out, mod_name


def _apply_name_override(scenario):
    """If we have a curated friendly name for this scenario ID, use it."""
    override = _SCENARIO_NAME_OVERRIDES.get(scenario["id"])
    if override:
        scenario["name"] = override[0]
        if override[1] and not scenario.get("player_count"):
            scenario["player_count"] = override[1]
    return scenario


def _discover_locked(server, force_rescan):
    """Actual scan work. Caller must hold the per-server scan lock."""
    diag = {"candidates_tried": [], "addons_scanned": 0,
            "mods_with_scenarios": 0, "scenarios_total": 0, "errors": []}

    cache_mods, cache_mtimes = ({}, {}) if force_rescan else _scan_cache_load(server)
    fresh_mods, fresh_mtimes = {}, {}

    seen_addon_dirs = set()
    addons_scanned = 0

    for root, is_vanilla in _candidate_addon_roots(server):
        diag["candidates_tried"].append({"path": root, "vanilla": is_vanilla})
        for addon_dir, meta_path, rdb_path in _find_addons(root):
            real_dir = os.path.realpath(addon_dir)
            if real_dir in seen_addon_dirs:
                continue
            seen_addon_dirs.add(real_dir)
            addons_scanned += 1

            # Cache key tracks both files so we re-scan if either changes.
            cache_key = real_dir
            try:
                meta_mtime = os.path.getmtime(meta_path) if meta_path else 0
                rdb_mtime  = os.path.getmtime(rdb_path) if rdb_path else 0
                mtime = max(meta_mtime, rdb_mtime)
            except OSError as e:
                diag["errors"].append(f"{cache_key}: stat failed ({e})")
                continue

            if cache_mtimes.get(cache_key) == mtime and cache_key in cache_mods:
                fresh_mods[cache_key] = cache_mods[cache_key]
                fresh_mtimes[cache_key] = mtime
                continue

            scenarios = []
            mod_name = None
            # 1. Try the workshop meta JSON first (gives us the publisher's
            #    display names + player counts when populated).
            if meta_path:
                scenarios, mod_name = _scenarios_from_meta(meta_path)
            # 2. Fall back to the .rdb scan when the meta has no scenarios
            #    (Linux dedi strips them) or when there's no meta at all
            #    (Bohemia's bundled vanilla addons).
            if not scenarios and rdb_path:
                if not mod_name:
                    mod_name = _addon_name_from_gproj(addon_dir) or os.path.basename(addon_dir)
                source = "vanilla" if is_vanilla else mod_name
                scenarios = _scenarios_from_rdb(rdb_path, source)
            # 3. Force-tag everything found in the server install dir as vanilla.
            if is_vanilla:
                for s in scenarios:
                    s["source"] = "vanilla"
            # 4. Single-scenario mods are usually named after their scenario.
            #    The .rdb fallback only knows the filename (e.g.
            #    "MontfordFortress"), but the workshop name is the friendly
            #    one ("Fortress"). When a mod publishes exactly one scenario
            #    and we have an addon display name, prefer that — unless an
            #    explicit override is already in place.
            if len(scenarios) == 1 and not is_vanilla and mod_name:
                if scenarios[0]["id"] not in _SCENARIO_NAME_OVERRIDES:
                    scenarios[0]["name"] = mod_name
            # 5. Apply our curated friendly-name overrides (mainly RHS).
            for s in scenarios:
                _apply_name_override(s)

            if scenarios:
                fresh_mods[cache_key] = scenarios
            fresh_mtimes[cache_key] = mtime

    _scan_cache_save(server, fresh_mods, fresh_mtimes)

    flat = []
    for sids in fresh_mods.values():
        flat.extend(sids)
    diag["addons_scanned"] = addons_scanned
    diag["mods_with_scenarios"] = len(fresh_mods)
    diag["scenarios_total"] = len(flat)
    # Back-compat fields the old UI knew about
    diag["workshop_dir"] = "; ".join(p for p, _ in _candidate_addon_roots(server)) or None
    diag["metas_found"]  = addons_scanned
    return flat, diag


def discover_mod_scenarios(server, force_rescan=False):
    """Return (scenarios, diag).
       Lock-protected per-server so concurrent /api/status polls or rescan
       clicks can't launch overlapping scans for the same instance. Non-rescan
       callers get the cached result without doing any disk I/O if a scan is
       already in progress."""
    if not force_rescan:
        # Cheap path: just read the on-disk cache.
        cache_mods, _mtimes = _scan_cache_load(server)
        if cache_mods:
            flat = []
            for sids in cache_mods.values():
                flat.extend(sids)
            diag = {"workshop_dir": None, "paks_found": len(cache_mods),
                    "scenarios_total": len(flat), "from_cache": True}
            return flat, diag

    lock = _scan_lock(server["id"])
    if not lock.acquire(blocking=force_rescan):
        # Scan in progress and we don't want to block — return whatever we have.
        last = _LAST_SCAN_RESULTS.get(server["id"], {"scenarios": [], "diag": None})
        return last["scenarios"], (last["diag"] or {"busy": True})
    try:
        scenarios, diag = _discover_locked(server, force_rescan)
        _LAST_SCAN_RESULTS[server["id"]] = {"scenarios": scenarios, "diag": diag, "ts": time.time()}
        return scenarios, diag
    finally:
        lock.release()


def cached_scenarios(server):
    """Cheap read for /api/status — never triggers a fresh scan."""
    cache_mods, _mtimes = _scan_cache_load(server)
    flat = []
    for sids in cache_mods.values():
        flat.extend(sids)
    return flat


def all_scenarios(server, force_rescan=False):
    """Vanilla list + auto-discovered, deduped by id (vanilla wins for naming).
       Returns (list, diag)."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    discovered, diag = discover_mod_scenarios(server, force_rescan=force_rescan)
    for s in discovered:
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out, diag


def all_scenarios_cached(server):
    """Like all_scenarios() but never scans — used by /api/status hot path."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    for s in cached_scenarios(server):
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out


# ─── LGSM PROCESS CONTROL ─────────────────────────────────────────────────────

def lgsm_run(server, command, timeout):
    """Run `./<id> <command>` inside the instance's LGSM directory. Returns
    (ok, stdout, stderr). LGSM instance scripts background the game process
    themselves (tmux) and return once that's done, so these calls are
    synchronous and bounded by `timeout`."""
    script = _instance_script(server)
    if not os.path.isfile(script) or not os.access(script, os.X_OK):
        return False, "", f"Instance script not found or not executable: {script}"
    try:
        r = subprocess.run([script, command], cwd=server["lgsm_dir"],
                            capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"'{command}' timed out after {timeout}s"
    except OSError as e:
        return False, "", str(e)


def _lgsm_tmux_socket(server):
    """LGSM never uses the default tmux socket — every instance gets its own,
    named "<id>-<uid>" where <uid> is a short hash LGSM generates once (on
    that instance's first-ever start) and stores in lgsm/data/<id>.uid. Every
    LGSM command (start/stop/console/check_status) targets that exact socket:
        tmux -L "<id>-<uid>" ...
    Returns the socket name, or None if the instance has never been started
    (no .uid file yet — nothing to check)."""
    uid_path = os.path.join(server["lgsm_dir"], "lgsm", "data", f"{server['id']}.uid")
    try:
        with open(uid_path) as f:
            uid = f.read().strip()
    except OSError:
        return None
    return f"{server['id']}-{uid}" if uid else None

def _tmux_pane_pids(server):
    """PIDs of the panes in LGSM's tmux session for this instance, on LGSM's
    own per-instance socket — the same session check_status.sh/console use —
    or None if the session doesn't exist (or was never started)."""
    socket = _lgsm_tmux_socket(server)
    if not socket:
        return None
    session = server["id"]
    try:
        r = subprocess.run(["tmux", "-L", socket, "has-session", "-t", session],
                            capture_output=True, text=True)
        if r.returncode != 0:
            return None
        r = subprocess.run(["tmux", "-L", socket, "list-panes", "-t", session, "-F", "#{pane_pid}"],
                            capture_output=True, text=True)
        return [int(p) for p in r.stdout.split() if p.isdigit()]
    except Exception:
        return None

def _proc_matches(pid, needle):
    try:
        with open(f"/proc/{pid}/comm") as f:
            if needle in f.read().strip().lower():
                return True
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            if needle in f.read().decode(errors="ignore").lower():
                return True
    except Exception:
        pass
    return False

def _proc_children(pid):
    """Direct child PIDs of `pid`, via the kernel-provided children list —
    O(this process's own children), not a scan of every process on the host."""
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            return [int(p) for p in f.read().split()]
    except Exception:
        return []

def _find_descendant_by_name(root_pid, name_substr):
    """root_pid or any of its descendants whose comm/cmdline contains
    name_substr (case-insensitive). LGSM commonly execs the game binary in
    place of the pane's shell, so root_pid itself is usually the match —
    checked first, cheaply, before ever walking descendants. Only walks
    root_pid's own process tree (via /proc/<pid>/task/<pid>/children), never
    the whole host's process table."""
    needle = name_substr.lower()
    queue = [root_pid]
    seen = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        if _proc_matches(pid, needle):
            return pid
        queue.extend(_proc_children(pid))
    return None

def get_server_pid(server):
    """Whether LGSM considers this instance running is authoritative via its
    own tmux session, reached on LGSM's own per-instance socket (see
    _lgsm_tmux_socket) — the same thing `./<id> console`, `./<id> details`
    and check_status.sh use. Matching purely by the binary's absolute path
    via pgrep (the old approach) silently found nothing whenever LGSM
    launched it with a relative path or different cwd, reporting OFFLINE
    despite the server being fully up and joinable. We now resolve the
    actual PID by walking the tmux pane's process tree, falling back to the
    old pgrep sweep only if no LGSM tmux socket/session is found at all."""
    pane_pids = _tmux_pane_pids(server)
    if pane_pids is not None:
        for pane_pid in pane_pids:
            found = _find_descendant_by_name(pane_pid, "ArmaReforgerServer")
            if found:
                return found
        # Session exists (LGSM thinks it's running) but the binary isn't
        # up under it yet — mid-start, not a case to fall through on.
        return None
    binary_path = os.path.join(server["lgsm_dir"], "serverfiles", "ArmaReforgerServer")
    try:
        r = subprocess.run(["pgrep", "-f", binary_path], capture_output=True, text=True)
        pids = r.stdout.strip().splitlines()
        return int(pids[0]) if pids else None
    except Exception:
        return None

def get_process_uptime(pid):
    try:
        r = subprocess.run(["ps", "-o", "etimes=", "-p", str(pid)], capture_output=True, text=True)
        return int(r.stdout.strip())
    except Exception:
        return 0

def format_uptime(seconds):
    if seconds < 60:    return f"{seconds}s"
    if seconds < 3600:  return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

def get_cpu_count():
    try:
        r = subprocess.run(["nproc"], capture_output=True, text=True)
        return max(1, int(r.stdout.strip()))
    except Exception:
        return 1

def get_cpu_ram(pid):
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "pcpu=,rss="], capture_output=True, text=True)
        parts = r.stdout.strip().split()
        cpu = round(float(parts[0]) / get_cpu_count(), 1)
        ram = round(int(parts[1]) / 1024, 1)
        return cpu, ram
    except Exception:
        return 0.0, 0.0

def get_system_ram():
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem = {l.split()[0].rstrip(":"): int(l.split()[1]) for l in lines if len(l.split()) >= 2}
        total = round(mem["MemTotal"] / 1024, 1)
        used  = round((mem["MemTotal"] - mem["MemAvailable"]) / 1024, 1)
        return used, total
    except Exception:
        return 0, 0

def get_latest_log(server):
    try:
        dirs = sorted(glob.glob(f"{server['log_dir']}/logs_*"), reverse=True)
        if not dirs:
            return None
        path = os.path.join(dirs[0], "console.log")
        return path if os.path.exists(path) else None
    except Exception:
        return None

def read_config(server):
    try:
        with open(server["server_config"]) as f:
            return json.load(f)
    except Exception:
        return {}

def write_config(server, cfg):
    with open(server["server_config"], "w") as f:
        json.dump(cfg, f, indent="\t")

# ─── PERSISTENCE ─────────────────────────────────────────────────────────────
#
# Reforger session save/load. The toggle is the presence of a top-level
# `persistence` block in config.json (autosave); `-loadSessionSave` is always
# passed at launch by LGSM so any existing save loads on start. Save files
# live under <profile_dir>/.save/ (Conflict / Combat Ops layout). Subdirs
# underneath: game/ (world/session), playersave/ (per-player), settings/.

_SAVE_SUBDIRS = (".save", "save", "saves")

def _get_persistence_block(cfg):
    """Read the persistence block at its real schema location:
    `game.gameProperties.persistence`. Returns the block dict or None."""
    gp = (cfg.get("game") or {}).get("gameProperties") or {}
    block = gp.get("persistence")
    return block if isinstance(block, dict) else None

def _set_persistence_block(cfg, block):
    """Write `block` (a dict) at game.gameProperties.persistence, or remove it
    if `block` is None. Also pops any legacy top-level `persistence` key — the
    1.6 server schema rejects it, so its presence is always a bug."""
    cfg.pop("persistence", None)
    gp = cfg.setdefault("game", {}).setdefault("gameProperties", {})
    if block is None:
        gp.pop("persistence", None)
    else:
        gp["persistence"] = block

def _persistence_enabled(server, cfg=None):
    if cfg is None:
        cfg = read_config(server)
    return _get_persistence_block(cfg) is not None

# Subdirs the flush button targets. `settings/` is intentionally preserved
# because it holds non-session config the server expects to regenerate from.
_FLUSHABLE_SUBDIRS = ("game", "playersave")

def _save_root(server):
    profile_dir = server.get("profile_dir", "")
    for sub in _SAVE_SUBDIRS:
        p = os.path.join(profile_dir, sub)
        if os.path.isdir(p):
            return p
    return os.path.join(profile_dir, ".save")  # canonical Linux dedicated path

def _scan_dir(path):
    """Return {count, bytes, newest} for files under `path`, or zeros if absent."""
    if not os.path.isdir(path):
        return {"count": 0, "bytes": 0, "newest": None}
    count = 0
    total = 0
    newest = 0.0
    for dirpath, _dirs, files in os.walk(path):
        for fn in files:
            try:
                st = os.stat(os.path.join(dirpath, fn))
            except OSError:
                continue
            count += 1
            total += st.st_size
            if st.st_mtime > newest:
                newest = st.st_mtime
    return {"count": count, "bytes": total, "newest": newest or None}

def _scan_saves(server):
    root = _save_root(server)
    if not os.path.isdir(root):
        return {"path": root, "exists": False, "total": {"count": 0, "bytes": 0, "newest": None}, "buckets": {}}
    buckets = {name: _scan_dir(os.path.join(root, name)) for name in ("game", "playersave", "settings")}
    total_count = sum(b["count"] for b in buckets.values())
    total_bytes = sum(b["bytes"] for b in buckets.values())
    newest_vals = [b["newest"] for b in buckets.values() if b["newest"]]
    return {
        "path":    root,
        "exists":  True,
        "buckets": buckets,
        "total":   {
            "count":  total_count,
            "bytes":  total_bytes,
            "newest": max(newest_vals) if newest_vals else None,
        },
    }

# _scan_saves() walks every save file on disk (os.walk + os.stat per file),
# which gets slow with a large/active session — and it's requested on every
# server switch. Cache briefly per server so rapid switches/polls don't each
# re-walk the whole tree; the flush endpoint always calls _scan_saves directly
# to get a fresh count after deleting files.
_SAVE_SCAN_CACHE: dict[str, tuple[float, dict]] = {}
_SAVE_SCAN_TTL = 5.0

def _scan_saves_cached(server):
    now = time.time()
    cached = _SAVE_SCAN_CACHE.get(server["id"])
    if cached and now - cached[0] < _SAVE_SCAN_TTL:
        return cached[1]
    result = _scan_saves(server)
    _SAVE_SCAN_CACHE[server["id"]] = (now, result)
    return result

def _flush_saves(server):
    """Remove the contents of `.save/game/` and `.save/playersave/` (world
    session + per-player data). `.save/settings/` is left alone — it holds
    non-session config the server regenerates from. Returns the count of files
    deleted."""
    import shutil
    root = _save_root(server)
    if not os.path.isdir(root):
        return 0
    removed = 0
    for sub in _FLUSHABLE_SUBDIRS:
        bucket = os.path.join(root, sub)
        if not os.path.isdir(bucket):
            continue
        for name in os.listdir(bucket):
            full = os.path.join(bucket, name)
            try:
                if os.path.isdir(full) and not os.path.islink(full):
                    for _dp, _dn, files in os.walk(full):
                        removed += len(files)
                    shutil.rmtree(full)
                else:
                    os.remove(full)
                    removed += 1
            except OSError:
                pass
    return removed


def get_map_name(server, cfg=None):
    try:
        if cfg is None:
            cfg = read_config(server)
        sid = cfg.get("game", {}).get("scenarioId", "")
        if not sid:
            return "Unknown"
        # Consult the full merged list (vanilla + discovered, with overrides
        # already applied) so the dashboard tile matches the dropdown.
        for m in all_scenarios_cached(server):
            if m["id"] == sid:
                return m["name"]
        return sid.split("/")[-1].replace(".conf", "")
    except Exception:
        return "Unknown"

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/manifest.json")
def manifest():
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    _ensure_csrf()
    return open(os.path.join(os.path.dirname(__file__), "index.html")).read()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        if not _login_rate_ok(ip):
            return jsonify({"ok": False, "error": "Too many attempts. Wait a minute."}), 429
        data = request.get_json(silent=True) or {}
        # bcrypt is intentionally slow — even on a successful login it adds ~100ms,
        # which is also a natural defense against brute force.
        if _verify_password(data.get("password", "")):
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["login_at"] = int(time.time())
            _ensure_csrf()
            return jsonify({"ok": True, "csrf": session["csrf"]})
        return jsonify({"ok": False, "error": "Invalid password"}), 401
    return open(os.path.join(os.path.dirname(__file__), "login.html")).read()

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/csrf")
def api_csrf():
    """Front-end fetches a CSRF token after login and on tab refresh."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"csrf": _ensure_csrf()})


# ─── SERVER REGISTRY ROUTES ───────────────────────────────────────────────────

@app.route("/api/servers")
def api_servers():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    out = []
    for s in load_servers():
        pid = get_server_pid(s)
        out.append({
            "id": s["id"],
            "name": s.get("name") or s["id"],
            "running": pid is not None,
            "lgsm_dir":      s.get("lgsm_dir", ""),
            "server_config": s.get("server_config", ""),
            "profile_dir":   s.get("profile_dir", ""),
            "log_dir":       s.get("log_dir", ""),
            "workshop_dir":  s.get("workshop_dir", ""),
        })
    return jsonify({"servers": out, "csrf": _ensure_csrf()})


@app.route("/api/servers/add", methods=["POST"])
def api_servers_add():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}

    sid = str(data.get("id", "")).strip()
    name = str(data.get("name", "")).strip()
    lgsm_dir = str(data.get("lgsm_dir", "")).strip().rstrip("/")

    if not _SERVER_ID_RE.match(sid):
        return jsonify({"ok": False, "error": "id must be 1-32 chars of letters, digits, - or _ (this must match the LGSM instance script name)"})
    if not name:
        return jsonify({"ok": False, "error": "name is required"})
    if not lgsm_dir or not os.path.isdir(lgsm_dir):
        return jsonify({"ok": False, "error": f"lgsm_dir does not exist: {lgsm_dir}"})

    script = os.path.join(lgsm_dir, sid)
    if not os.path.isfile(script):
        return jsonify({"ok": False, "error": f"No LGSM instance script found at {script}. Install it first with: bash linuxgsm.sh {sid}"})
    if not os.access(script, os.X_OK):
        return jsonify({"ok": False, "error": f"{script} exists but is not executable"})

    servers = load_servers()
    if any(s["id"] == sid for s in servers):
        return jsonify({"ok": False, "error": f"A server with id '{sid}' is already registered"})

    defaults = derive_server_paths(lgsm_dir, sid)
    entry = {
        "id": sid,
        "name": name,
        "lgsm_dir": lgsm_dir,
        "server_config": str(data.get("server_config") or defaults["server_config"]).strip(),
        "profile_dir":   str(data.get("profile_dir")   or defaults["profile_dir"]).strip(),
        "log_dir":       str(data.get("log_dir")       or defaults["log_dir"]).strip(),
        "workshop_dir":  str(data.get("workshop_dir")  or defaults["workshop_dir"]).strip(),
    }
    servers.append(entry)
    save_servers(servers)
    return jsonify({"ok": True, "server": entry})


@app.route("/api/servers/update", methods=["POST"])
def api_servers_update():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    sid = str(data.get("id", "")).strip()

    servers = load_servers()
    idx = next((i for i, s in enumerate(servers) if s["id"] == sid), None)
    if idx is None:
        return jsonify({"ok": False, "error": "Unknown server id"})

    entry = servers[idx]
    for field in ("name", "lgsm_dir", "server_config", "profile_dir", "log_dir", "workshop_dir"):
        if field in data and str(data[field]).strip():
            entry[field] = str(data[field]).strip().rstrip("/") if field == "lgsm_dir" else str(data[field]).strip()

    script = os.path.join(entry["lgsm_dir"], entry["id"])
    if not os.path.isfile(script):
        return jsonify({"ok": False, "error": f"No LGSM instance script found at {script}"})

    servers[idx] = entry
    save_servers(servers)
    return jsonify({"ok": True, "server": entry})


@app.route("/api/servers/remove", methods=["POST"])
def api_servers_remove():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    sid = str(data.get("id", "")).strip()

    servers = load_servers()
    new = [s for s in servers if s["id"] != sid]
    if len(new) == len(servers):
        return jsonify({"ok": False, "error": "Unknown server id"})
    save_servers(new)
    return jsonify({"ok": True})


# ─── PER-SERVER ROUTES ─────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    server, err = _require_server()
    if err: return err
    pid = get_server_pid(server)
    cfg = read_config(server)
    cpu, ram = get_cpu_ram(pid) if pid else (0.0, 0.0)
    ram_used, ram_total = get_system_ram()
    missions = all_scenarios_cached(server)
    return jsonify({
        "running":        pid is not None,
        "pid":            pid,
        "map":            get_map_name(server, cfg),
        "players":        0,
        "uptime":         format_uptime(get_process_uptime(pid)) if pid else "—",
        "uptime_sec":     get_process_uptime(pid) if pid else 0,
        "server_name":    cfg.get("game", {}).get("name", "—"),
        "ip":             cfg.get("publicAddress", "—"),
        "port":           cfg.get("publicPort", "—"),
        "scenario_id":    cfg.get("game", {}).get("scenarioId", ""),
        "missions":       missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "password":       cfg.get("game", {}).get("password", ""),
        "password_admin": cfg.get("game", {}).get("passwordAdmin", ""),
        "cpu":            cpu,
        "ram_process":    ram,
        "ram_used":       ram_used,
        "ram_total":      ram_total,
        "mods":           cfg.get("game", {}).get("mods", []),
        "csrf":           _ensure_csrf(),
    })

@app.route("/api/scenarios/rescan", methods=["POST"])
def api_scenarios_rescan():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    missions, diag = all_scenarios(server, force_rescan=True)
    return jsonify({
        "ok": True,
        "missions": missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "diag": diag,
    })

@app.route("/api/metrics")
def api_metrics():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    server, err = _require_server()
    if err: return err
    pid = get_server_pid(server)
    cpu, ram = get_cpu_ram(pid) if pid else (0.0, 0.0)
    ram_used, ram_total = get_system_ram()
    return jsonify({
        "cpu": cpu, "ram_process": ram,
        "ram_used": ram_used, "ram_total": ram_total,
        "running": pid is not None, "ts": int(time.time()),
    })

@app.route("/api/logs")
def api_logs():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    server, err = _require_server()
    if err: return err
    n = int(request.args.get("lines", 100))
    path = get_latest_log(server)
    if not path:
        return jsonify({"lines": [], "path": None})
    try:
        r = subprocess.run(["tail", "-n", str(n), path], capture_output=True, text=True)
        return jsonify({"lines": r.stdout.splitlines(), "path": path})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

def _normalize_mod_entry(entry):
    """Validate one mod row. Returns canonical dict or None."""
    if not isinstance(entry, dict):
        return None
    mod_id = str(entry.get("modId", "")).strip()
    if not mod_id or len(mod_id) > 32:
        return None
    if not all(c in "0123456789ABCDEFabcdef" for c in mod_id):
        return None
    out = {"modId": mod_id.upper()}
    name = str(entry.get("name", "")).strip()
    if name:
        if len(name) > 200 or any(c in name for c in "\n\r"):
            return None
        out["name"] = name
    version = str(entry.get("version", "")).strip()
    if version:
        if len(version) > 32 or any(c in version for c in '\n\r"\\'):
            return None
        out["version"] = version
    return out


@app.route("/api/config", methods=["POST"])
def api_config():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    data = request.get_json(silent=True) or {}
    cfg  = read_config(server)
    changed = False
    if "server_name" in data and data["server_name"].strip():
        cfg.setdefault("game", {})["name"] = data["server_name"].strip(); changed = True
    if "scenario_id" in data:
        sid = data["scenario_id"].strip()
        valid_ids = {m["id"] for m in all_scenarios_cached(server)}
        if sid not in valid_ids:
            return jsonify({"ok": False, "error": "Unknown scenario"})
        cfg.setdefault("game", {})["scenarioId"] = sid; changed = True
    if "password" in data:
        cfg.setdefault("game", {})["password"] = data["password"]; changed = True
    if "password_admin" in data and data["password_admin"].strip():
        cfg.setdefault("game", {})["passwordAdmin"] = data["password_admin"].strip(); changed = True
    if not changed:
        return jsonify({"ok": False, "error": "No changes"})
    try:
        write_config(server, cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid(server) is not None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# Full config.json editor. The structured /api/config fields above cover the
# common cases; this lets admins reach everything else (mission rotation,
# admin lists, gameProperties, VON, etc.) without SSH access.
_RAW_CONFIG_MAX_BYTES = 500_000

@app.route("/api/config/raw", methods=["GET"])
def api_config_raw_get():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    server, err = _require_server()
    if err: return err
    cfg = read_config(server)
    return jsonify({"ok": True, "raw": json.dumps(cfg, indent="\t")})

@app.route("/api/config/raw", methods=["POST"])
def api_config_raw_set():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err

    body = request.get_json(silent=True) or {}
    raw = body.get("raw")
    if not isinstance(raw, str) or not raw.strip():
        return jsonify({"ok": False, "error": "Empty config"}), 400
    if len(raw.encode("utf-8")) > _RAW_CONFIG_MAX_BYTES:
        return jsonify({"ok": False, "error": f"Config exceeds {_RAW_CONFIG_MAX_BYTES // 1000} KB limit"}), 400

    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({"ok": False, "error": f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}"}), 400
    if not isinstance(cfg, dict):
        return jsonify({"ok": False, "error": "Top-level value must be a JSON object"}), 400

    try:
        write_config(server, cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid(server) is not None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/persistence", methods=["GET"])
def api_persistence_get():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    server, err = _require_server()
    if err: return err
    cfg = read_config(server)
    block = _get_persistence_block(cfg) or {}
    saves = _scan_saves_cached(server)
    return jsonify({
        "enabled":          _persistence_enabled(server, cfg),
        "autoSaveInterval": block.get("autoSaveInterval", 10),
        "hiveId":           block.get("hiveId", 1),
        "saves":            saves,
        "profile_dir":      server.get("profile_dir"),
    })

@app.route("/api/persistence", methods=["POST"])
def api_persistence_set():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    data = request.get_json(silent=True) or {}
    cfg  = read_config(server)
    enabled = bool(data.get("enabled"))
    if enabled:
        block = _get_persistence_block(cfg) or {}
        if "autoSaveInterval" in data:
            try:
                v = int(data["autoSaveInterval"])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "autoSaveInterval must be an integer"})
            if not 0 <= v <= 60:
                return jsonify({"ok": False, "error": "autoSaveInterval must be between 0 and 60"})
            block["autoSaveInterval"] = v
        else:
            block.setdefault("autoSaveInterval", 10)
        if "hiveId" in data:
            try:
                v = int(data["hiveId"])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "hiveId must be an integer"})
            if not 0 <= v <= 16383:
                return jsonify({"ok": False, "error": "hiveId must be between 0 and 16383"})
            block["hiveId"] = v
        else:
            block.setdefault("hiveId", 1)
        _set_persistence_block(cfg, block)
    else:
        _set_persistence_block(cfg, None)
    try:
        write_config(server, cfg)
        return jsonify({
            "ok": True,
            "restart_required": get_server_pid(server) is not None,
            "enabled":           _persistence_enabled(server, cfg),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/persistence/flush", methods=["POST"])
def api_persistence_flush():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    # Refuse to delete saves while the server is running — the game holds file
    # handles and may rewrite them mid-flush, which leaves us with partials.
    if get_server_pid(server):
        return jsonify({"ok": False, "error": "Stop the server before flushing saves"})
    try:
        removed = _flush_saves(server)
        fresh = _scan_saves(server)
        _SAVE_SCAN_CACHE[server["id"]] = (time.time(), fresh)
        return jsonify({"ok": True, "removed": removed, "saves": fresh})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mods/add", methods=["POST"])
def api_mods_add():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    data = request.get_json(silent=True) or {}
    norm = _normalize_mod_entry({"modId": data.get("modId",""), "name": data.get("name",""), "version": data.get("version","")})
    if not norm:
        return jsonify({"ok": False, "error": "Invalid mod entry (modId must be 1-32 hex chars)"})
    if "name" not in norm:
        return jsonify({"ok": False, "error": "name is required for manual entry"})
    cfg  = read_config(server)
    mods = cfg.setdefault("game", {}).setdefault("mods", [])
    if any(m.get("modId", "").upper() == norm["modId"] for m in mods):
        return jsonify({"ok": False, "error": "Mod with this ID already exists"})
    mods.append(norm)
    try:
        write_config(server, cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid(server) is not None, "mods": mods})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mods/import", methods=["POST"])
def api_mods_import():
    """Bulk-import mods. Accepts either:
       - multipart/form-data with a 'file' part containing a JSON array, plus
         form fields 'mode' (replace|merge), 'server_id' and '_csrf'.
       - application/json with {payload: <text or array>, mode, server_id, _csrf}.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err

    raw = None
    mode = "replace"

    if request.files and "file" in request.files:
        f = request.files["file"]
        try:
            raw = f.read().decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"ok": False, "error": "File must be UTF-8 encoded JSON"}), 400
        mode = (request.form.get("mode") or "replace").strip().lower()
    else:
        body = request.get_json(silent=True) or {}
        payload = body.get("payload")
        if isinstance(payload, list):
            raw = json.dumps(payload)
        elif isinstance(payload, str):
            raw = payload
        mode = (body.get("mode") or "replace").strip().lower()

    if mode not in ("replace", "merge"):
        return jsonify({"ok": False, "error": "mode must be 'replace' or 'merge'"}), 400
    if not raw or not raw.strip():
        return jsonify({"ok": False, "error": "Empty payload"}), 400

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({"ok": False, "error": f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}"}), 400
    if not isinstance(data, list):
        return jsonify({"ok": False, "error": "Top-level value must be a JSON array"}), 400

    valid = []
    skipped = []
    seen = set()
    for i, entry in enumerate(data):
        norm = _normalize_mod_entry(entry)
        if not norm:
            skipped.append(f"#{i + 1}: invalid")
            continue
        if norm["modId"] in seen:
            skipped.append(f"#{i + 1}: duplicate modId {norm['modId']}")
            continue
        seen.add(norm["modId"])
        valid.append(norm)

    cfg = read_config(server)
    g   = cfg.setdefault("game", {})

    if mode == "merge":
        existing = list(g.get("mods", []))
        existing_ids = {str(m.get("modId", "")).upper() for m in existing}
        added = 0
        for m in valid:
            if m["modId"] not in existing_ids:
                existing.append(m)
                existing_ids.add(m["modId"])
                added += 1
        g["mods"] = existing
        msg = f"Merged: {added} added, {len(valid) - added} already present"
    else:
        g["mods"] = valid
        msg = f"Replaced full mod list with {len(valid)} entries"

    try:
        write_config(server, cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({
        "ok": True,
        "message": msg,
        "imported": len(valid),
        "skipped": skipped,
        "mods": g["mods"],
        "restart_required": get_server_pid(server) is not None,
    })

@app.route("/api/mods/remove", methods=["POST"])
def api_mods_remove():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    data   = request.get_json(silent=True) or {}
    mod_id = data.get("modId", "").strip().upper()
    if not mod_id:
        return jsonify({"ok": False, "error": "Missing modId"})
    cfg  = read_config(server)
    mods = cfg.get("game", {}).get("mods", [])
    new  = [m for m in mods if str(m.get("modId", "")).upper() != mod_id]
    if len(new) == len(mods):
        return jsonify({"ok": False, "error": "Mod not found"})
    cfg.setdefault("game", {})["mods"] = new
    try:
        write_config(server, cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid(server) is not None, "mods": new})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/start", methods=["POST"])
def api_start():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    if get_server_pid(server):
        return jsonify({"ok": False, "error": "Server is already running"})
    ok, out, errout = lgsm_run(server, "start", timeout=45)
    if not ok:
        return jsonify({"ok": False, "error": (errout or out or "LGSM start failed").strip()[-800:]})
    return jsonify({"ok": True})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    if not get_server_pid(server):
        return jsonify({"ok": False, "error": "Server is not running"})
    ok, out, errout = lgsm_run(server, "stop", timeout=60)
    if not ok:
        return jsonify({"ok": False, "error": (errout or out or "LGSM stop failed").strip()[-800:]})
    return jsonify({"ok": True})

@app.route("/api/restart", methods=["POST"])
def api_restart():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    server, err = _require_server()
    if err: return err
    ok, out, errout = lgsm_run(server, "restart", timeout=90)
    if not ok:
        return jsonify({"ok": False, "error": (errout or out or "LGSM restart failed").strip()[-800:]})
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PANEL_PORT, threaded=True)
