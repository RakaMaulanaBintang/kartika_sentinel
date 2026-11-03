"""Inti KARTIKA-SENTINEL: konfigurasi, audit log berantai-hash, blocklist, statistik, autentikasi admin."""
import collections
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from pathlib import Path

from fastapi import Header, HTTPException, Request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# ---------------- Konfigurasi (bisa diubah lewat environment variable) ----------------
BLOCK_THRESHOLD = int(os.getenv("KARTIKA_BLOCK_THRESHOLD", "70"))   # skor risiko >= ini => blokir
BLOCK_TTL = int(os.getenv("KARTIKA_BLOCK_TTL", "300"))              # lama blokir IP (detik)
TRAP_BLOCK_TTL = int(os.getenv("KARTIKA_TRAP_BLOCK_TTL", "3600"))   # lama blokir IP yang kena trapdoor
ALLOW_SIM_IP = os.getenv("KARTIKA_ALLOW_SIM_IP", "1") == "1"        # izinkan header X-Sim-IP dari loopback (demo)
# Hanya untuk Docker demo: terima X-Sim-IP dari sumber mana pun. AMAN hanya bila port dipublikasikan ke
# 127.0.0.1 (seperti di docker-compose.yml). Jangan aktifkan bila server terbuka ke jaringan.
SIM_TRUST_ALL = os.getenv("KARTIKA_SIM_TRUST_ALL", "0") == "1"
MAX_EVENTS = 5000
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def load_admin_key() -> str:
    """API key admin: dari env, atau dibuat acak sekali lalu disimpan di data/admin_key.txt."""
    env = os.getenv("KARTIKA_ADMIN_KEY")
    if env:
        return env
    f = DATA_DIR / "admin_key.txt"
    rotate = os.getenv("KARTIKA_ROTATE_KEY", "0") == "1"  # key baru setiap server dinyalakan
    if f.exists() and not rotate:
        return f.read_text().strip()
    key = "KSA-" + secrets.token_urlsafe(18)
    f.write_text(key)
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return key


ADMIN_KEY = load_admin_key()


# ---------------- Statistik & timeline ----------------
def new_stats() -> dict:
    return {
        "requests": 0, "passed": 0, "suspicious": 0, "blocked": 0,
        "honeytoken_hits": 0, "trap_triggers": 0,
        "msg_created": 0, "msg_destroyed": 0, "msg_expired": 0,
    }


stats = new_stats()
timeline: dict = {}  # detik epoch -> [jumlah request, jumlah diblokir]


def tick(blocked: bool) -> None:
    s = int(time.time())
    b = timeline.setdefault(s, [0, 0])
    b[0] += 1
    if blocked:
        b[1] += 1
    for k in [k for k in timeline if k < s - 180]:
        del timeline[k]


def timeline_series(n: int = 60) -> list:
    now = int(time.time())
    return [timeline.get(s, [0, 0]) for s in range(now - n + 1, now + 1)]


# ---------------- Audit log berantai-hash (tahan-ubah) ----------------
HASH_FIELDS = ("id", "ts", "time", "type", "severity", "ip", "summary", "status", "risk", "reasons", "mitre", "details")
events: list = []
chain = {"anchor": "GENESIS", "last_hash": "GENESIS", "seq": 0}

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(s, limit: int = 160) -> str:
    return _CTRL.sub("", str(s))[:limit]


def _canon(e: dict) -> str:
    return json.dumps({k: e[k] for k in HASH_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev: str, e: dict) -> str:
    return hashlib.sha256((prev + _canon(e)).encode("utf-8")).hexdigest()


def emit(type_, severity, ip, summary, status="-", risk=0, reasons=None, mitre=None, details=None) -> dict:
    chain["seq"] += 1
    now = time.time()
    e = {
        "id": chain["seq"],
        "ts": round(now, 3),
        "time": time.strftime("%H:%M:%S", time.localtime(now)),
        "type": type_,
        "severity": severity,
        "ip": str(ip),
        "summary": clean(summary),
        "status": status,
        "risk": int(risk),
        "reasons": list(reasons or []),
        "mitre": list(mitre or []),
        "details": details or {},
    }
    e["prev_hash"] = chain["last_hash"]
    e["hash"] = compute_hash(chain["last_hash"], e)
    chain["last_hash"] = e["hash"]
    events.append(e)
    if len(events) > MAX_EVENTS:
        chain["anchor"] = events.pop(0)["hash"]
    return e


def verify_chain(evs=None, anchor=None) -> dict:
    evs = events if evs is None else evs
    prev = chain["anchor"] if anchor is None else anchor
    for i, e in enumerate(evs):
        if e["prev_hash"] != prev or e["hash"] != compute_hash(e["prev_hash"], e):
            return {"ok": False, "checked": i, "total": len(evs), "broken_at": e["id"]}
        prev = e["hash"]
    return {"ok": True, "checked": len(evs), "total": len(evs), "broken_at": None}


def verify_with_simulated_tamper() -> dict:
    """Salin log, ubah satu entri di tengah, lalu verifikasi. Tidak mengubah log asli."""
    copy_ = copy.deepcopy(events)
    if not copy_:
        return {"ok": True, "checked": 0, "total": 0, "broken_at": None, "tampered_id": None}
    idx = len(copy_) // 2
    copy_[idx]["summary"] = copy_[idx]["summary"] + " [DIUBAH PENYUSUP]"
    res = verify_chain(copy_, chain["anchor"])
    res["tampered_id"] = copy_[idx]["id"]
    return res


# ---------------- Blocklist (mitigasi otomatis) ----------------
blocklist: dict = {}  # ip -> {since, expires, reason, risk, source}


def purge_blocklist() -> None:
    now = time.time()
    for ip in [ip for ip, v in blocklist.items() if v["expires"] <= now]:
        del blocklist[ip]
        emit("UNBLOCK", "INFO", ip, "Masa blokir berakhir otomatis", status="PASSED")


def is_blocked(ip: str):
    ent = blocklist.get(ip)
    if ent and ent["expires"] <= time.time():
        purge_blocklist()
        ent = blocklist.get(ip)
    return ent


def block_ip(ip: str, reason: str, risk: int, ttl: int = None, source: str = "AI", mitre=None) -> None:
    ttl = ttl or BLOCK_TTL
    now = time.time()
    is_new = ip not in blocklist
    blocklist[ip] = {"since": now, "expires": now + ttl, "reason": clean(reason, 120), "risk": int(risk), "source": source}
    if is_new:
        emit("BLOCK", "HIGH", ip, f"IP diblokir otomatis: {reason}", status="BLOCKED", risk=risk,
             mitre=mitre, details={"ttl_detik": ttl, "sumber": source})


def unblock_ip(ip: str) -> bool:
    if ip in blocklist:
        del blocklist[ip]
        emit("UNBLOCK", "INFO", ip, "Blokir dilepas manual oleh admin", status="PASSED")
        return True
    return False


# ---------------- IP klien & autentikasi admin ----------------
def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    direct = request.client.host if request.client else "0.0.0.0"
    if ALLOW_SIM_IP and (SIM_TRUST_ALL or direct in LOOPBACK):
        sim = request.headers.get("x-sim-ip", "")
        if sim and _valid_ip(sim):
            return sim
    return direct


_admin_fail: dict = collections.defaultdict(collections.deque)


async def require_admin(request: Request, x_api_key: str = Header(default="")):
    ip = client_ip(request)
    now = time.time()
    dq = _admin_fail[ip]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= 8:
        raise HTTPException(status_code=429, detail="Terlalu banyak percobaan. Coba lagi sebentar.")
    if not secrets.compare_digest(x_api_key.encode("utf-8"), ADMIN_KEY.encode("utf-8")):
        dq.append(now)
        emit("ADMIN_LOGIN_FAIL", "MEDIUM", ip, "Percobaan akses admin dengan API key salah",
             status="BLOCKED", risk=50, mitre=["T1110"])
        raise HTTPException(status_code=401, detail="API key tidak valid")


def reset_core() -> None:
    events.clear()
    chain.update({"anchor": "GENESIS", "last_hash": "GENESIS", "seq": 0})
    stats.clear()
    stats.update(new_stats())
    timeline.clear()
    blocklist.clear()
    _admin_fail.clear()