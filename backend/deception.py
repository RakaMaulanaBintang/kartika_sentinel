"""Modul deception: database intel berkunci (Vault), Trapdoor Key, honeytoken, dan fingerprint perangkat."""
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

import core
from core import DATA_DIR, TRAP_BLOCK_TTL, block_ip, emit, stats

VAULT_FILE = DATA_DIR / "intel_secret.enc"
KEYS_FILE = DATA_DIR / "vault_keys.json"

# Path umpan: tampak seperti file bocor/backup. Setiap akses memicu alarm.
HONEY_PATHS = ("/backup/config.bak", "/admin/credentials.txt")

KEY_RE = re.compile(r"^KSNT-[0-9A-F]{4}(-[0-9A-F]{4}){3}$")

# Seluruh isi di bawah ini FIKTIF (data demo).
REAL_DATA = {
    "klasifikasi": "TERBATAS (DATA DEMO FIKTIF)",
    "dokumen": [
        {"id": "OPS-014", "judul": "Jadwal rotasi sandi satuan", "isi": "Rotasi kunci dilakukan tiap Senin 06.00 oleh operator jaga."},
        {"id": "OPS-021", "judul": "Titik kumpul darurat (fiktif)", "isi": "Titik A: lapangan apel. Titik B: gedung serbaguna."},
        {"id": "OPS-033", "judul": "Kontak piket siber (fiktif)", "isi": "Piket-1: ext. 1101, Piket-2: ext. 1102."},
    ],
}
DECOY_DATA = {
    "klasifikasi": "RAHASIA",
    "dokumen": [
        {"id": "OPS-101", "judul": "Rencana pergeseran logistik", "isi": "Konvoi berangkat 04.30, rute utara, 6 kendaraan."},
        {"id": "OPS-117", "judul": "Daftar sandi cadangan", "isi": "Sandi-1: BRAVO-7731, Sandi-2: KILO-2049."},
        {"id": "OPS-122", "judul": "Jaringan komunikasi alternatif", "isi": "Kanal 7 pukul 22.00, frekuensi cadangan kanal 12."},
    ],
}

_state = {"valid_key": "", "trap_key": "", "salt": b""}


def _gen_key() -> str:
    return "KSNT-" + "-".join(secrets.token_hex(2).upper() for _ in range(4))


def _derive(key: str, salt: bytes) -> bytes:
    raw = hashlib.scrypt(key.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)


def init() -> None:
    """Buat vault terenkripsi + sepasang kunci (sah & jebakan) bila belum ada."""
    if VAULT_FILE.exists() and KEYS_FILE.exists():
        k = json.loads(KEYS_FILE.read_text())
        _state.update(valid_key=k["valid_key"], trap_key=k["trap_key"], salt=base64.b64decode(k["salt"]))
        return
    valid, trap = _gen_key(), _gen_key()
    salt = secrets.token_bytes(16)
    token = Fernet(_derive(valid, salt)).encrypt(json.dumps(REAL_DATA).encode("utf-8"))
    VAULT_FILE.write_bytes(token)
    KEYS_FILE.write_text(json.dumps({
        "catatan": "Hanya untuk demo. Di produksi simpan kunci sah terpisah (HSM/secret manager).",
        "valid_key": valid, "trap_key": trap, "salt": base64.b64encode(salt).decode(),
    }, indent=2))
    try:
        import os
        os.chmod(KEYS_FILE, 0o600)
    except OSError:
        pass
    _state.update(valid_key=valid, trap_key=trap, salt=salt)


def keys_info() -> dict:
    return {"valid_key": _state["valid_key"], "trap_key": _state["trap_key"], "vault_file": VAULT_FILE.name,
            "terenkripsi": VAULT_FILE.exists()}


def mask_key(key: str) -> str:
    return key[:9] + "-****-****-****" if len(key) >= 9 else "****"


def sanitize_client_fp(fp) -> dict:
    if not isinstance(fp, dict):
        return {}
    out = {}
    for k in ("screen", "tz", "lang", "platform", "cores"):
        if k in fp:
            out[k] = core.clean(fp[k], 60)
    return out


def fingerprint(headers, client_fp=None) -> dict:
    ua = headers.get("user-agent", "")
    lang = headers.get("accept-language", "")
    enc = headers.get("accept-encoding", "")
    ch_ua = headers.get("sec-ch-ua", "")
    plat = headers.get("sec-ch-ua-platform", "")
    server_fp = hashlib.sha256("|".join([ua, lang, enc, ch_ua, plat]).encode("utf-8")).hexdigest()[:16]
    return {
        "fingerprint_server": server_fp,
        "user_agent": core.clean(ua, 200),
        "accept_language": core.clean(lang, 80),
        "klien": sanitize_client_fp(client_fp) or None,
    }


def honeytoken_body(path: str) -> str:
    return (
        "# KARTIKA backup config (jangan disebarkan)\n"
        "DB_HOST=10.0.0.12\n"
        "DB_USER=svc_intel\n"
        "DB_PASS=Wq8-vX2!nR5z\n"
        f"VAULT_KEY={_state['trap_key']}\n"
    )


def handle_honeytoken(ip: str, path: str, headers) -> str:
    fp = fingerprint(headers)
    stats["honeytoken_hits"] += 1
    emit("HONEYTOKEN_ACCESS", "HIGH", ip, f"Honeytoken diakses: {path}", status="WATCH", risk=60,
         reasons=["Mengakses file umpan (honeytoken)"], mitre=["T1552.001"], details=fp)
    return honeytoken_body(path)


def vault_unlock(ip: str, headers, body: dict):
    """Kembalikan (status_http, payload). Kunci sah -> data asli; kunci jebakan -> data palsu + alarm."""
    key = core.clean(body.get("key", ""), 40).strip()
    fp = fingerprint(headers, body.get("fp"))

    if secrets.compare_digest(key.encode("utf-8"), _state["trap_key"].encode("utf-8")):
        stats["trap_triggers"] += 1
        details = dict(fp)
        details.update({"ip_pengakses": ip, "waktu": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "kunci_dipakai": mask_key(key)})
        emit("TRAPDOOR_TRIGGERED", "CRITICAL", ip, "TRAPDOOR TERPICU: kunci jebakan digunakan untuk membuka vault",
             status="BLOCKED", risk=100, reasons=["Memakai trapdoor key (kunci hasil kebocoran)"],
             mitre=["T1552.001", "T1078"], details=details)
        block_ip(ip, "Menggunakan trapdoor key", 100, ttl=TRAP_BLOCK_TTL, source="TRAPDOOR", mitre=["T1078"])
        return 200, {"status": "ok", "data": DECOY_DATA}

    if KEY_RE.match(key):
        try:
            data = Fernet(_derive(key, _state["salt"])).decrypt(VAULT_FILE.read_bytes())
            emit("VAULT_ACCESS", "INFO", ip, "Vault dibuka dengan kunci sah", status="PASSED")
            return 200, {"status": "ok", "data": json.loads(data)}
        except (InvalidToken, ValueError):
            pass
    return 401, {"error": "Kunci tidak valid"}


VAULT_PAGE = """<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Portal Intel Satuan (contoh)</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:48px auto;padding:0 16px;color:#1f2937}
input,button{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #cbd5e1}
button{background:#10b981;color:#fff;border:0;cursor:pointer}pre{background:#f1f5f9;padding:12px;border-radius:8px;overflow:auto}</style></head>
<body><h2>Portal Intel Satuan</h2><p>Masukkan kunci dekripsi untuk membuka database intel.</p>
<form id="f"><input id="k" placeholder="KSNT-XXXX-XXXX-XXXX-XXXX" size="30" autocomplete="off">
<button>Buka</button></form><pre id="out"></pre>
<script>
const fp={screen:screen.width+'x'+screen.height,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
lang:navigator.language,platform:navigator.platform,cores:String(navigator.hardwareConcurrency||'')};
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();
const r=await fetch('/gw/vault/unlock',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({key:document.getElementById('k').value,fp})});
document.getElementById('out').textContent=r.status+'\\n'+await r.text();});
</script></body></html>"""
