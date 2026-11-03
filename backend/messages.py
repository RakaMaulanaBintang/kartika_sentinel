"""Komunikasi taktis sekali-baca (ephemeral & self-destruct). Terenkripsi AES-256-GCM, kunci hanya di memori."""
import collections
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import core
from core import block_ip, emit, stats

MAX_LEN = 2000
store: dict = {}  # id -> {ct, nonce, key(bytearray), created, expires, from_ip}
_invalid: dict = collections.defaultdict(collections.deque)


def create(text: str, ttl: int, sender_ip: str) -> str:
    mid = secrets.token_urlsafe(16)
    key = bytearray(AESGCM.generate_key(bit_length=256))
    nonce = secrets.token_bytes(12)
    ct = AESGCM(bytes(key)).encrypt(nonce, text.encode("utf-8"), mid.encode("utf-8"))
    now = time.time()
    store[mid] = {"ct": ct, "nonce": nonce, "key": key, "created": now, "expires": now + ttl, "from_ip": sender_ip}
    stats["msg_created"] += 1
    emit("MSG_CREATED", "INFO", sender_ip, f"Pesan taktis dibuat (kedaluwarsa {ttl} dtk)", status="PASSED",
         details={"id": mid[:6] + "…", "ttl_detik": ttl, "panjang": len(text)})
    return mid


def _wipe(entry: dict) -> None:
    k = entry["key"]
    for i in range(len(k)):
        k[i] = 0
    entry["ct"] = b""


def open_once(mid: str, ip: str):
    """Baca pesan lalu hancurkan permanen. Kembalikan teks, atau None bila tidak ada."""
    entry = store.pop(mid, None)
    if entry is None:
        return None
    if entry["expires"] <= time.time():
        _wipe(entry)
        stats["msg_expired"] += 1
        emit("MSG_EXPIRED", "INFO", entry["from_ip"], "Pesan taktis kedaluwarsa sebelum dibuka", status="PASSED",
             details={"id": mid[:6] + "…"})
        return None
    try:
        text = AESGCM(bytes(entry["key"])).decrypt(entry["nonce"], entry["ct"], mid.encode("utf-8")).decode("utf-8")
    except InvalidTag:
        _wipe(entry)
        return None
    _wipe(entry)
    stats["msg_destroyed"] += 1
    emit("MSG_DESTROYED", "MEDIUM", ip, "Pesan taktis dibaca lalu dihancurkan permanen (self-destruct)",
         status="PASSED", details={"id": mid[:6] + "…", "pembaca": ip})
    return text


def note_invalid(ip: str) -> bool:
    """Catat akses ID salah. Kembalikan True bila IP kini diblokir (>=5 kali/60 dtk)."""
    now = time.time()
    dq = _invalid[ip]
    while dq and now - dq[0] > 60:
        dq.popleft()
    dq.append(now)
    emit("MSG_INVALID_ACCESS", "MEDIUM", ip, "Akses pesan taktis dengan ID tidak valid/sudah hancur",
         status="BLOCKED", risk=40, mitre=["T1110"])
    if len(dq) >= 5:
        block_ip(ip, "Menebak ID pesan taktis", 75, source="AI", mitre=["T1110"])
        return True
    return False


def purge_expired() -> None:
    now = time.time()
    for mid in [m for m, e in store.items() if e["expires"] <= now]:
        entry = store.pop(mid)
        _wipe(entry)
        stats["msg_expired"] += 1
        emit("MSG_EXPIRED", "INFO", entry["from_ip"], "Pesan taktis kedaluwarsa dan dihapus otomatis",
             status="PASSED", details={"id": mid[:6] + "…"})


def pending_list() -> list:
    now = time.time()
    return [{"id": m[:6] + "…", "sisa_detik": max(0, int(e["expires"] - now))} for m, e in store.items()]


def reset() -> None:
    for e in store.values():
        _wipe(e)
    store.clear()
    _invalid.clear()
