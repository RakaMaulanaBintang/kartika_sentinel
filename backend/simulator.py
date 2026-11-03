"""Simulator traffic & serangan untuk demo. Dipakai oleh dashboard (in-process) dan attack_sim.py (via HTTP).

Semua request dikirim ke gateway KARTIKA-SENTINEL (/gw/...) dengan header X-Sim-IP agar tiap "penyerang"
punya IP berbeda (hanya diterima bila datang dari loopback). Target hanya aplikasi contoh lokal.
"""
import asyncio
import random
import re

import httpx

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
KEY_RE = re.compile(r"KSNT-[0-9A-F]{4}(?:-[0-9A-F]{4}){3}")
WORDS = ["jadwal", "piket", "sandi", "kontak", "prosedur", "panduan"]


def _ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(2, 254)}"


async def _req(c: httpx.AsyncClient, ip: str, method: str, path: str, ua: str = BROWSER_UA, **kw):
    headers = kw.pop("headers", {})
    headers.update({"X-Sim-IP": ip, "User-Agent": ua})
    try:
        return await c.request(method, "/gw" + path, headers=headers, **kw)
    except httpx.HTTPError:
        return None


async def normal_one(c: httpx.AsyncClient) -> None:
    ip = _ip("192.168.1")
    roll = random.random()
    if roll < 0.35:
        await _req(c, ip, "GET", "/")
    elif roll < 0.6:
        await _req(c, ip, "GET", "/api/status")
    elif roll < 0.9:
        await _req(c, ip, "GET", f"/search?q={random.choice(WORDS)}")
    else:
        await _req(c, ip, "POST", "/login", json={"username": "operator", "password": "Op3rator!2026"})


async def normal(c, n: int = 25):
    lines = [f"Mengirim {n} request normal dari IP 192.168.1.x"]
    for _ in range(n):
        await normal_one(c)
        await asyncio.sleep(0.2)
    return lines


async def bruteforce(c):
    ip = _ip("10.66.66")
    lines = [f"Brute-force login dari {ip}"]
    for i, pw in enumerate(["123456", "password", "admin", "qwerty", "letmein", "operator", "Op3rator", "welcome", "12345678", "iloveyou"], 1):
        r = await _req(c, ip, "POST", "/login", json={"username": "operator", "password": pw})
        code = r.status_code if r is not None else "-"
        lines.append(f"  percobaan {i}: HTTP {code}")
        await asyncio.sleep(0.25)
        if code == 403:
            lines.append("  -> IP diblokir oleh KARTIKA-SENTINEL")
            break
    return lines


async def sqli(c):
    payloads = ["' OR 1=1--", "1' UNION SELECT username,password FROM users--", "'; DROP TABLE users;--",
                "<script>alert(1)</script>", "../../etc/passwd"]
    lines = []
    for p in payloads:
        ip = _ip("10.66.66")
        r = await _req(c, ip, "GET", "/search", params={"q": p})
        lines.append(f"  {ip} q={p!r} -> HTTP {r.status_code if r is not None else '-'}")
        await asyncio.sleep(0.4)
    return ["Injeksi (SQLi/XSS/traversal) dari beberapa IP"] + lines


async def scan(c):
    ip = _ip("10.66.66")
    paths = ["/.env", "/admin", "/wp-login.php", "/phpmyadmin", "/server-status", "/.git/config", "/config.php",
             "/backup.zip", "/login.php", "/robots.txt", "/cgi-bin/test", "/.aws/credentials"]
    lines = [f"Pemindaian jalur dari {ip} (User-Agent browser biasa, tanpa signature)"]
    for p in paths:
        r = await _req(c, ip, "GET", p)
        code = r.status_code if r is not None else "-"
        lines.append(f"  GET {p} -> HTTP {code}")
        await asyncio.sleep(0.15)
        if code == 403:
            lines.append("  -> IP diblokir berdasarkan perilaku")
            break
    return lines


async def flood(c, n: int = 70):
    ip = _ip("10.66.66")
    lines = [f"Flood {n} request cepat dari {ip}"]
    blocked_at = None
    for i in range(1, n + 1):
        r = await _req(c, ip, "GET", "/")
        if r is not None and r.status_code == 403 and blocked_at is None:
            blocked_at = i
    lines.append(f"  diblokir pada request ke-{blocked_at}" if blocked_at else "  tidak diblokir")
    return lines


async def killchain(c):
    ip = _ip("10.66.66")
    lines = [f"Kill chain lengkap dari {ip}"]
    for p in ("/api/status", "/robots.txt", "/admin"):
        r = await _req(c, ip, "GET", p)
        lines.append(f"  1. Pengintaian GET {p} -> HTTP {r.status_code if r is not None else '-'}")
        await asyncio.sleep(0.4)
    r = await _req(c, ip, "GET", "/backup/config.bak")
    text = r.text if r is not None else ""
    lines.append(f"  2. GET /backup/config.bak -> HTTP {r.status_code if r is not None else '-'} (menemukan file 'bocor')")
    await asyncio.sleep(0.8)
    m = KEY_RE.search(text)
    if not m:
        lines.append("  kunci tidak ditemukan (kemungkinan IP sudah diblokir)")
        return lines
    key = m.group(0)
    lines.append(f"  3. Mencoba kunci hasil curian {key[:9]}-****")
    r = await _req(c, ip, "POST", "/vault/unlock", json={"key": key, "fp": {"screen": "1366x768", "tz": "UTC", "platform": "Linux x86_64"}})
    lines.append(f"     vault merespons HTTP {r.status_code if r is not None else '-'} (penyerang mendapat DATA PALSU)")
    await asyncio.sleep(0.8)
    r = await _req(c, ip, "GET", "/")
    lines.append(f"  4. Percobaan lanjutan -> HTTP {r.status_code if r is not None else '-'} (IP sudah diblokir)")
    return lines


SCENARIOS = {
    "normal": normal,
    "bruteforce": bruteforce,
    "sqli": sqli,
    "scan": scan,
    "flood": flood,
    "killchain": killchain,
}
