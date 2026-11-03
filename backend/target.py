"""Aplikasi target CONTOH yang dilindungi gateway. Ganti dengan aplikasi sungguhan lewat KARTIKA_TARGET_URL."""
import json

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

target_app = FastAPI(title="Portal Satuan (contoh)", docs_url=None, redoc_url=None, openapi_url=None)

USERS = {"operator": "Op3rator!2026"}
ARTICLES = ["Jadwal piket siber", "Panduan rotasi sandi", "Prosedur pelaporan insiden", "Daftar kontak satuan"]


@target_app.get("/", response_class=HTMLResponse)
async def index():
    return (
        "<!doctype html><html lang='id'><meta charset='utf-8'><title>Portal Satuan (contoh)</title>"
        "<body style='font-family:system-ui;max-width:640px;margin:48px auto'>"
        "<h2>Portal Satuan</h2><p>Aplikasi contoh yang dilindungi KARTIKA-SENTINEL.</p></body></html>"
    )


@target_app.get("/api/status")
async def status():
    return {"status": "ok", "service": "Portal Satuan (contoh)"}


@target_app.get("/search")
async def search(q: str = ""):
    results = [a for a in ARTICLES if q.lower() in a.lower()] if q else ARTICLES
    return {"query": q[:100], "results": results}


@target_app.post("/login")
async def login(request: Request):
    try:
        data = json.loads((await request.body()) or b"{}")
    except ValueError:
        return JSONResponse({"error": "Format JSON tidak valid"}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"error": "Format tidak valid"}, status_code=400)
    user, pw = str(data.get("username", "")), str(data.get("password", ""))
    if USERS.get(user) == pw and pw:
        return {"status": "ok", "message": f"Selamat datang, {user}"}
    return JSONResponse({"error": "Username atau password salah"}, status_code=401)
