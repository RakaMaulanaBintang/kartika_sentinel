"""KARTIKA-SENTINEL — gateway keamanan: deteksi hybrid (rule + ML), mitigasi otomatis, deception, pesan taktis, audit."""
import asyncio
import csv
import io
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

import core
import deception
import detection
import messages
import simulator
from core import client_ip, emit, require_admin, stats
from target import target_app

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
MAX_BODY = 1_000_000
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
               "transfer-encoding", "upgrade", "host", "content-length", "content-encoding",
               "x-sim-ip", "x-forwarded-for", "x-sentinel-client-ip"}

TARGET_URL = os.getenv("KARTIKA_TARGET_URL")  # kosong = pakai aplikasi contoh in-process
if TARGET_URL:
    target_client = httpx.AsyncClient(base_url=TARGET_URL, timeout=10, follow_redirects=False)
else:
    target_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=target_app), base_url="http://target", timeout=10)

_tasks: set = set()
_loop_task = None


async def housekeeping():
    while True:
        await asyncio.sleep(5)
        messages.purge_expired()
        core.purge_blocklist()
        detection.gc_states()


@asynccontextmanager
async def lifespan(app: FastAPI):
    deception.init()
    detection.load_model()
    emit("SYSTEM", "INFO", "-", "KARTIKA-SENTINEL aktif: gateway, mesin deteksi hybrid, deception, dan audit siap", status="PASSED")
    hk = asyncio.create_task(housekeeping())
    print("\n" + "=" * 64)
    print(" KARTIKA-SENTINEL aktif")
    print(" Dashboard : http://127.0.0.1:8000")
    print(f" Admin key : {core.ADMIN_KEY}")
    print(" (disimpan di backend/data/admin_key.txt; ganti via env KARTIKA_ADMIN_KEY)")
    print("=" * 64 + "\n")
    yield
    hk.cancel()
    for t in list(_tasks):
        t.cancel()
    await target_client.aclose()
    await self_client.aclose()


app = FastAPI(title="KARTIKA-SENTINEL", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(null|https?://(127\.0\.0\.1|localhost)(:\d+)?)$",
    allow_methods=["*"], allow_headers=["*"],
)
self_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://sentinel", timeout=60)


# ============================ Gateway (reverse proxy + IDS/IPS) ============================
def _log_traffic(ip, info, decision, risk, reasons, mitre, extra):
    stats["requests"] += 1
    key = {"PASSED": "passed", "SUSPICIOUS": "suspicious", "BLOCKED": "blocked"}[decision]
    stats[key] += 1
    core.tick(decision == "BLOCKED")
    sev = {"PASSED": "INFO", "SUSPICIOUS": "MEDIUM", "BLOCKED": "HIGH"}[decision]
    summary = f"{info.method} {info.path}" + (f"?{info.query}" if info.query else "")
    return emit("TRAFFIC", sev, ip, summary, status=decision, risk=risk, reasons=reasons, mitre=mitre, details=extra)


@app.api_route("/gw/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway(path: str, request: Request):
    ip = client_ip(request)
    full_path = "/" + path
    query = request.url.query
    raw = await request.body()
    if len(raw) > MAX_BODY:
        return JSONResponse({"error": "Payload terlalu besar"}, status_code=413)
    info = detection.RequestInfo(request.method, full_path, query, raw[:4096].decode("utf-8", "ignore"),
                                 request.headers.get("user-agent", ""))

    # 1) Blocklist: tolak langsung
    ent = core.is_blocked(ip)
    if ent:
        ent["expires"] = max(ent["expires"], time.time() + (core.BLOCK_TTL if ent["source"] != "TRAPDOOR" else 0))
        ev = _log_traffic(ip, info, "BLOCKED", ent["risk"], ["IP ada di blocklist: " + ent["reason"]], [], {"sumber": "BLOCKLIST"})
        return JSONResponse({"error": "Forbidden", "ref": ev["id"]}, status_code=403)

    # 2) Analisis hybrid
    res = detection.assess(ip, info)
    if res["decision"] == "BLOCKED":
        ev = _log_traffic(ip, info, "BLOCKED", res["risk"], res["reasons"], res["mitre"],
                          {"fitur": res["features"], "ml": res["ml"], "ua": core.clean(info.ua, 80)})
        core.block_ip(ip, "; ".join(res["reasons"]) or "Skor risiko tinggi", res["risk"], mitre=res["mitre"])
        detection.record_response(ip, info, 403)
        return JSONResponse({"error": "Forbidden", "ref": ev["id"]}, status_code=403)

    # 3) Deception (honeytoken & vault) atau teruskan ke target
    norm = full_path.rstrip("/").lower() or "/"
    resp = None
    if norm in deception.HONEY_PATHS:
        resp = Response(deception.handle_honeytoken(ip, norm, request.headers), status_code=200, media_type="text/plain")
    elif norm == "/vault" and request.method == "GET":
        resp = HTMLResponse(deception.VAULT_PAGE)
    elif norm == "/vault/unlock" and request.method == "POST":
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        status, payload = deception.vault_unlock(ip, request.headers, body if isinstance(body, dict) else {})
        resp = JSONResponse(payload, status_code=status)
    else:
        fwd = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
        fwd["x-forwarded-for"] = ip
        fwd["x-sentinel-client-ip"] = ip
        url = full_path + (f"?{query}" if query else "")
        try:
            up = await target_client.request(request.method, url, headers=fwd, content=raw)
        except httpx.HTTPError:
            resp = JSONResponse({"error": "Target tidak dapat dihubungi"}, status_code=502)
        else:
            out = {k: v for k, v in up.headers.items() if k.lower() not in HOP_HEADERS}
            resp = Response(content=up.content, status_code=up.status_code, headers=out)

    _log_traffic(ip, info, res["decision"], res["risk"], res["reasons"], res["mitre"],
                 {"fitur": res["features"], "ml": res["ml"], "http": resp.status_code, "ua": core.clean(info.ua, 80)})
    if detection.record_response(ip, info, resp.status_code) and not core.is_blocked(ip):
        core.block_ip(ip, "Brute-force login terdeteksi (>=5 kegagalan/60 dtk)", 85, mitre=["T1110"])
    return resp


# ============================ Pesan taktis (publik: penerima) ============================
@app.post("/api/msg/open/{mid}")
async def msg_open(mid: str, request: Request):
    ip = client_ip(request)
    if core.is_blocked(ip):
        raise HTTPException(status_code=403, detail="Forbidden")
    text = messages.open_once(mid[:64], ip)
    if text is None:
        messages.note_invalid(ip)
        raise HTTPException(status_code=404, detail="Pesan tidak ditemukan, sudah dihancurkan, atau kedaluwarsa")
    return {"text": text, "hancur_dalam_detik": 10}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# ============================ Admin API ============================
class MsgIn(BaseModel):
    text: str = Field(min_length=1, max_length=messages.MAX_LEN)
    ttl: int = Field(default=600, ge=30, le=86400)


@app.get("/api/admin/ping", dependencies=[Depends(require_admin)])
async def ping():
    return {"ok": True}


@app.get("/api/admin/state", dependencies=[Depends(require_admin)])
async def state():
    now = time.time()
    evs = core.events
    attackers, mitre_counts = {}, {}
    for e in evs[-1500:]:
        if e["type"] == "TRAFFIC" and e["status"] == "BLOCKED":
            attackers[e["ip"]] = attackers.get(e["ip"], 0) + 1
        for t in e["mitre"]:
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
    top = sorted(attackers.items(), key=lambda kv: -kv[1])[:5]
    alarms = [e for e in evs if e["type"] in ("TRAPDOOR_TRIGGERED", "HONEYTOKEN_ACCESS")][-15:]
    trim = lambda e: {k: v for k, v in e.items() if k != "prev_hash"}
    return {
        "now": now,
        "stats": dict(stats),
        "blocked_active": len(core.blocklist),
        "blocklist": [{"ip": ip, "reason": v["reason"], "risk": v["risk"], "source": v["source"],
                       "sisa_detik": max(0, int(v["expires"] - now))} for ip, v in core.blocklist.items()],
        "events": [trim(e) for e in evs[-150:]][::-1],
        "alarms": [trim(e) for e in alarms][::-1],
        "timeline": core.timeline_series(60),
        "top_attackers": [{"ip": ip, "n": n} for ip, n in top],
        "mitre": mitre_counts,
        "metrics": detection.metrics,
        "messages": messages.pending_list(),
        "chain": {"events": len(evs), "last_hash": core.chain["last_hash"][:16]},
        "sim_loop": _loop_task is not None and not _loop_task.done(),
        "config": {"threshold": core.BLOCK_THRESHOLD, "ttl": core.BLOCK_TTL},
    }


@app.post("/api/admin/unblock/{ip}", dependencies=[Depends(require_admin)])
async def unblock(ip: str):
    if not core.unblock_ip(ip):
        raise HTTPException(status_code=404, detail="IP tidak ada di blocklist")
    return {"unblocked": ip}


@app.post("/api/admin/reset", dependencies=[Depends(require_admin)])
async def reset():
    core.reset_core()
    messages.reset()
    detection.reset()
    emit("SYSTEM", "INFO", "-", "Data direset oleh admin", status="PASSED")
    return {"status": "reset"}


@app.post("/api/admin/msg", dependencies=[Depends(require_admin)])
async def msg_create(body: MsgIn, request: Request):
    mid = messages.create(body.text, body.ttl, client_ip(request))
    link = str(request.base_url).rstrip("/") + "/?m=" + mid
    return {"id": mid, "link": link, "ttl": body.ttl}


@app.get("/api/admin/vault", dependencies=[Depends(require_admin)])
async def vault_info():
    return deception.keys_info()


@app.get("/api/admin/audit/verify", dependencies=[Depends(require_admin)])
async def audit_verify(simulate_tamper: bool = False):
    res = core.verify_with_simulated_tamper() if simulate_tamper else core.verify_chain()
    res["simulasi_perubahan"] = simulate_tamper
    return res


def _csv_cell(v) -> str:
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


@app.get("/api/admin/report.csv", dependencies=[Depends(require_admin)])
async def report_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "waktu", "jenis", "severity", "ip", "status", "risiko", "ringkasan", "alasan", "mitre", "hash"])
    for e in core.events:
        w.writerow([e["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])), e["type"], e["severity"],
                    _csv_cell(e["ip"]), e["status"], e["risk"], _csv_cell(e["summary"]),
                    _csv_cell("; ".join(e["reasons"])), ",".join(e["mitre"]), e["hash"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": "attachment; filename=laporan_insiden_kartika_sentinel.csv"})


def _spawn(coro):
    t = asyncio.create_task(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return t


async def _normal_loop():
    while True:
        await simulator.normal_one(self_client)
        await asyncio.sleep(0.8)


@app.post("/api/admin/simulate/loop/{action}", dependencies=[Depends(require_admin)])
async def sim_loop(action: str):
    global _loop_task
    if action == "start":
        if _loop_task is None or _loop_task.done():
            _loop_task = _spawn(_normal_loop())
    elif action == "stop":
        if _loop_task is not None:
            _loop_task.cancel()
            _loop_task = None
    else:
        raise HTTPException(status_code=404, detail="Aksi tidak dikenal")
    return {"running": _loop_task is not None and not _loop_task.done()}


@app.post("/api/admin/simulate/{name}", dependencies=[Depends(require_admin)])
async def simulate(name: str):
    fn = simulator.SCENARIOS.get(name)
    if not fn:
        raise HTTPException(status_code=404, detail="Skenario tidak dikenal")
    _spawn(fn(self_client))
    return {"started": name}


# ============================ Dashboard ============================
@app.get("/")
async def dashboard():
    return FileResponse(FRONTEND, media_type="text/html", headers={
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:",
    })
