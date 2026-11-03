"""Mesin deteksi hybrid: rule/heuristik + Isolation Forest, digabung menjadi skor risiko 0-100."""
import collections
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote

import joblib
import numpy as np

from core import BLOCK_THRESHOLD, DATA_DIR
from deception import HONEY_PATHS

MODEL_PATH = DATA_DIR / "model.pkl"
METRICS_PATH = DATA_DIR / "metrics.json"

FEATURES = ["req_10s", "error_ratio", "unique_paths", "payload_len", "special_ratio", "sus_tokens", "req_per_path"]
# Tanda kutip ganda, kurung kurawal, dan siku sengaja tidak dihitung: wajar muncul di body JSON normal.
SPECIAL = set("';<>()|`$\\*#%")
AUTH_PATHS = {"/login", "/vault/unlock"}
BRUTE_N = 5          # gagal login >= N dalam 60 dtk => brute-force
FLOOD_N = 30         # request > N dalam 10 dtk => flood
SCAN_UNIQUE = 8      # path unik >= N dalam 10 dtk (dengan banyak error) => scan

SENSITIVE_PREFIXES = ("/.env", "/.git", "/.aws", "/.ssh", "/wp-login", "/wp-admin", "/phpmyadmin", "/server-status",
                      "/config.php", "/admin", "/etc/passwd", "/backup.zip", "/cgi-bin")

# (id, nama, regex, bobot, MITRE ATT&CK)
RULES = [
    ("SQLI", "SQL Injection", re.compile(
        r"(\bunion\b[\s\S]{0,30}\bselect\b)|(\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+)|(['\"]\s*(or|and)\s+['\"\d])"
        r"|(--\s*$|--\s)|(;\s*(drop|delete|insert|update|alter)\b)|(\bsleep\s*\(|\bbenchmark\s*\()|(\bselect\b[\s\S]+\bfrom\b)",
        re.I), 75, "T1190"),
    ("XSS", "Cross-Site Scripting (XSS)", re.compile(
        r"<\s*script|javascript\s*:|on(error|load|click|mouseover)\s*=|<\s*(img|svg|iframe)[^>]*>", re.I), 70, "T1190"),
    ("TRAVERSAL", "Path Traversal", re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows)", re.I), 75, "T1190"),
    ("CMDI", "Command Injection", re.compile(
        r"(;|\||&&|`|\$\()\s*(cat|ls|whoami|id|uname|wget|curl|nc|ncat|bash|sh|powershell|cmd)\b", re.I), 80, "T1059"),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|nessus|zgrab", re.I)
SUS_TOKENS = re.compile(
    r"\b(select|union|insert|drop|delete|update|sleep|benchmark|script|alert|onerror|onload|passwd|whoami|wget|curl|"
    r"bash|exec|eval|cmd)\b|\.\./", re.I)


@dataclass
class RequestInfo:
    method: str
    path: str
    query: str
    body: str
    ua: str


class IPState:
    __slots__ = ("reqs", "fails", "last")

    def __init__(self):
        self.reqs = collections.deque(maxlen=300)   # (ts, path, status)
        self.fails = collections.deque(maxlen=50)   # ts gagal autentikasi
        self.last = time.time()


ip_state: dict = {}
_model = None
metrics: dict = {}


def _st(ip: str) -> IPState:
    st = ip_state.get(ip)
    if st is None:
        st = ip_state[ip] = IPState()
    return st


def gc_states(max_idle: int = 300) -> None:
    now = time.time()
    for ip in [ip for ip, s in ip_state.items() if now - s.last > max_idle]:
        del ip_state[ip]


def reset() -> None:
    ip_state.clear()


def _deep_unquote(s: str) -> str:
    for _ in range(2):
        s = unquote(s)
    return s


def _norm_path(p: str) -> str:
    return p.rstrip("/").lower() or "/"


# ---------------- Ekstraksi fitur ----------------
def extract_features(ip: str, info: RequestInfo, now: float) -> dict:
    st = _st(ip)
    recent10 = [r for r in st.reqs if now - r[0] <= 10]
    window = [r for r in st.reqs if now - r[0] <= 60][-20:]
    errs = sum(1 for r in window if r[2] is not None and r[2] >= 400)
    text = _deep_unquote(info.query + " " + info.body)
    count = len(recent10) + 1
    unique = len({r[1] for r in recent10} | {info.path})
    return {
        "req_10s": count,
        "error_ratio": errs / len(window) if window else 0.0,
        "unique_paths": unique,
        "payload_len": len(info.query) + len(info.body),
        "special_ratio": sum(c in SPECIAL for c in text) / max(1, len(text)),
        "sus_tokens": min(6, len(SUS_TOKENS.findall(text))),
        "req_per_path": count / max(1, unique),
    }


# ---------------- Rule / heuristik ----------------
def run_rules(ip: str, info: RequestInfo, f: dict, now: float) -> list:
    hits = []
    target = _deep_unquote(info.path + "?" + info.query + " " + info.body)
    for rid, name, rx, weight, mitre in RULES:
        if rx.search(target):
            hits.append({"id": rid, "name": name, "weight": weight, "mitre": mitre})
    if SCANNER_UA.search(info.ua or ""):
        hits.append({"id": "SCANNER_UA", "name": "Tool pemindai terdeteksi (User-Agent)", "weight": 70, "mitre": "T1595.002"})
    path = _norm_path(info.path)
    if path not in HONEY_PATHS and any(path.startswith(p) for p in SENSITIVE_PREFIXES):
        hits.append({"id": "SENSITIVE_PATH", "name": "Mengakses jalur sensitif", "weight": 35, "mitre": "T1595.002"})
    if f["unique_paths"] >= SCAN_UNIQUE and f["error_ratio"] >= 0.5:
        hits.append({"id": "SCAN", "name": "Perilaku pemindaian jalur (scan)", "weight": 65, "mitre": "T1595"})
    if f["req_10s"] > FLOOD_N:
        hits.append({"id": "FLOOD", "name": "Banjir permintaan (flood)", "weight": 75, "mitre": "T1498"})
    st = _st(ip)
    if sum(1 for t in st.fails if now - t <= 60) >= BRUTE_N:
        hits.append({"id": "BRUTE", "name": "Brute-force login", "weight": 85, "mitre": "T1110"})
    return hits


# ---------------- Model ML ----------------
def _fit_predict_risk(vec) -> tuple:
    x = np.array([vec], dtype=float)
    pred = int(_model.predict(x)[0])
    d = float(_model.decision_function(x)[0])
    risk = min(65, 40 + (-d) * 200) if pred == -1 else 0
    return pred, d, risk


def assess(ip: str, info: RequestInfo) -> dict:
    """Nilai satu request: fitur -> rule + ML -> skor risiko gabungan -> keputusan."""
    now = time.time()
    st = _st(ip)
    st.last = now
    f = extract_features(ip, info, now)
    hits = run_rules(ip, info, f, now)
    pred, d, ml_risk = (1, 0.0, 0) if _model is None else _fit_predict_risk([f[k] for k in FEATURES])

    rule_score = min(100, sum(h["weight"] for h in hits))
    hi, lo = max(rule_score, ml_risk), min(rule_score, ml_risk)
    risk = int(min(100, hi + 0.3 * lo))
    reasons = [h["name"] for h in hits]
    if pred == -1:
        reasons.append("Anomali perilaku terdeteksi model ML")
    decision = "BLOCKED" if risk >= BLOCK_THRESHOLD else ("SUSPICIOUS" if risk >= 40 else "PASSED")
    return {
        "risk": risk, "decision": decision, "reasons": reasons,
        "mitre": sorted({h["mitre"] for h in hits}),
        "features": {k: round(float(v), 3) for k, v in f.items()},
        "ml": {"anomaly": pred == -1, "score": round(d, 4)},
    }


def record_response(ip: str, info: RequestInfo, status: int) -> bool:
    """Catat hasil request. Kembalikan True bila ambang brute-force baru saja tercapai."""
    now = time.time()
    st = _st(ip)
    st.last = now
    st.reqs.append((now, info.path, status))
    if _norm_path(info.path) in AUTH_PATHS and status in (401, 403):
        st.fails.append(now)
        return sum(1 for t in st.fails if now - t <= 60) >= BRUTE_N
    return False


# ---------------- Data sintetis, pelatihan, evaluasi ----------------
def _with_derived(arr):
    """Tambah kolom req_per_path = req_10s / unique_paths (urutan sama dengan FEATURES)."""
    arr = np.asarray(arr, dtype=float)
    return np.column_stack([arr, arr[:, 0] / np.maximum(1.0, arr[:, 2])])


def gen_normal(rng, n: int):
    count = np.minimum(10, 1 + rng.poisson(1.5, n)).astype(float)
    err = rng.beta(1, 14, n)
    uniq = np.minimum(count, rng.integers(1, 5, n)).astype(float)
    payload = np.abs(rng.normal(30, 25, n))
    special = np.where(rng.random(n) < 0.9, 0.0, rng.uniform(0, 0.04, n))
    sus = (rng.random(n) < 0.01).astype(float)
    return _with_derived(np.column_stack([count, err, uniq, payload, special, sus]))


ATTACK_KINDS = ["flood", "bruteforce", "scan", "injection"]


def gen_attack(rng, kind: str, n: int):
    if kind == "flood":
        return _with_derived(np.column_stack([rng.integers(25, 120, n), rng.uniform(0, 0.3, n), rng.integers(1, 4, n),
                                              np.abs(rng.normal(20, 10, n)), np.zeros(n), np.zeros(n)]))
    if kind == "bruteforce":
        return _with_derived(np.column_stack([rng.integers(4, 13, n), rng.uniform(0.7, 1.0, n), rng.integers(1, 3, n),
                                              rng.uniform(30, 70, n), rng.uniform(0, 0.03, n), np.zeros(n)]))
    if kind == "scan":
        uniq = rng.integers(8, 36, n)
        count = np.maximum(rng.integers(8, 45, n), uniq)
        return _with_derived(np.column_stack([count, rng.uniform(0.6, 1.0, n), uniq, rng.uniform(0, 40, n),
                                              rng.uniform(0, 0.03, n), (rng.random(n) < 0.2)]))
    return _with_derived(np.column_stack([rng.integers(1, 7, n), rng.uniform(0, 0.5, n), rng.integers(1, 4, n),
                                          rng.uniform(40, 500, n), rng.uniform(0.05, 0.4, n), rng.integers(1, 6, n)]))


def train_model(seed: int = 42, save: bool = True) -> dict:
    """Latih Isolation Forest pada traffic normal (sintetis), evaluasi pada data uji berlabel."""
    from sklearn.ensemble import IsolationForest

    rng = np.random.default_rng(seed)
    normal = gen_normal(rng, 6000)
    split = 4800
    model = IsolationForest(n_estimators=150, contamination=0.02, random_state=seed)
    model.fit(normal[:split])

    test_normal = normal[split:]
    per_kind, attack_blocks = {}, []
    for kind in ATTACK_KINDS:
        X = gen_attack(rng, kind, 300)
        pred = model.predict(X) == -1
        per_kind[kind] = round(float(pred.mean()), 4)
        attack_blocks.append(pred)
    atk_pred = np.concatenate(attack_blocks)
    nor_pred = model.predict(test_normal) == -1

    tp, fn = int(atk_pred.sum()), int((~atk_pred).sum())
    fp, tn = int(nor_pred.sum()), int((~nor_pred).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    m = {
        "algoritma": "Isolation Forest (150 pohon, contamination 0.02)",
        "dataset": "Sintetis: traffic normal + 4 jenis serangan (flood, brute-force, scan, injection)",
        "dilatih_pada": datetime.now().isoformat(timespec="seconds"),
        "sampel_latih": split, "uji_normal": len(test_normal), "uji_serangan": int(len(atk_pred)),
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "fpr": round(fp / (fp + tn), 4), "accuracy": round((tp + tn) / (tp + tn + fp + fn), 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "recall_per_serangan": per_kind,
        "catatan": "Hasil pada data sintetis; untuk klaim nyata latih ulang dengan dataset publik (NSL-KDD/CIC-IDS2017).",
    }
    if save:
        joblib.dump(model, MODEL_PATH)
        METRICS_PATH.write_text(json.dumps(m, indent=2, ensure_ascii=False))
    return m, model


def load_model() -> None:
    """Muat model; bila belum ada atau gagal dimuat, latih otomatis (hanya beberapa detik)."""
    global _model, metrics
    try:
        _model = joblib.load(MODEL_PATH)
        metrics = json.loads(METRICS_PATH.read_text()) if METRICS_PATH.exists() else {}
        return
    except Exception:
        pass
    metrics, _model = train_model()
