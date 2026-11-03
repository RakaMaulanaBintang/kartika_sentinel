#!/usr/bin/env bash
# Jalankan KARTIKA-SENTINEL (Linux / macOS / Git Bash)
set -e
cd "$(dirname "$0")"
echo "=== KARTIKA-SENTINEL ==="

command -v python3 >/dev/null 2>&1 || { echo "Python 3 belum terpasang."; exit 1; }

if [ ! -d venv ]; then
  echo "[1/3] Membuat virtual environment..."
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate

echo "[2/3] Memasang dependensi..."
python -m pip install -q -r requirements.txt

echo "[3/3] Menjalankan server di http://127.0.0.1:8000"
cd backend
exec python -m uvicorn app:app --host 127.0.0.1 --port 8000
