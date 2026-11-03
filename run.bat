@echo off
setlocal
cd /d "%~dp0"
echo === KARTIKA-SENTINEL ===

rem --- Admin key baru setiap run.bat dijalankan. Hapus baris berikut bila ingin key tetap. ---
set "KARTIKA_ROTATE_KEY=1"

rem --- Cari Python terbaru yang terpasang, harus versi 3.10 atau lebih baru ---
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul && set "PY=py -3"
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo [GAGAL] Python 3.10 atau lebih baru tidak ditemukan.
  echo Python di komputer ini terlalu lama untuk library yang dibutuhkan.
  echo.
  echo Solusi:
  echo   1. Unduh Python terbaru dari https://www.python.org/downloads/
  echo   2. Saat instalasi, CENTANG "Add python.exe to PATH"
  echo   3. Tutup jendela ini, lalu klik dua kali run.bat lagi
  echo.
  pause
  exit /b 1
)
echo Memakai: %PY%
%PY% --version

rem --- Buang venv lama bila dibuat dengan Python yang terlalu lama ---
if exist venv\Scripts\python.exe (
  venv\Scripts\python.exe -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
  if errorlevel 1 (
    echo Membuang venv lama ^(dibuat dengan Python lama^)...
    rmdir /s /q venv
  )
)

if not exist venv (
  echo [1/3] Membuat virtual environment...
  %PY% -m venv venv
  if errorlevel 1 (
    echo [GAGAL] Tidak bisa membuat virtual environment.
    pause
    exit /b 1
  )
)
call venv\Scripts\activate.bat

echo [2/3] Memasang dependensi ^(hanya lama saat pertama kali^)...
python -m pip install -q --upgrade pip >nul 2>nul
python -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo.
  echo [GAGAL] Dependensi tidak bisa dipasang. Kirim pesan error di atas untuk dicek.
  echo Penyebab umum: tidak ada internet, atau Python bukan versi 64-bit.
  pause
  exit /b 1
)

echo [3/3] Menjalankan server di http://127.0.0.1:8000
echo Biarkan jendela ini tetap terbuka selama demo. Tekan Ctrl+C untuk berhenti.
cd backend
start "" http://127.0.0.1:8000
python -m uvicorn app:app --host 127.0.0.1 --port 8000
pause
