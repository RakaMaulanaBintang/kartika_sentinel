# KARTIKA-SENTINEL

**AI Perimeter Defense & Cryptographic Trapdoor System** — purwarupa untuk Kartika Cyber Hackathon 2026, kategori *Penangkalan*.

Satu sistem, satu alur cerita: **penyerang menyerang gerbang → diblokir otomatis → menemukan "kunci bocor" → terjebak trapdoor → alarm merah di dashboard** — ditambah komunikasi taktis sekali-baca yang hancur sendiri dan log audit yang tahan-ubah.

> Seluruh data pada demo (dokumen intel, koordinat, kontak) adalah **fiktif**. Simulator serangan hanya menyerang aplikasi contoh lokal milik Anda sendiri.

## Cara menjalankan (±2 menit)

Butuh **Python 3.10+** (centang "Add Python to PATH" saat memasang di Windows).

**Windows:** klik dua kali `run.bat`
**Linux / macOS / Git Bash:** `bash run.sh`

Skrip akan membuat virtual environment, memasang dependensi, melatih model AI otomatis (beberapa detik), lalu membuka dashboard di **http://127.0.0.1:8000**.

Saat server menyala, terminal menampilkan **Admin key** (juga tersimpan di `backend/data/admin_key.txt`). Salin ke layar login dashboard.

## Skenario demo (untuk video, ±3 menit)

1. Login → tab **Monitor** → **Mulai traffic normal** (hijau PASSED, grafik bergerak).
2. Tekan **Brute-force**, **SQLi / XSS**, **Scan jalur**, **Flood** → baris merah BLOCKED; klik baris untuk melihat *alasan*, skor risiko, dan teknik **MITRE ATT&CK**.
3. Tekan **Jalankan KILL CHAIN lengkap** → penyerang menemukan `/backup/config.bak`, memakai kunci "bocor" → **ALARM MERAH** (IP, waktu, fingerprint perangkat) → IP dikunci.
4. Tab **Pesan Taktis** → buat pesan → buka tautan di tab baru → tampil 10 detik lalu hancur; buka lagi → tidak bisa.
5. Tab **Trapdoor & Vault** → buka dengan kunci sah (data asli) vs kunci jebakan (data palsu + alarm).
6. Tab **Audit & Metrik** → precision/recall/FPR model, **Verifikasi integritas**, lalu **Simulasikan penyusup mengubah log** → rantai terdeteksi rusak. Unduh laporan insiden CSV.

Simulasi dari terminal: `cd backend && python attack_sim.py all` (atau `killchain`, `bruteforce`, `sqli`, `scan`, `flood`).

## Arsitektur

```
Klien/Penyerang ──► /gw/*  GATEWAY (reverse proxy)
                      │ 1. Blocklist? ──► 403 (milidetik)
                      │ 2. Mesin deteksi HYBRID
                      │      ├─ Rule: SQLi, XSS, traversal, cmd-injection, scanner UA,
                      │      │        brute-force, flood, scan jalur, jalur sensitif
                      │      └─ ML: Isolation Forest (7 fitur perilaku per IP)
                      │      → skor risiko 0-100 + alasan + MITRE ATT&CK
                      │ 3. Skor ≥ 70 ──► BLOKIR OTOMATIS (TTL, diperpanjang bila mencoba lagi)
                      │ 4. Deception: /backup/config.bak (honeytoken), /vault (trapdoor)
                      └─ 5. Lolos ──► Aplikasi target (contoh)

Audit log berantai-hash (SHA-256) ──► Dashboard admin (API key) ──► laporan CSV
Pesan taktis: AES-256-GCM, kunci hanya di memori, sekali baca, self-destruct
```

| Modul | Berkas | Isi |
|---|---|---|
| Gateway & API | `backend/app.py` | reverse proxy, IPS, API admin, dashboard |
| Deteksi hybrid | `backend/detection.py` | rule + Isolation Forest, pelatihan & evaluasi |
| Deception | `backend/deception.py` | vault terenkripsi, kunci sah vs trapdoor, honeytoken, fingerprint |
| Pesan taktis | `backend/messages.py` | enkripsi AES-GCM, sekali baca, penghancuran |
| Inti | `backend/core.py` | audit hash-chain, blocklist, auth admin, statistik |
| Simulator | `backend/simulator.py`, `attack_sim.py` | skenario serangan |
| Dashboard | `frontend/index.html` | satu file, tanpa CDN (jalan offline) |

## Tentang model AI — jujur soal klaim

- Algoritma: **Isolation Forest** (scikit-learn) dilatih pada traffic **normal sintetis**, dievaluasi pada data uji berlabel (normal + 4 jenis serangan). Metrik tampil di tab *Audit & Metrik* dan di `backend/data/metrics.json`.
- Itu **data sintetis buatan sendiri**, jadi angkanya bukan bukti performa di jaringan nyata. Di slide, sebut ini sebagai *proof of concept*.
- Untuk klaim lebih kuat, latih ulang dengan dataset publik (NSL-KDD / CIC-IDS2017): ganti `gen_normal` / `gen_attack` di `detection.py`, lalu `python train.py`.
- Yang membuat blokir andal adalah **kombinasi** rule + ML; ML menangkap perilaku yang tidak punya signature.

## Keamanan aplikasi

- Semua endpoint admin butuh **API key** (perbandingan waktu-konstan, rate-limit percobaan salah, percobaan salah dicatat sebagai insiden).
- CORS dibatasi ke localhost; server hanya mendengarkan `127.0.0.1`; header keamanan + CSP pada dashboard.
- Seluruh teks dari luar di dashboard dirender dengan `textContent` (tanpa `innerHTML`), CSV dinetralkan dari formula injection.
- Header `X-Sim-IP` (IP simulasi untuk demo) **hanya diterima dari loopback**. Matikan dengan `KARTIKA_ALLOW_SIM_IP=0` bila dipakai di luar demo.

Variabel lingkungan: `KARTIKA_ADMIN_KEY`, `KARTIKA_BLOCK_THRESHOLD` (70), `KARTIKA_BLOCK_TTL` (300 dtk), `KARTIKA_TRAP_BLOCK_TTL` (3600), `KARTIKA_TARGET_URL` (proxy ke aplikasi nyata alih-alih target contoh), `KARTIKA_ALLOW_SIM_IP`.

## Batasan purwarupa (sebutkan di slide sebagai rencana pengembangan)

- State (blocklist, log, pesan) ada di **memori**: hilang saat server restart (kecuali vault & model di `backend/data/`). Rencana: SQLite/PostgreSQL + Redis.
- Pemblokiran berada di level aplikasi (gateway), belum menyentuh firewall OS (`iptables`/`nftables`). Rencana: integrasi aksi firewall nyata.
- Berjalan satu proses; belum clustering/HA.
- Kunci sah dan jebakan disimpan di `vault_keys.json` untuk keperluan demo; produksi memakai HSM/secret manager.
