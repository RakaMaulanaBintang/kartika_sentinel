# KARTIKA-SENTINEL: AI Perimeter Defense & Cryptographic Trapdoor System

Purwarupa sistem **penangkalan siber** untuk Kartika Cyber Hackathon 2026 (kategori *Penangkalan*). Sistem ini berdiri di depan sebuah aplikasi sebagai **gerbang (API gateway)** yang memeriksa setiap request, memblokir penyerang secara otomatis, menjebak pencuri kunci enkripsi, mengirim pesan taktis yang hancur setelah dibaca, dan menampilkan semuanya dalam satu dashboard.

> Seluruh data dalam demo (dokumen intel, koordinat, kontak) adalah **fiktif**. Simulator serangan hanya menyerang aplikasi contoh lokal milik Anda sendiri.

---

## Daftar isi

1. [Masalah yang diselesaikan](#1-masalah-yang-diselesaikan)
2. [Empat modul](#2-empat-modul)
3. [Arsitektur dan alur request](#3-arsitektur-dan-alur-request)
4. [Mesin deteksi hybrid](#4-mesin-deteksi-hybrid)
5. [Mitigasi otomatis](#5-mitigasi-otomatis)
6. [Pesan taktis sekali-baca](#6-pesan-taktis-sekali-baca)
7. [Vault, Trapdoor Key, dan Honeytoken](#7-vault-trapdoor-key-dan-honeytoken)
8. [Audit log tahan-ubah](#8-audit-log-tahan-ubah)
9. [Dashboard](#9-dashboard)
10. [Cara menjalankan](#10-cara-menjalankan)
11. [Skenario demo](#11-skenario-demo)
12. [Referensi API](#12-referensi-api)
13. [Konfigurasi](#13-konfigurasi)
14. [Keamanan sistem ini sendiri](#14-keamanan-sistem-ini-sendiri)
15. [Hasil pengujian dan akurasi model](#15-hasil-pengujian-dan-akurasi-model)
16. [Batasan dan rencana pengembangan](#16-batasan-dan-rencana-pengembangan)
17. [Struktur folder](#17-struktur-folder)

---

## 1. Masalah yang diselesaikan

Infrastruktur informasi satuan menghadapi tiga masalah yang saling terkait:

| Masalah | Pendekatan KARTIKA-SENTINEL |
|---|---|
| Serangan datang lebih cepat daripada analis bisa merespons | Deteksi dan blokir **otomatis** di gerbang, tanpa menunggu operator |
| Penyerang yang berhasil mencuri kunci tidak terdeteksi karena tampak seperti pengguna sah | **Trapdoor key**: kunci umpan yang tampak asli, memberi data palsu dan membunyikan alarm |
| Komunikasi sensitif tertinggal jejaknya | Pesan **sekali baca**, terenkripsi, dan dihapus dari memori setelah dibuka |

Seluruh kejadian dicatat dalam log yang **tahan-ubah**, sehingga penyusup tidak bisa menghapus jejaknya tanpa ketahuan.

---

## 2. Empat modul

| # | Modul | Fungsi singkat | Berkas |
|---|---|---|---|
| 1 | **Gateway & AI IDS/IPS** | Reverse proxy yang memeriksa request dengan rule dan model ML, lalu memblokir IP berbahaya | `app.py`, `detection.py` |
| 2 | **Komunikasi taktis** | Pesan terenkripsi AES-256-GCM, sekali baca, hancur otomatis | `messages.py` |
| 3 | **Vault & Trapdoor** | Database terenkripsi dengan dua kunci (sah dan jebakan), plus file umpan (honeytoken) | `deception.py` |
| 4 | **Threat Intelligence Dashboard** | Satu layar untuk log real-time, alarm merah, pesan, metrik, dan audit | `frontend/index.html` |

---

## 3. Arsitektur dan alur request

```
                    ┌────────────────────────────────────────────────────────┐
 Klien / Penyerang  │  KARTIKA-SENTINEL  (FastAPI, http://127.0.0.1:8000)    │
        │           │                                                        │
        ▼           │  /gw/*  ──►  1. IP ada di blocklist?                   │
   request  ───────►│                 ya  ──► 403 langsung (model tidak       │
                    │                         dipanggil)                      │
                    │              2. Mesin deteksi hybrid                    │
                    │                 ├─ Rule / heuristik                     │
                    │                 └─ Isolation Forest (ML)                │
                    │                 ──► skor risiko 0-100 + alasan + MITRE  │
                    │              3. Skor ≥ 70 ?                             │
                    │                 ya  ──► blokir IP otomatis + 403        │
                    │              4. Jalur khusus (deception):               │
                    │                 /backup/config.bak  → honeytoken        │
                    │                 /vault, /vault/unlock → vault           │
                    │              5. Selain itu ──► teruskan ke aplikasi     │
                    │                                 target                  │
                    │                                                        │
                    │  Audit log berantai-hash ──► Dashboard admin (API key) │
                    └────────────────────────────────────────────────────────┘
```

Aplikasi target yang dilindungi adalah **portal contoh** (`target.py`). Untuk melindungi aplikasi lain, set `KARTIKA_TARGET_URL` ke alamat aplikasi itu dan semua request akan diteruskan ke sana.

**Urutan keputusan pada setiap request** (`app.py`, fungsi `gateway`):

1. Hitung IP klien. Bila IP ada di blocklist, langsung balas **403** dan catat. Tidak ada pemanggilan model.
2. Ekstrak fitur perilaku dan jalankan rule serta model (lihat bagian 4).
3. Bila skor risiko **≥ 70** → catat, masukkan IP ke blocklist, balas **403**.
4. Bila request menuju jalur umpan atau vault → ditangani modul deception.
5. Selain itu → teruskan ke target, catat status (`PASSED` atau `SUSPICIOUS`), dan perbarui riwayat IP.

---

## 4. Mesin deteksi hybrid

Keputusan memakai **dua sumber yang digabung**, supaya kelemahan satu sumber ditutup oleh yang lain: rule menangkap pola yang jelas dan bisa dijelaskan, ML menangkap perilaku abnormal yang tidak punya signature.

### 4.1 Fitur perilaku per IP

Dihitung pada setiap request dari riwayat IP tersebut:

| Fitur | Arti |
|---|---|
| `req_10s` | jumlah request dari IP itu dalam 10 detik terakhir |
| `error_ratio` | proporsi respons berstatus ≥ 400 dari 20 request terakhir (60 detik) |
| `unique_paths` | jumlah jalur berbeda yang diakses dalam 10 detik |
| `payload_len` | panjang query string + body |
| `special_ratio` | proporsi karakter khusus (`' ; < > ( ) \| \` $ \ * # %`) pada payload |
| `sus_tokens` | jumlah kata mencurigakan (`select`, `union`, `drop`, `script`, `passwd`, `../`, dll.), maksimal 6 |
| `req_per_path` | `req_10s / unique_paths` (membedakan flood dari penjelajahan normal) |

Payload didekode URL dua kali sebelum diperiksa, sehingga pengelabuan lewat encoding ganda (`%2527`) tetap terbaca.

### 4.2 Rule / heuristik

Setiap rule yang cocok menambah bobot ke skor rule. Skor rule maksimal 100.

| Rule | Mendeteksi | Bobot | MITRE ATT&CK |
|---|---|---|---|
| `SQLI` | SQL injection (`UNION SELECT`, `OR 1=1`, `'; DROP`, `--`, `sleep()`) | 75 | T1190 |
| `XSS` | `<script>`, `javascript:`, `onerror=`, tag `<img/svg/iframe>` | 70 | T1190 |
| `TRAVERSAL` | `../`, `/etc/passwd`, `c:\windows` | 75 | T1190 |
| `CMDI` | injeksi perintah (`; cat`, `\| whoami`, `$(...)`) | 80 | T1059 |
| `SCANNER_UA` | User-Agent alat pemindai (sqlmap, nikto, nmap, hydra, dll.) | 70 | T1595.002 |
| `SENSITIVE_PATH` | jalur sensitif (`/.env`, `/.git`, `/admin`, `/wp-login`, `/phpmyadmin`, dll.) | 35 | T1595.002 |
| `SCAN` | ≥ 8 jalur berbeda dalam 10 detik **dan** ≥ 50% error | 65 | T1595 |
| `FLOOD` | > 30 request dalam 10 detik | 75 | T1498 |
| `BRUTE` | ≥ 5 kegagalan login (`/login`, `/vault/unlock`) dalam 60 detik | 85 | T1110 |

### 4.3 Model machine learning

- **Algoritma:** Isolation Forest (scikit-learn), 150 pohon, `contamination = 0.02`.
- **Dilatih pada traffic normal saja** (deteksi anomali tanpa label serangan), dengan 7 fitur di atas.
- **Dilatih otomatis** saat server pertama kali menyala (beberapa detik); model disimpan di `backend/data/model.pkl`. Latih ulang manual dengan `python train.py`.
- Keluaran model: `anomali` atau `normal`, plus skor. Anomali diubah menjadi skor ML antara 40 dan 65 (tidak pernah menembus ambang blokir sendirian).

### 4.4 Penggabungan skor

```
skor_rule = min(100, jumlah bobot rule yang cocok)
skor_ml   = 0                              bila normal
          = min(65, 40 + (-skor_model)*200) bila anomali

risiko = min(100, max(skor_rule, skor_ml) + 0.3 * min(skor_rule, skor_ml))

risiko ≥ 70  → BLOCKED
risiko ≥ 40  → SUSPICIOUS (diloloskan, ditandai kuning)
selain itu   → PASSED
```

Karena skor ML dibatasi 65, **ML saja tidak cukup untuk memblokir**; ia harus diperkuat oleh rule atau perilaku lain. Ini sengaja, untuk menekan false positive pada traffic normal. Setiap keputusan menyimpan **alasan** (nama rule yang cocok dan penanda anomali ML), teknik **MITRE ATT&CK**, dan fitur yang dipakai, sehingga keputusan AI bisa diaudit dan tidak menjadi kotak hitam.

---

## 5. Mitigasi otomatis

Saat IP diblokir, entri disimpan di memori: waktu mulai, waktu kedaluwarsa, alasan, skor, dan sumber (`AI` atau `TRAPDOOR`).

| Aspek | Perilaku |
|---|---|
| Penolakan | Request berikutnya dari IP itu dijawab **403 tanpa memanggil model** (hanya pencarian di memori) |
| Masa blokir | **300 detik** (`KARTIKA_BLOCK_TTL`); **diperpanjang** setiap IP itu mencoba lagi |
| Blokir trapdoor | **3600 detik** (`KARTIKA_TRAP_BLOCK_TTL`), tidak diperpanjang |
| Lepas blokir | Otomatis saat kedaluwarsa (dicatat `UNBLOCK`), atau manual lewat tombol *Unblock* di dashboard |
| Penebakan ID pesan | ≥ 5 akses ID pesan tidak valid dalam 60 detik → IP diblokir (skor 75) |

Blokir bersifat **di level aplikasi** (gateway). Integrasi ke firewall sistem operasi tercantum sebagai rencana pengembangan.

---

## 6. Pesan taktis sekali-baca

Mensimulasikan pengiriman koordinat atau perintah rahasia yang tidak boleh meninggalkan jejak.

**Alur**

1. **Pengirim** (tab *Pesan Taktis*) menulis pesan (maks. 2.000 karakter) dan memilih masa kedaluwarsa (1 menit, 10 menit, atau 1 jam).
2. Server mengenkripsi dengan **AES-256-GCM**: kunci acak 256-bit **per pesan**, nonce acak 12 byte, dan ID pesan dipakai sebagai *associated data*. Kunci **hanya disimpan di memori**, tidak pernah ditulis ke disk.
3. Pengirim mendapat **tautan sekali pakai** berisi ID pesan acak (128-bit).
4. **Penerima** membuka tautan, melihat halaman peringatan, lalu menekan *Buka pesan*.
5. Pada saat itu server mendekripsi, **langsung menghapus entri** dari memori, dan menimpa kunci dengan nol.
6. Browser menampilkan pesan dengan **hitung mundur 10 detik**, lalu mengosongkan teks dari halaman dan menghapus ID dari URL.
7. Membuka tautan yang sama lagi → `404`: *"Pesan tidak ditemukan, sudah dihancurkan, atau kedaluwarsa."*

**Kejadian yang dicatat di dashboard:** `MSG_CREATED`, `MSG_DESTROYED` (pesan dibaca lalu hancur), `MSG_EXPIRED` (kedaluwarsa sebelum dibuka), `MSG_INVALID_ACCESS` (ID salah atau sudah hancur).

> Catatan akurat: pesan dihapus dari **memori server saat pertama kali dibuka**, sedangkan hitung mundur 10 detik adalah batas tampil di **layar penerima**. Isi pesan tidak masuk ke log; log hanya memuat ID yang dipendekkan dan panjang pesan.

---

## 7. Vault, Trapdoor Key, dan Honeytoken

Menjebak penyusup yang berhasil mencuri kunci enkripsi.

### 7.1 Vault terenkripsi

- Database fiktif `backend/data/intel_secret.enc` dienkripsi **Fernet**, dengan kunci turunan dari kunci pengguna lewat **scrypt** (N=2¹⁴, r=8, p=1) dan garam acak.
- Ada **dua kunci** berformat sama: `KSNT-XXXX-XXXX-XXXX-XXXX`.

| Kunci | Hasil saat dipakai di `/gw/vault/unlock` |
|---|---|
| **Kunci SAH** | Data **asli** dibuka dan dicatat `VAULT_ACCESS` (INFO) |
| **Kunci JEBAKAN** | Data **palsu** (decoy) diberikan, lalu alarm dipicu (di bawah) |
| Kunci lain | `401 Kunci tidak valid` (dihitung sebagai kegagalan untuk deteksi brute-force) |

Perbandingan kunci jebakan memakai pembanding waktu-konstan.

### 7.2 Apa yang terjadi saat kunci jebakan dipakai

Server menjalankan fungsi pencatat yang menangkap:

| Data | Sumber |
|---|---|
| **IP penyerang** | alamat klien |
| **Waktu akses** | jam server saat kunci dipakai |
| **Fingerprint server** | SHA-256 (16 karakter pertama) dari `User-Agent`, `Accept-Language`, `Accept-Encoding`, `sec-ch-ua`, `sec-ch-ua-platform` |
| **Fingerprint klien** | resolusi layar, zona waktu, bahasa, platform, jumlah core CPU (dikirim oleh JavaScript di halaman `/gw/vault`) |
| **Kunci yang dipakai** | disamarkan (`KSNT-4B49-****-****-****`) |

Lalu: kejadian `TRAPDOOR_TRIGGERED` (severity **CRITICAL**, skor 100, teknik T1552.001 dan T1078) dicatat, **IP diblokir selama 1 jam**, dan dashboard menampilkan **alarm merah** berisi semua data di atas. Fingerprint yang sama tetap dapat dikenali walau penyerang berganti IP.

### 7.3 Honeytoken (file umpan)

Jalur `/gw/backup/config.bak` dan `/gw/admin/credentials.txt` berpura-pura menjadi file konfigurasi yang bocor. Isinya memuat baris `VAULT_KEY=` yang berisi **kunci jebakan**. Setiap akses ke file ini dicatat sebagai `HONEYTOKEN_ACCESS` (severity HIGH, skor 60, T1552.001) beserta fingerprint, **tanpa langsung memblokir**, sehingga penyerang terdorong memakai kunci itu dan masuk ke jebakan.

> Soal "fungsi tersembunyi": kunci jebakan tidak berisi kode. Server **mengenali kunci itu saat dipakai** lalu menjalankan pencatatan dan alarm. Ini lebih aman daripada menyisipkan kode ke dalam kunci.

---

## 8. Audit log tahan-ubah

Setiap kejadian (traffic, blokir, pesan, trapdoor, login admin gagal) masuk ke satu log berantai.

- Setiap entri memuat `hash = SHA-256(hash_sebelumnya + isi_entri_kanonik)`.
- Mengubah, menghapus, atau menyisipkan satu entri akan **memutus rantai** dari titik itu ke depan.
- Dashboard (tab *Audit & Metrik*) punya tombol:
  - **Verifikasi integritas**: memeriksa seluruh rantai.
  - **Simulasikan penyusup mengubah log**: mengubah satu entri pada **salinan** log lalu memverifikasinya, sehingga terlihat rantai rusak di entri tersebut. Log asli tidak disentuh.
  - **Unduh laporan insiden (CSV)**: seluruh kejadian beserta alasan, MITRE, dan hash. Sel dinetralkan dari formula injection spreadsheet.
- Menyimpan sampai 5.000 entri terakhir; entri tertua yang dibuang dijadikan jangkar rantai agar verifikasi tetap valid.

Batasan: log hidup di memori server. Bila server restart, log kosong kembali (lihat bagian 16).

---

## 9. Dashboard

Satu berkas HTML tanpa CDN (berjalan **offline**), mendukung tema terang dan gelap. Login memakai Admin API key.

| Tab | Isi |
|---|---|
| **Monitor** | Kartu statistik, **alarm merah** trapdoor, grafik traffic 60 detik, log keamanan real-time (filter semua/diblokir/alarm/pesan, pencarian IP, tombol jeda, klik baris untuk detail alasan dan MITRE), top IP penyerang, daftar IP diblokir dengan tombol *Unblock*, teknik MITRE yang terdeteksi, dan tombol simulasi serangan |
| **Pesan Taktis** | Form pengirim, tautan penerima, daftar pesan menunggu dibuka, log pesan |
| **Trapdoor & Vault** | Kunci sah dan jebakan, tombol uji (sebagai pengguna sah, sebagai peretas, akses file umpan), hasil, dan alarm terbaru |
| **Audit & Metrik** | Precision/recall/F1/false positive/akurasi model, matriks konfusi, verifikasi hash chain, simulasi perubahan log, unduh CSV |

Halaman penerima pesan (`/?m=<id>`) adalah tampilan terpisah tanpa login.

---

## 10. Cara menjalankan

Butuh **Python 3.10 atau lebih baru** (`run.bat` otomatis memilih versi terbaru yang terpasang).

**Windows:** klik dua kali `run.bat`.
**Linux / macOS:** `bash run.sh`.
**Docker (opsional):** `docker compose up --build`, login dengan nilai `KARTIKA_ADMIN_KEY` di `docker-compose.yml`.

Skrip membuat virtual environment, memasang dependensi, melatih model otomatis, dan membuka http://127.0.0.1:8000. **Admin key tampil di terminal** saat server menyala (dan tersimpan di `backend/data/admin_key.txt`). `run.bat` membuat key baru setiap dijalankan.

Cara manual:

```
python -m venv venv
venv\Scripts\activate          # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
cd backend
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

---

## 11. Skenario demo

Urutan yang disarankan untuk video (±3 menit). Klik **Reset data demo** dulu agar layar bersih.

1. **Traffic normal**: tekan *Mulai traffic normal* → baris hijau `PASSED`, grafik bergerak.
2. **Serangan satu per satu**: *Brute-force*, *SQLi / XSS*, *Scan jalur*, *Flood*. Tunjukkan baris merah `BLOCKED`; klik satu baris untuk memperlihatkan alasan, skor, dan teknik MITRE.
3. **Kill chain lengkap** (inti cerita): pengintaian → menemukan `/backup/config.bak` → memakai kunci "bocor" → data palsu → **alarm merah** → IP terkunci.
4. **Pesan taktis**: buat pesan, buka tautan di tab baru, lihat hitung mundur dan hancur, buka lagi untuk membuktikan sudah hilang.
5. **Trapdoor & Vault**: bandingkan kunci SAH (data asli) dengan kunci JEBAKAN (data palsu + alarm).
6. **Audit & Metrik**: tunjukkan metrik model, verifikasi integritas, lalu simulasikan perubahan log.

Dari terminal: `cd backend && python attack_sim.py killchain` (atau `all`, `bruteforce`, `sqli`, `scan`, `flood`, `normal`).

Simulator memakai header `X-Sim-IP` agar tiap "penyerang" punya IP berbeda. Header ini **hanya diterima dari loopback** (kecuali mode Docker).

---

## 12. Referensi API

**Publik**

| Method | Path | Fungsi |
|---|---|---|
| ANY | `/gw/{path}` | Gateway: pemeriksaan, deception, atau teruskan ke target |
| POST | `/api/msg/open/{id}` | Buka pesan taktis (sekali baca) |
| GET | `/api/health` | Cek status |
| GET | `/` | Dashboard |

**Admin** (wajib header `X-API-Key`)

| Method | Path | Fungsi |
|---|---|---|
| GET | `/api/admin/ping` | Validasi key |
| GET | `/api/admin/state` | Statistik, log, blocklist, alarm, metrik, grafik |
| POST | `/api/admin/unblock/{ip}` | Lepas blokir IP |
| POST | `/api/admin/reset` | Kosongkan data demo |
| POST | `/api/admin/msg` | Buat pesan taktis (`text`, `ttl`) |
| GET | `/api/admin/vault` | Tampilkan kunci sah dan jebakan (khusus demo) |
| GET | `/api/admin/audit/verify[?simulate_tamper=true]` | Verifikasi hash chain |
| GET | `/api/admin/report.csv` | Laporan insiden |
| POST | `/api/admin/simulate/{nama}` | Jalankan skenario (`bruteforce`, `sqli`, `scan`, `flood`, `killchain`, `normal`) |
| POST | `/api/admin/simulate/loop/{start\|stop}` | Traffic normal berkelanjutan |

---

## 13. Konfigurasi

Lewat variabel lingkungan:

| Variabel | Default | Arti |
|---|---|---|
| `KARTIKA_ADMIN_KEY` | acak, disimpan di `data/admin_key.txt` | Admin API key |
| `KARTIKA_ROTATE_KEY` | `0` (`run.bat` memakai `1`) | `1` = key baru setiap server dinyalakan |
| `KARTIKA_BLOCK_THRESHOLD` | `70` | Skor risiko minimum untuk memblokir |
| `KARTIKA_BLOCK_TTL` | `300` | Lama blokir IP (detik) |
| `KARTIKA_TRAP_BLOCK_TTL` | `3600` | Lama blokir IP yang kena trapdoor (detik) |
| `KARTIKA_TARGET_URL` | kosong | Alamat aplikasi sungguhan; kosong = pakai portal contoh |
| `KARTIKA_ALLOW_SIM_IP` | `1` | Izinkan header `X-Sim-IP` (demo). Set `0` di luar demo |
| `KARTIKA_SIM_TRUST_ALL` | `0` | Hanya untuk Docker lokal; jangan aktifkan bila terbuka ke jaringan |

---

## 14. Keamanan sistem ini sendiri

- **Admin API** dilindungi API key, dibandingkan dengan pembanding waktu-konstan. **8 kegagalan per menit** per IP → `429`; setiap kegagalan dicatat sebagai insiden (T1110).
- Server hanya mendengarkan **`127.0.0.1`**; CORS dibatasi ke localhost; dashboard dilayani dengan header `Content-Security-Policy`, `X-Frame-Options: DENY`, dan `nosniff`.
- Seluruh teks yang berasal dari luar ditampilkan di dashboard dengan `textContent` (tanpa `innerHTML`), sehingga payload serangan yang tercatat di log tidak bisa dieksekusi.
- File CSV dinetralkan dari formula injection (`=`, `+`, `-`, `@`).
- Log tidak menyimpan isi pesan taktis maupun kunci lengkap.
- Batas ukuran body request 1 MB.

---

## 15. Hasil pengujian dan akurasi model

**Akurasi model** (data uji berlabel, `backend/data/metrics.json`; ditampilkan di tab *Audit & Metrik*). Contoh hasil pelatihan dengan seed tetap:

| Metrik | Nilai |
|---|---|
| Precision | 97,5% |
| Recall | 99,7% |
| F1 | 98,6% |
| False positive rate | 2,6% |
| Akurasi | 98,5% |
| Matriks konfusi | TP 1196 · FP 31 · TN 1169 · FN 4 |
| Recall per jenis serangan | flood 100% · brute-force 98,7% · scan 100% · injection 100% |

> **Penting:** angka ini berasal dari **data sintetis buatan sendiri** (traffic normal + 4 jenis serangan), jadi **bukan bukti performa di jaringan nyata**. 

**Pengujian end-to-end** (dijalankan pada pipeline gateway sungguhan):

| Uji | Hasil |
|---|---|
| 250 request normal dari IP berbeda | **0** diblokir, 0 ditandai mencurigakan |
| SQLi, XSS, path traversal (5 payload) | 5 dari 5 diblokir (403) |
| Brute-force login | diblokir pada percobaan ke-6 |
| Scan jalur (User-Agent browser biasa) | diblokir berdasarkan perilaku |
| Flood | diblokir pada request ke-31 |
| Kill chain (file umpan → kunci jebakan) | alarm merah terpicu, data palsu diberikan, IP terkunci |
| Pesan taktis | terbuka sekali, teks dikosongkan setelah 10 detik, buka kedua → 404 |
| Hash chain | utuh; setelah simulasi perubahan, rantai terdeteksi rusak |

---

## 16. Batasan

**Batasan purwarupa saat ini**

- State (blocklist, log, pesan) ada di **memori** dan hilang saat server restart. Vault, model, dan key tetap tersimpan di `backend/data/`.
- Pemblokiran berada di **level aplikasi**; belum memanipulasi firewall sistem operasi.
- Berjalan sebagai **satu proses** (belum clustering atau high availability).
- Model dilatih pada data sintetis; kunci vault demo disimpan di `vault_keys.json` untuk keperluan peragaan.
- Fingerprint berbasis header dan JavaScript bisa dipalsukan penyerang yang canggih; ia pelengkap, bukan identitas pasti.

---

## 17. Struktur folder

```
kartika_sentinel/
├── run.bat / run.sh        # skrip jalankan (Windows / Linux-macOS)
├── requirements.txt
├── Dockerfile, docker-compose.yml, .dockerignore
├── README.md
├── frontend/
│   └── index.html          # dashboard satu berkas (offline)
└── backend/
    ├── app.py              # gateway, API, dashboard
    ├── detection.py        # rule + Isolation Forest, pelatihan, evaluasi
    ├── deception.py        # vault, trapdoor key, honeytoken, fingerprint
    ├── messages.py         # pesan taktis sekali-baca (AES-256-GCM)
    ├── core.py             # audit hash-chain, blocklist, auth admin, statistik
    ├── target.py           # aplikasi target contoh
    ├── simulator.py        # skenario serangan
    ├── attack_sim.py       # simulator serangan via command line
    ├── train.py            # latih ulang model
    └── data/               # dibuat otomatis: model, vault, key (jangan di-commit)
```

**Teknologi:** Python, FastAPI, scikit-learn (Isolation Forest), `cryptography` (AES-GCM, Fernet), httpx, HTML/CSS/JavaScript tanpa framework.

# SUPPORT BY :
**Sleep Not Found**
