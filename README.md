# RAJDOLL v1

Asisten pribadi untuk vulnerability assessment (VA) aplikasi web. RAJDOLL menjalankan pipeline VA lengkap di laptop: recon, pengujian per kategori OWASP WSTG v4.2, validasi temuan secara deterministik, bantuan LLM lokal untuk tugas-tugas kecil, triase, laporan Markdown, dan retest.

> **Status: sedang dibangun ulang.** Saat ini repo berada di fase **F0 (persiapan)**. Belum ada fitur VA yang bisa dipakai. Rencana lengkap ada di [`docs/v1/IPD.md`](docs/v1/IPD.md).

## Dokumen

| Dokumen | Isi |
|---|---|
| [PRD](docs/v1/PRD.md) | Tujuan, pengguna, kebutuhan fungsional dan non-fungsional |
| [TRD](docs/v1/TRD.md) | Arsitektur dan keputusan teknis |
| [AFD](docs/v1/AFD.md) | Alur aplikasi, state machine, wireframe |
| [BSD](docs/v1/BSD.md) | Skema database dan kontrak API |
| [IPD](docs/v1/IPD.md) | Fase pengerjaan dan kriteria selesai |

## Menjalankan kerangka (F0)

Prasyarat: Windows dengan Docker Desktop (backend WSL2). Simpan repo di filesystem WSL (misalnya `~/RAJDOLL`), bukan di `/mnt/c`.

1. Salin `.env.example` menjadi `.env`, lalu isi `POSTGRES_PASSWORD`.
2. Jalankan:

   ```bash
   docker compose up -d --build
   ```

3. Buka `http://127.0.0.1:8000/health`. Responsnya harus `{"status": "ok", ...}`.

## Pengembangan

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

## Kode lama

Sistem multi-agen sebelumnya ada di folder [`legacy/`](legacy/) sebagai rujukan selama pembangunan ulang, dan akan dihapus di fase F11. Versi lama yang masih bisa dijalankan ada di tag `v0-legacy` (commit `3307255`).

## Lisensi

MIT, lihat [LICENSE](LICENSE).
