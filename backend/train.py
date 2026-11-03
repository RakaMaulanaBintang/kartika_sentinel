"""Latih ulang model deteksi anomali (Isolation Forest) dan tampilkan metrik evaluasi.

    python train.py

Model otomatis dilatih saat server pertama dijalankan; skrip ini untuk melatih ulang secara manual.
"""
import json

import detection


def main() -> None:
    metrics, _ = detection.train_model()
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    print(f"\nModel berhasil disimpan: {detection.MODEL_PATH}")


if __name__ == "__main__":
    main()
