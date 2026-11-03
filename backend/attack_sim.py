"""Simulator serangan untuk demo (berjalan via HTTP ke gateway KARTIKA-SENTINEL milik Anda sendiri).

Contoh:
    python attack_sim.py killchain
    python attack_sim.py all --url http://127.0.0.1:8000

Skenario: normal, bruteforce, sqli, scan, flood, killchain, all.
HANYA gunakan terhadap sistem Anda sendiri (target contoh lokal).
"""
import argparse
import asyncio

import httpx

from simulator import SCENARIOS


async def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=list(SCENARIOS) + ["all"])
    p.add_argument("--url", default="http://127.0.0.1:8000", help="alamat KARTIKA-SENTINEL")
    args = p.parse_args()

    names = ["normal", "sqli", "scan", "bruteforce", "flood", "killchain"] if args.scenario == "all" else [args.scenario]
    async with httpx.AsyncClient(base_url=args.url, timeout=15) as c:
        for name in names:
            print(f"\n=== Skenario: {name} ===")
            for line in await SCENARIOS[name](c):
                print(line)
            await asyncio.sleep(1)
    print("\nSelesai. Lihat hasilnya di dashboard.")


if __name__ == "__main__":
    asyncio.run(main())
