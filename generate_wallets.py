import json
import os
import secrets
import sys

from coincurve import PrivateKey


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WALLETS_PATH = os.path.join(BASE_DIR, "wallets.json")


def main():
    count = int(os.getenv("WORKERS", "2"))
    force = "--force" in sys.argv

    if os.path.exists(WALLETS_PATH) and not force:
        print("wallets.json already exists. Use --force to overwrite.")
        return 1

    wallets = []
    for i in range(count):
        pk = secrets.token_bytes(32)
        pub = PrivateKey(pk).public_key.format(compressed=True)[1:].hex()
        wallets.append({"id": i, "private_key": pk.hex(), "public_key": pub})

    with open(WALLETS_PATH, "w", encoding="utf-8") as f:
        json.dump(wallets, f, indent=2)
    print(f"generated {count} wallets at {WALLETS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
