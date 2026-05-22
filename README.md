# RPOW ORACLE Railway Web Miner

Folder ini untuk deploy Railway sebagai **web service**, bukan worker service.
App bind ke `$PORT`, punya `/healthz`, dan miner CPU berjalan di background dari proses web.

## Deploy

1. Upload folder `railway-web` ke Railway.
2. Pilih service type web/default.
3. Railway akan memakai start command dari `railway.json`:

```bash
gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 120 app:app
```

## Config

Default sudah mining token `oracle` dan auto-send ke `main_wallet` di `config.json`.
Override lewat Railway Variables kalau perlu:

```env
TOKEN=oracle
WORKERS=2
AUTO_SEND_THRESHOLD=1
CPU_BATCH_SIZE=100000
MAIN_WALLET=3944bf6fde01a9554bcbeb3dbc55849b8a4431723f99ba2c3e733eaf8deacde6
AUTO_START=1
AUTO_GENERATE_WALLETS=1
```

Kalau `wallets.json` tidak ada, app akan generate wallet runtime otomatis. Kalau mau pakai wallet tetap, buat `wallets.json` dengan:

```bash
python generate_wallets.py
```

Jangan push `wallets.json` ke repo publik karena berisi private key.

## Endpoints

- `/` dashboard sederhana
- `/healthz` healthcheck Railway
- `/status` status JSON
- `POST /start` start miner
- `POST /stop` stop miner

Catatan: ini CPU miner untuk Railway web container. Tidak memakai OpenCL/GPU.
