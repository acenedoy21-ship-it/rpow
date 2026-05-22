import base64
import hashlib
import html
import json
import os
import secrets
import struct
import threading
import time
import uuid
from decimal import Decimal, InvalidOperation

import requests
from coincurve import PrivateKey
from flask import Flask, Response, jsonify, redirect, request, url_for
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
WALLETS_PATH = os.path.join(BASE_DIR, "wallets.json")
ORIGIN = "https://rpow.hopeware.ltd"
BASE_UNIT_DECIMALS = 9
BASE_UNIT_SCALE = Decimal(10) ** BASE_UNIT_DECIMALS

DEFAULT_CONFIG = {
    "main_wallet": "",
    "token": "oracle",
    "workers": 2,
    "auto_send_threshold": 1,
    "cpu_batch_size": 100000,
    "worker_start_delay": 0,
}

TOKEN_ALIASES = {
    "aplha": "alpha",
}

SUPPORTED_TOKENS = {
    "meme": {"path": "meme", "label": "MEME"},
    "alpha": {"path": "alpha", "label": "ALPHA"},
    "beta": {"path": "beta", "label": "BETA"},
    "burn": {"path": "burn", "label": "BURN"},
    "oracle": {"path": "oracle", "label": "ORACLE"},
}

app = Flask(__name__)

state_lock = threading.RLock()
stop_event = threading.Event()
threads = []
app_state = {
    "running": False,
    "stopping": False,
    "started_at": None,
    "token": None,
    "token_path": None,
    "workers_configured": 0,
    "workers_active": 0,
    "total_mined": 0,
    "total_sent": "0",
    "last_error": "",
    "workers": [],
    "log": [],
}


def as_decimal(value):
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(0)


def fmt_amount(value):
    amount = as_decimal(value)
    if amount == amount.to_integral_value():
        return str(amount.quantize(Decimal(1)))
    text = format(amount, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def amount_from_base_units(base_units):
    amount = as_decimal(base_units) / BASE_UNIT_SCALE
    return fmt_amount(amount)


def balance_base_units_from_me(me):
    if not isinstance(me, dict):
        return None
    base_units = me.get("balance_base_units")
    if base_units is None:
        return None
    base_units = str(base_units).strip()
    if as_decimal(base_units) <= 0:
        return "0"
    return base_units


def add_log(message):
    with state_lock:
        app_state["log"].append(
            {"ts": int(time.time()), "message": str(message)[:300]}
        )
        app_state["log"] = app_state["log"][-100:]


def resolve_token(cfg):
    raw = cfg.get("token", DEFAULT_CONFIG["token"])
    token = str(raw or DEFAULT_CONFIG["token"]).strip().lower()
    token = TOKEN_ALIASES.get(token, token)
    if token not in SUPPORTED_TOKENS:
        allowed = ", ".join(t.upper() for t in SUPPORTED_TOKENS)
        raise ValueError(f"Unsupported token '{raw}'. Use one of: {allowed}")
    return SUPPORTED_TOKENS[token]


def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def env_int(name, default):
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(read_json(CONFIG_PATH, {}))

    if os.getenv("MAIN_WALLET"):
        cfg["main_wallet"] = os.getenv("MAIN_WALLET", "").strip()
    if os.getenv("TOKEN"):
        cfg["token"] = os.getenv("TOKEN", "").strip()
    cfg["workers"] = env_int("WORKERS", int(cfg.get("workers", 2)))
    cfg["auto_send_threshold"] = env_int(
        "AUTO_SEND_THRESHOLD", int(cfg.get("auto_send_threshold", 1))
    )
    cfg["cpu_batch_size"] = env_int(
        "CPU_BATCH_SIZE", int(cfg.get("cpu_batch_size", 100000))
    )
    cfg["worker_start_delay"] = float(
        os.getenv("WORKER_START_DELAY", cfg.get("worker_start_delay", 0))
    )

    token = resolve_token(cfg)
    cfg["token_path"] = token["path"]
    cfg["token_label"] = token["label"]
    cfg["workers"] = max(1, int(cfg["workers"]))
    cfg["auto_send_threshold"] = max(0, int(cfg["auto_send_threshold"]))
    cfg["cpu_batch_size"] = max(1000, int(cfg["cpu_batch_size"]))
    return cfg


def generate_wallets(count):
    wallets = []
    for i in range(count):
        pk = secrets.token_bytes(32)
        pub = PrivateKey(pk).public_key.format(compressed=True)[1:].hex()
        wallets.append({"id": i, "private_key": pk.hex(), "public_key": pub})
    return wallets


def load_wallets(count):
    raw_b64 = os.getenv("WALLETS_JSON_B64")
    raw_json = os.getenv("WALLETS_JSON")

    if raw_b64:
        wallets = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
    elif raw_json:
        wallets = json.loads(raw_json)
    elif os.path.exists(WALLETS_PATH):
        wallets = read_json(WALLETS_PATH, [])
    elif os.getenv("AUTO_GENERATE_WALLETS", "1") != "0":
        wallets = generate_wallets(count)
        try:
            with open(WALLETS_PATH, "w", encoding="utf-8") as f:
                json.dump(wallets, f, indent=2)
        except OSError as exc:
            add_log(f"wallets generated in memory only: {exc}")
        add_log(f"generated {len(wallets)} runtime wallets")
    else:
        wallets = []

    valid = []
    for i, wallet in enumerate(wallets):
        pk = str(wallet.get("private_key", "")).strip().lower()
        if len(pk) == 64:
            item = dict(wallet)
            item["id"] = item.get("id", i)
            item["private_key"] = pk
            valid.append(item)
    return valid


_pub_cache = {}


def pub_of(pk):
    key = pk.hex()
    if key not in _pub_cache:
        _pub_cache[key] = PrivateKey(pk).public_key.format(compressed=True)[1:].hex()
    return _pub_cache[key]


def auth_hdr(pk, pub, url, method, body=None):
    ts = int(time.time())
    tags = [["u", url], ["method", method]]
    if body:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])
    ser = json.dumps([0, pub, ts, 27235, tags, ""], separators=(",", ":"))
    eid = hashlib.sha256(ser.encode()).hexdigest()
    sig = PrivateKey(pk).sign_schnorr(bytes.fromhex(eid)).hex()
    ev = json.dumps(
        {
            "id": eid,
            "pubkey": pub,
            "created_at": ts,
            "kind": 27235,
            "tags": tags,
            "content": "",
            "sig": sig,
        }
    )
    return "Nostr " + base64.b64encode(ev.encode()).decode()


def mk_session():
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=4,
        pool_maxsize=8,
        max_retries=Retry(total=1, backoff_factor=0.2),
    )
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 Railway RPOW Web Miner",
            "Accept": "application/json",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
            "Connection": "keep-alive",
        }
    )
    return session


class API:
    def __init__(self, pk, token_path):
        self.pk = pk
        self.pub = pub_of(pk)
        self.s = mk_session()
        self.n = 0
        self.token_path = token_path
        self.last_error = ""

    def request(self, method, path, body=None):
        raw = json.dumps(body).encode() if body else None
        url = f"{ORIGIN}/{self.token_path}{path}"
        auth_url = f"{ORIGIN}{path}"
        headers = {"Authorization": auth_hdr(self.pk, self.pub, auth_url, method, raw)}
        if raw:
            headers["Content-Type"] = "application/json"
        try:
            if method == "POST":
                response = self.s.post(url, data=raw, headers=headers, timeout=8)
            else:
                response = self.s.get(url, headers=headers, timeout=8)
            try:
                result = response.json()
            except ValueError:
                result = {"error": response.text[:200]}
            if response.status_code != 200:
                self.last_error = (
                    result.get("message") or result.get("error") or str(response.status_code)
                )
                return None
            self.last_error = ""
            return result
        except Exception as exc:
            self.last_error = type(exc).__name__
            return None
        finally:
            self.n += 1
            if self.n >= 500:
                self.n = 0
                try:
                    self.s.close()
                except Exception:
                    pass
                self.s = mk_session()

    def post(self, path, body=None):
        return self.request("POST", path, body)

    def get(self, path):
        return self.request("GET", path)


def has_trailing_zero_bits(digest, difficulty):
    full_bytes = difficulty // 8
    remaining_bits = difficulty % 8

    if full_bytes and digest[-full_bytes:] != (b"\x00" * full_bytes):
        return False
    if not remaining_bits:
        return True

    check_index = -full_bytes - 1 if full_bytes else -1
    mask = (1 << remaining_bits) - 1
    return (digest[check_index] & mask) == 0


def mine_cpu(prefix_hex, difficulty, batch_size, stop):
    prefix = bytes.fromhex(prefix_hex)
    pack_nonce = struct.Struct("<Q").pack
    sha256 = hashlib.sha256
    nonce = 0
    hashes = 0
    started = time.time()
    difficulty = int(difficulty)

    while nonce < 0xFFFFFFFFFFFFFFFF and not stop.is_set():
        end = min(nonce + batch_size, 0xFFFFFFFFFFFFFFFF)
        for current in range(nonce, end):
            digest = sha256(prefix + pack_nonce(current)).digest()
            hashes += 1
            if has_trailing_zero_bits(digest, difficulty):
                return str(current), time.time() - started, hashes
        nonce = end
    return None, time.time() - started, hashes


def drain_balance(api, recipient_pubkey):
    if not recipient_pubkey:
        return Decimal(0)
    me = api.get("/me")
    if not me:
        return None
    base_units = balance_base_units_from_me(me)
    if base_units is None:
        return None
    if as_decimal(base_units) <= 0:
        return Decimal(0)
    amount = float(amount_from_base_units(base_units))
    result = api.post(
        "/send",
        {
            "recipient_pubkey": recipient_pubkey,
            "amount": amount,
            "idempotency_key": uuid.uuid4().hex,
        },
    )
    if not result:
        return None
    sent_base_units = result.get("transferred_base_units")
    if sent_base_units is not None:
        return as_decimal(amount_from_base_units(sent_base_units))
    return as_decimal(str(amount))


def set_worker(index, **values):
    with state_lock:
        if index < len(app_state["workers"]):
            app_state["workers"][index].update(values)
            app_state["workers"][index]["updated_at"] = int(time.time())


class MinerThread(threading.Thread):
    def __init__(self, index, wallet, cfg):
        super().__init__(daemon=True)
        self.index = index
        self.wallet = wallet
        self.cfg = cfg
        self.api = API(bytes.fromhex(wallet["private_key"]), cfg["token_path"])
        self.mined = 0
        self.sent = Decimal(0)
        self.fails = 0

    def run(self):
        pub = str(self.wallet.get("public_key") or self.api.pub)
        set_worker(self.index, status="ready", pubkey=pub[:10] + "..." + pub[-6:])

        while not stop_event.is_set():
            set_worker(self.index, status="challenge")
            challenge = self.api.post("/challenge")
            if not challenge:
                self.fails += 1
                set_worker(self.index, status="wait", error=self.api.last_error)
                time.sleep(min(self.fails * 2, 15))
                continue

            self.fails = 0
            difficulty = int(challenge["difficulty_bits"])
            set_worker(self.index, status=f"mining d{difficulty}", error="")
            nonce, seconds, hashes = mine_cpu(
                challenge["nonce_prefix"],
                difficulty,
                self.cfg["cpu_batch_size"],
                stop_event,
            )
            if stop_event.is_set():
                break
            if not nonce:
                set_worker(self.index, status="no-solution")
                continue

            mhs = hashes / max(seconds, 0.001) / 1_000_000
            set_worker(self.index, status="mint", mhs=round(mhs, 3), hashes=hashes)
            minted = self.api.post(
                "/mint",
                {
                    "challenge_id": challenge["challenge_id"],
                    "solution_nonce": nonce,
                },
            )
            if not minted:
                set_worker(self.index, status="mint-error", error=self.api.last_error)
                time.sleep(1)
                continue

            self.mined += 1
            with state_lock:
                app_state["total_mined"] += 1
            set_worker(self.index, status="minted", mined=self.mined)

            threshold = self.cfg["auto_send_threshold"]
            if threshold and self.mined % threshold == 0:
                set_worker(self.index, status="send")
                sent = drain_balance(self.api, self.cfg.get("main_wallet", ""))
                if sent is None:
                    set_worker(self.index, status="send-error", error=self.api.last_error)
                    time.sleep(1)
                    continue
                self.sent += sent
                with state_lock:
                    total_sent = as_decimal(app_state["total_sent"]) + sent
                    app_state["total_sent"] = fmt_amount(total_sent)
                set_worker(self.index, status="sent", sent=fmt_amount(self.sent))

        set_worker(self.index, status="stopped")


def start_miner():
    global threads
    with state_lock:
        if app_state["running"] or app_state["stopping"]:
            return True, "already running"

    try:
        cfg = load_config()
        wallets = load_wallets(cfg["workers"])
        if not wallets:
            raise RuntimeError("no wallets available")
        worker_count = min(cfg["workers"], len(wallets))
        cfg["workers"] = worker_count
    except Exception as exc:
        with state_lock:
            app_state["last_error"] = str(exc)
        add_log(f"start failed: {exc}")
        return False, str(exc)

    stop_event.clear()
    worker_rows = [
        {
            "id": i,
            "status": "boot",
            "mined": 0,
            "sent": "0",
            "mhs": 0,
            "error": "",
            "updated_at": int(time.time()),
        }
        for i in range(worker_count)
    ]

    with state_lock:
        app_state.update(
            {
                "running": True,
                "stopping": False,
                "started_at": int(time.time()),
                "token": cfg["token_label"],
                "token_path": cfg["token_path"],
                "workers_configured": cfg["workers"],
                "workers_active": worker_count,
                "total_mined": 0,
                "total_sent": "0",
                "last_error": "",
                "workers": worker_rows,
            }
        )

    threads = []
    for i in range(worker_count):
        thread = MinerThread(i, wallets[i], cfg)
        threads.append(thread)
        thread.start()
        if cfg["worker_start_delay"] > 0:
            time.sleep(cfg["worker_start_delay"])

    add_log(f"started {worker_count} web-mode miner threads for {cfg['token_label']}")
    return True, "started"


def stop_miner():
    with state_lock:
        if not app_state["running"]:
            return True, "not running"
        app_state["stopping"] = True
    stop_event.set()
    add_log("stop requested")
    return True, "stopping"


def refresh_runtime_state():
    global threads
    with state_lock:
        if not threads:
            return
        alive = [thread for thread in threads if thread.is_alive()]
        if app_state["running"] and not alive:
            app_state["running"] = False
            app_state["stopping"] = False
            app_state["workers_active"] = 0
        threads = alive


def snapshot_state():
    refresh_runtime_state()
    with state_lock:
        data = json.loads(json.dumps(app_state))
    if data["started_at"]:
        data["uptime_seconds"] = int(time.time()) - int(data["started_at"])
    else:
        data["uptime_seconds"] = 0
    return data


@app.get("/")
def index():
    data = snapshot_state()
    rows = []
    for worker in data["workers"]:
        rows.append(
            "<tr>"
            f"<td>{worker.get('id')}</td>"
            f"<td>{html.escape(str(worker.get('status', '')))}</td>"
            f"<td>{worker.get('mined', 0)}</td>"
            f"<td>{html.escape(str(worker.get('sent', '0')))}</td>"
            f"<td>{worker.get('mhs', 0)}</td>"
            f"<td>{html.escape(str(worker.get('error', '')))}</td>"
            "</tr>"
        )
    logs = "".join(
        f"<li>{item['ts']} - {html.escape(item['message'])}</li>"
        for item in reversed(data["log"][-12:])
    )
    control = (
        '<form method="post" action="/stop"><button>stop</button></form>'
        if data["running"]
        else '<form method="post" action="/start"><button>start</button></form>'
    )
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>RPOW Railway Web Miner</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; background: #0b0d10; color: #e8edf2; margin: 24px; }}
    a {{ color: #86efac; }}
    .bar {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 16px 0; }}
    .pill {{ border: 1px solid #2b3542; padding: 6px 10px; border-radius: 6px; background: #111821; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    th, td {{ border-bottom: 1px solid #24303d; padding: 8px; text-align: left; font-size: 13px; }}
    button {{ background: #86efac; color: #07110b; border: 0; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 700; }}
    .muted {{ color: #8a97a8; }}
  </style>
</head>
<body>
  <h1>RPOW Railway Web Miner</h1>
  <div class="bar">
    <span class="pill">mode: web</span>
    <span class="pill">running: {data["running"]}</span>
    <span class="pill">token: {html.escape(str(data["token"]))}</span>
    <span class="pill">workers: {data["workers_active"]}</span>
    <span class="pill">mined: {data["total_mined"]}</span>
    <span class="pill">sent: {html.escape(str(data["total_sent"]))}</span>
    <span class="pill">uptime: {data["uptime_seconds"]}s</span>
  </div>
  {control}
  <p class="muted">Health: <a href="/healthz">/healthz</a> | JSON: <a href="/status">/status</a></p>
  <table>
    <thead><tr><th>#</th><th>status</th><th>mined</th><th>sent</th><th>MH/s</th><th>error</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <h2>log</h2>
  <ul>{logs}</ul>
</body>
</html>"""
    return Response(body, mimetype="text/html")


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "mode": "web", "running": snapshot_state()["running"]})


@app.get("/status")
def status():
    return jsonify(snapshot_state())


@app.post("/start")
def start_route():
    start_miner()
    if request.accept_mimetypes.accept_json:
        return jsonify(snapshot_state())
    return redirect(url_for("index"))


@app.post("/stop")
def stop_route():
    stop_miner()
    if request.accept_mimetypes.accept_json:
        return jsonify(snapshot_state())
    return redirect(url_for("index"))


if os.getenv("AUTO_START", "1") != "0":
    start_miner()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
