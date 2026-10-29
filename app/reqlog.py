"""Request logging for the honeypot.

Every HTTP request becomes one JSON line in a per-day file (UTC):
    <LOG_DIR>/requests-YYYY-MM-DD.jsonl

Design rules:
- Log everything the client sent: method, path, raw query, every header in the order
  received from the edge server, and the body (first BODY_KEEP bytes, plus its full length
  and SHA-256).
- Facts that only the edge server (Caddy) knows -- client IP, TLS version, ALPN, SNI --
  arrive in X-HP-* headers that Caddy sets. They are moved into an "edge" object and
  removed from the client header list, so the two are never confused. The app listens on
  127.0.0.1 only, so these headers can only come from Caddy.
- Never let logging break a response, and never let one huge request make a huge line.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = 1
BODY_READ_LIMIT = 64 * 1024     # read at most this much of a request body
BODY_KEEP = 8 * 1024            # store at most this much of it in the log
HEADER_VALUE_LIMIT = 8 * 1024   # truncate any single header value beyond this
HEADER_COUNT_LIMIT = 200        # keep at most this many headers

# Headers Caddy injects (lower-case). Values go to the "edge" object.
EDGE_HEADERS = {
    "x-hp-client-ip": "client_ip",
    "x-hp-client-port": "client_port",
    "x-hp-orig-xff": "orig_x_forwarded_for",
    "x-hp-proto": "http_version",
    "x-hp-tls-version": "tls_version",
    "x-hp-tls-cipher": "tls_cipher",
    "x-hp-tls-alpn": "tls_alpn",
    "x-hp-tls-sni": "tls_sni",
    "x-hp-tls-resumed": "tls_resumed",
    "x-hp-edge": "edge_name",
}
# Headers Caddy's reverse proxy adds or rewrites itself. The client's own
# X-Forwarded-For is preserved separately (x-hp-orig-xff); these are dropped.
PROXY_ADDED = {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "via"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _decode(b: bytes) -> str:
    return b.decode("latin-1")  # HTTP header bytes; latin-1 is lossless


DEFAULT_DAILY_CAP = 500 * 1024 * 1024  # bytes per day file before lines are shortened


def capped_record(record: dict) -> dict:
    """The short form written once a day's file passes the cap: enough to count and
    attribute the request, without headers or body."""
    return {
        "v": record.get("v"),
        "ts": record.get("ts"),
        "id": record.get("id"),
        "capped": True,
        "edge": {k: record.get("edge", {}).get(k) for k in ("client_ip", "edge_name")},
        "method": record.get("method"),
        "path": (record.get("path") or "")[:512],
        "status": record.get("status"),
    }


class RequestLogger:
    """Appends JSON lines to one file per UTC day.

    Once a day's file passes `daily_cap` bytes, further lines that day are written in the
    short form above, so a flood of requests cannot fill the disk with full records.
    Set HP_MAX_DAILY_LOG_BYTES to change the cap.
    """

    def __init__(self, log_dir: str, daily_cap: int | None = None):
        self.log_dir = log_dir
        env_cap = os.environ.get("HP_MAX_DAILY_LOG_BYTES")
        self.daily_cap = daily_cap if daily_cap is not None else int(env_cap or DEFAULT_DAILY_CAP)
        self._lock = threading.Lock()

    def path_for(self, ts: datetime) -> str:
        return os.path.join(self.log_dir, f"requests-{ts.strftime('%Y-%m-%d')}.jsonl")

    def write(self, record: dict) -> None:
        ts = datetime.fromisoformat(record["ts"])
        with self._lock:
            os.makedirs(self.log_dir, exist_ok=True)
            path = self.path_for(ts)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            if size >= self.daily_cap:
                record = capped_record(record)
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())


def split_headers(raw: list[tuple[bytes, bytes]]) -> tuple[list[list[str]], dict, bool]:
    """Return (client headers in order, edge facts, truncated flag)."""
    client: list[list[str]] = []
    edge: dict = {}
    truncated = False
    for name_b, value_b in raw:
        name = _decode(name_b)
        value = _decode(value_b)
        low = name.lower()
        if low in EDGE_HEADERS:
            if value != "":
                edge[EDGE_HEADERS[low]] = value
            continue
        if low.startswith("x-hp-"):
            continue  # never log unknown internal headers as client data
        if low in PROXY_ADDED:
            continue
        if len(client) >= HEADER_COUNT_LIMIT:
            truncated = True
            continue
        if len(value) > HEADER_VALUE_LIMIT:
            value = value[:HEADER_VALUE_LIMIT]
            truncated = True
        client.append([name, value])
    return client, edge, truncated


def body_record(chunks: list[bytes], total_len: int, overflow: bool) -> dict | None:
    if total_len == 0:
        return None
    data = b"".join(chunks)
    kept = data[:BODY_KEEP]
    rec = {
        "length": total_len,
        "read_bytes": len(data),
        "sha256_of_read": hashlib.sha256(data).hexdigest(),
        "kept_b64": base64.b64encode(kept).decode("ascii"),
        "kept_truncated": len(data) > BODY_KEEP,
        "read_truncated": overflow,
    }
    try:
        rec["kept_text"] = kept.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return rec


class LoggingMiddleware:
    """Pure ASGI middleware: reads the body up front, replays it, logs after response."""

    def __init__(self, app, logger: RequestLogger):
        self.app = app
        self.logger = logger

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        t0 = time.perf_counter()
        ts = _utc_now()
        req_id = uuid.uuid4().hex

        # Read the request body (bounded), keep draining past the limit.
        chunks: list[bytes] = []
        total = 0
        overflow = False
        more = True
        disconnected = False
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            body = message.get("body", b"")
            total += len(body)
            if not overflow:
                room = BODY_READ_LIMIT - sum(len(c) for c in chunks)
                if len(body) > room:
                    chunks.append(body[:room])
                    overflow = True
                else:
                    chunks.append(body)
            more = message.get("more_body", False)

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return {"type": "http.disconnect"}

        status = None
        resp_bytes = 0

        async def capture_send(message):
            nonlocal status, resp_bytes
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                resp_bytes += len(message.get("body", b""))
            await send(message)

        error = None
        try:
            await self.app(scope, replay_receive, capture_send)
        except Exception as e:  # noqa: BLE001 - logged, then re-raised
            error = repr(e)[:500]
            raise
        finally:
            try:
                headers, edge, truncated = split_headers(scope.get("headers", []))
                record = {
                    "v": SCHEMA_VERSION,
                    "ts": ts.isoformat(timespec="microseconds"),
                    "id": req_id,
                    "edge": edge,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "raw_path": _decode(scope.get("raw_path") or b""),
                    "query": _decode(scope.get("query_string") or b""),
                    "asgi_http_version": scope.get("http_version"),
                    "headers": headers,
                    "headers_truncated": truncated,
                    "body": body_record(chunks, total, overflow),
                    "client_disconnected_early": disconnected,
                    "status": status,
                    "resp_bytes": resp_bytes,
                    "duration_ms": round((time.perf_counter() - t0) * 1000, 3),
                }
                if error:
                    record["error"] = error
                if "client_ip" not in edge and scope.get("client"):
                    # Direct connection (no edge server): local testing only.
                    record["edge"]["socket_peer"] = scope["client"][0]
                self.logger.write(record)
            except Exception:  # noqa: BLE001 - logging must never break serving
                pass
