#!/usr/bin/env python3
"""
bridge-mqtt-multi-longfast — Meshtastic channel republisher between two MQTT servers.

Problem it solves: a Meshtastic node connects to only ONE MQTT server, and the
public LongFast of each server is the SAME channel (name "LongFast", public PSK
AQ==), differing only by the topic ROOT. That prevents "being on both publics AND
choosing per message" from a single device.

Solution: the device uses a 2nd channel with a different LOCAL name (e.g.
LongFastCO) but the SAME public PSK (AQ==). This service:
  - reads that local channel's packets on the LOCAL broker,
  - rewrites only the channel-hash byte (-> LongFast hash) and channel_id
    (-> "LongFast"), WITHOUT touching the payload (already encrypted with the
    right key),
  - republishes to the public LongFast of the REMOTE server (remapped root).
And the reverse, to receive.

Because the PSK is the same (AQ==), there is no re-encryption: just one protobuf
field swap + the topic. Loops are avoided by deduplicating on packet.id.

A minimal HTTP status page is served on STATUS_PORT (connection state + counters).
"""
import os
import sys
import time
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import paho.mqtt.client as mqtt

# Meshtastic protobufs (new path; fall back to older layout)
try:
    from meshtastic.protobuf import mqtt_pb2
except ImportError:  # pragma: no cover
    from meshtastic import mqtt_pb2  # type: ignore

# ---------------------------------------------------------------------------
# Config (via env)
# ---------------------------------------------------------------------------
def env(key, default=None, required=False):
    v = os.environ.get(key, default)
    if required and (v is None or v == ""):
        logging.error("Missing required environment variable: %s", key)
        sys.exit(1)
    return v

LOCAL_HOST = env("LOCAL_MQTT_HOST", "127.0.0.1")
LOCAL_PORT = int(env("LOCAL_MQTT_PORT", "1883"))
LOCAL_USER = env("LOCAL_MQTT_USER", "")
LOCAL_PASS = env("LOCAL_MQTT_PASS", "")
LOCAL_ROOT = env("LOCAL_ROOT", "meshdev")
LOCAL_CHANNEL = env("LOCAL_CHANNEL", "LongFastCO")

REMOTE_HOST = env("REMOTE_MQTT_HOST", "mqtt.meshtastic.org")
REMOTE_PORT = int(env("REMOTE_MQTT_PORT", "1883"))
REMOTE_USER = env("REMOTE_MQTT_USER", "meshdev")
REMOTE_PASS = env("REMOTE_MQTT_PASS", "large4cats")
REMOTE_ROOT = env("REMOTE_ROOT", "msh/US/CO")
REMOTE_CHANNEL = env("REMOTE_CHANNEL", "LongFast")

STATUS_PORT = int(env("STATUS_PORT", "8080"))
LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bridge")

# ---------------------------------------------------------------------------
# Runtime stats (exposed by the status server). No secrets here.
# ---------------------------------------------------------------------------
STATS = {
    "local_connected": False,
    "remote_connected": False,
    "out_relayed": 0,
    "in_relayed": 0,
    "errors": 0,
    "started": time.time(),
}

# ---------------------------------------------------------------------------
# Channel hash (firmware algorithm: XOR of all name bytes XOR the key bytes).
# Default expanded key (PSK "AQ==" / index 1). Checks out: LongFast -> 8.
# ---------------------------------------------------------------------------
DEFAULT_KEY = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

def channel_hash(name: str) -> int:
    h = 0
    for c in name.encode("utf-8"):
        h ^= c
    for b in DEFAULT_KEY:
        h ^= b
    return h & 0xFF

LOCAL_HASH = channel_hash(LOCAL_CHANNEL)    # e.g. LongFastCO -> 4
REMOTE_HASH = channel_hash(REMOTE_CHANNEL)  # e.g. LongFast   -> 8

# Topics
LOCAL_SUB = f"{LOCAL_ROOT}/2/e/{LOCAL_CHANNEL}/#"
REMOTE_SUB = f"{REMOTE_ROOT}/2/e/{REMOTE_CHANNEL}/#"

# ---------------------------------------------------------------------------
# Dedup for loop-prevention (recently seen packet ids).
# The immediate echo (our own publish coming back through the subscription) is
# always caught: we just added the id. clear() only drops old ids, outside the
# loop window — harmless.
# ---------------------------------------------------------------------------
_seen = set()

def already_seen(pid: int) -> bool:
    if pid in _seen:
        return True
    _seen.add(pid)
    if len(_seen) > 4000:
        _seen.clear()
        _seen.add(pid)
    return False

def gateway_from_topic(topic: str) -> str:
    """Last topic segment is the gateway id (e.g. !f6709dc8)."""
    return topic.rsplit("/", 1)[-1]

# ---------------------------------------------------------------------------
# Republishing
# ---------------------------------------------------------------------------
def repackage(payload: bytes, new_hash: int, new_channel_id: str):
    """Rewrite packet.channel + channel_id of a ServiceEnvelope. Returns
    (reserialized_bytes, packet_id) or (None, None) if not applicable."""
    se = mqtt_pb2.ServiceEnvelope()
    se.ParseFromString(payload)
    if not se.HasField("packet"):
        return None, None
    pkt = se.packet
    # only makes sense for encrypted channel packets
    if not pkt.HasField("encrypted") or len(pkt.encrypted) == 0:
        return None, None
    pid = pkt.id
    pkt.channel = new_hash
    se.channel_id = new_channel_id
    return se.SerializeToString(), pid

def make_on_message(direction, dst_client, dst_root, dst_channel, new_hash, new_channel_id):
    def on_message(client, userdata, msg):
        try:
            new_payload, pid = repackage(msg.payload, new_hash, new_channel_id)
            if new_payload is None:
                return
            if pid and already_seen(pid):
                log.debug("[%s] skip dup id=0x%x", direction, pid)
                return
            gw = gateway_from_topic(msg.topic)
            dst_topic = f"{dst_root}/2/e/{dst_channel}/{gw}"
            dst_client.publish(dst_topic, new_payload, qos=0)
            STATS[f"{direction}_relayed"] += 1
            log.info("[%s] id=0x%x %s -> %s (hash->%d)",
                     direction, pid or 0, msg.topic, dst_topic, new_hash)
        except Exception as e:
            STATS["errors"] += 1
            log.warning("[%s] error handling msg from %s: %s", direction, msg.topic, e)
    return on_message

def build_client(name, host, port, user, password):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"bridge-{name}")
    if user:
        c.username_pw_set(user, password)
    c.reconnect_delay_set(min_delay=1, max_delay=30)

    def on_connect(client, userdata, flags, reason_code, properties):
        STATS[f"{name}_connected"] = (reason_code == 0 or str(reason_code) == "Success")
        log.info("[%s] connected to %s:%d (rc=%s)", name, host, port, reason_code)

    def on_disconnect(client, userdata, flags, reason_code, properties):
        STATS[f"{name}_connected"] = False
        log.warning("[%s] disconnected from %s:%d (rc=%s)", name, host, port, reason_code)

    c.on_connect = on_connect
    c.on_disconnect = on_disconnect
    return c

# ---------------------------------------------------------------------------
# Minimal HTTP status page (satisfies Umbrel app_proxy + useful visibility).
# ---------------------------------------------------------------------------
def _status_payload():
    up = int(time.time() - STATS["started"])
    return {
        "local": {"host": LOCAL_HOST, "root": LOCAL_ROOT, "channel": LOCAL_CHANNEL,
                  "hash": LOCAL_HASH, "connected": STATS["local_connected"]},
        "remote": {"host": REMOTE_HOST, "root": REMOTE_ROOT, "channel": REMOTE_CHANNEL,
                   "hash": REMOTE_HASH, "connected": STATS["remote_connected"]},
        "relayed_out": STATS["out_relayed"],
        "relayed_in": STATS["in_relayed"],
        "errors": STATS["errors"],
        "uptime_seconds": up,
    }

class StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence access logs
        pass

    def do_GET(self):
        s = _status_payload()
        if self.path.rstrip("/") == "/status.json":
            body = json.dumps(s, indent=2).encode()
            ctype = "application/json"
        else:
            def dot(ok):
                return ('<span style="color:#2ecc71">●</span>' if ok
                        else '<span style="color:#e74c3c">●</span>')
            body = f"""<!doctype html><html><head><meta charset=utf-8>
<title>bridge-mqtt-multi-longfast</title>
<meta http-equiv=refresh content=5>
<style>body{{font-family:system-ui,sans-serif;background:#1a1a2e;color:#eee;max-width:640px;margin:40px auto;padding:0 16px}}
h1{{font-size:18px}} table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:6px 10px;border-bottom:1px solid #333}}
.k{{color:#9aa}}</style></head><body>
<h1>bridge-mqtt-multi-longfast</h1>
<table>
<tr><th>Side</th><th>Connected</th><th>Host</th><th>Root</th><th>Channel</th><th>Hash</th></tr>
<tr><td>local</td><td>{dot(s['local']['connected'])}</td><td>{s['local']['host']}</td><td>{s['local']['root']}</td><td>{s['local']['channel']}</td><td>{s['local']['hash']}</td></tr>
<tr><td>remote</td><td>{dot(s['remote']['connected'])}</td><td>{s['remote']['host']}</td><td>{s['remote']['root']}</td><td>{s['remote']['channel']}</td><td>{s['remote']['hash']}</td></tr>
</table>
<p><span class=k>relayed out → remote:</span> {s['relayed_out']}<br>
<span class=k>relayed in → local:</span> {s['relayed_in']}<br>
<span class=k>errors:</span> {s['errors']} &nbsp; <span class=k>uptime:</span> {s['uptime_seconds']}s</p>
<p class=k><a href="/status.json" style="color:#6cf">status.json</a></p>
</body></html>""".encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def start_status_server():
    srv = ThreadingHTTPServer(("0.0.0.0", STATUS_PORT), StatusHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("status server listening on :%d", STATUS_PORT)

# ---------------------------------------------------------------------------
def main():
    log.info("bridge-mqtt-multi-longfast starting")
    log.info("LOCAL  %s:%d root=%s channel=%s (hash=%d)  sub=%s",
             LOCAL_HOST, LOCAL_PORT, LOCAL_ROOT, LOCAL_CHANNEL, LOCAL_HASH, LOCAL_SUB)
    log.info("REMOTE %s:%d root=%s channel=%s (hash=%d)  sub=%s",
             REMOTE_HOST, REMOTE_PORT, REMOTE_ROOT, REMOTE_CHANNEL, REMOTE_HASH, REMOTE_SUB)

    start_status_server()

    local = build_client("local", LOCAL_HOST, LOCAL_PORT, LOCAL_USER, LOCAL_PASS)
    remote = build_client("remote", REMOTE_HOST, REMOTE_PORT, REMOTE_USER, REMOTE_PASS)

    # LOCAL (LongFastCO) -> REMOTE (public LongFast): rewrite hash -> REMOTE_HASH
    local.on_message = make_on_message(
        "out", remote, REMOTE_ROOT, REMOTE_CHANNEL, REMOTE_HASH, REMOTE_CHANNEL)
    # REMOTE (LongFast) -> LOCAL (LongFastCO): rewrite hash -> LOCAL_HASH
    remote.on_message = make_on_message(
        "in", local, LOCAL_ROOT, LOCAL_CHANNEL, LOCAL_HASH, LOCAL_CHANNEL)

    def sub_local(client, *a):
        client.subscribe(LOCAL_SUB, qos=0)
        log.info("[local] subscribed to %s", LOCAL_SUB)
    def sub_remote(client, *a):
        client.subscribe(REMOTE_SUB, qos=0)
        log.info("[remote] subscribed to %s", REMOTE_SUB)
    # chain the subscription onto on_connect
    _lc = local.on_connect
    _rc = remote.on_connect
    local.on_connect = lambda c, u, f, rc, p: (_lc(c, u, f, rc, p), sub_local(c))
    remote.on_connect = lambda c, u, f, rc, p: (_rc(c, u, f, rc, p), sub_remote(c))

    local.connect_async(LOCAL_HOST, LOCAL_PORT, keepalive=60)
    remote.connect_async(REMOTE_HOST, REMOTE_PORT, keepalive=60)
    local.loop_start()
    remote.loop_start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        local.loop_stop()
        remote.loop_stop()

if __name__ == "__main__":
    main()
