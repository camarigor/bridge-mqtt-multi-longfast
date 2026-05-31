#!/usr/bin/env python3
"""
bridge-mqtt-multi-longfast — Meshtastic channel router across multiple MQTT servers.

A Meshtastic node connects to only ONE MQTT server. To be on the public LongFast
of several servers (each is the same channel "LongFast" + public PSK AQ==,
differing only by topic root) AND choose per message which one, the device uses a
distinct local channel name per destination (e.g. LongFast, LongFastCO) — all
published to ONE local broker (mosquitto).

This service is the single router: it connects to the local broker and to each
remote public server, and for every configured bridge it relays a local channel
to/from a remote channel, rewriting the channel-hash byte + channel_id. The PSK
is the same AQ==, so no re-encryption is needed.

Some remotes' ecosystems publish PLAINTEXT (decoded) packets rather than
encrypted ones — e.g. a regional mqtt.meshtastic.org root where gateways uplink
already-decoded packets. For those, set BRIDGE{N}_REMOTE_DECODED=true: the app
decrypts outbound packets to plaintext before publishing (so the remote's tools
read them), and relays the remote's decoded packets inbound (the local device
accepts both encrypted and plaintext downlink). Loops are avoided by packet-id
dedup.

Architecture:  device -> mosquitto (local) <-> this app -> {meshbrasil, US/CO, ...}

Config (env): shared LOCAL_MQTT_* + numbered BRIDGE{N}_* (see README). A legacy
single-bridge config via REMOTE_MQTT_*/LOCAL_CHANNEL is still accepted.
A status page is served on STATUS_PORT.
"""
import os
import sys
import time
import json
import uuid
import struct
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import paho.mqtt.client as mqtt

try:
    from meshtastic.protobuf import mqtt_pb2, mesh_pb2
except ImportError:  # pragma: no cover
    from meshtastic import mqtt_pb2, mesh_pb2  # type: ignore

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def env(key, default=None, required=False):
    v = os.environ.get(key, default)
    if required and (v is None or v == ""):
        logging.error("Missing required environment variable: %s", key)
        sys.exit(1)
    return v

def env_bool(key, default=False):
    return str(os.environ.get(key, str(default))).strip().lower() in ("1", "true", "yes", "on")

# Shared local broker
LOCAL_HOST = env("LOCAL_MQTT_HOST", "127.0.0.1")
LOCAL_PORT = int(env("LOCAL_MQTT_PORT", "1883"))
LOCAL_USER = env("LOCAL_MQTT_USER", "")
LOCAL_PASS = env("LOCAL_MQTT_PASS", "")
LOCAL_ROOT = env("LOCAL_ROOT", "meshdev")

STATUS_PORT = int(env("STATUS_PORT", "8080"))
LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bridge")

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


def decrypt_to_data(pkt):
    """Decrypt an AQ==-channel-encrypted MeshPacket into a plaintext Data.

    Meshtastic uses AES-CTR with a 16-byte nonce = packet_id (u64 LE) +
    from (u32 LE) + 4 zero bytes, and the expanded default key for PSK AQ==.
    Returns the Data, or None if it doesn't decode (foreign key / PKI packet).
    """
    try:
        frm = getattr(pkt, "from")
        # The CTR nonce is the Meshtastic protocol-defined value (packet_id + from
        # node), NOT a random IV. It MUST be deterministic so any receiver holding
        # the channel PSK derives the identical nonce to decrypt. Using os.urandom
        # here would break interoperability — hence the scanner hit is a false
        # positive on this protocol-mandated construction.
        nonce = struct.pack("<Q", pkt.id) + struct.pack("<I", frm) + b"\x00\x00\x00\x00"  # nosemgrep
        dec = Cipher(algorithms.AES(DEFAULT_KEY), modes.CTR(nonce)).decryptor()  # nosemgrep
        raw = dec.update(pkt.encrypted) + dec.finalize()
        d = mesh_pb2.Data()
        d.ParseFromString(raw)
        if d.portnum == 0:  # PORTNUM_UNKNOWN -> garbage (wrong key / PKI packet)
            return None
        return d
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Bridge definitions (one local channel <-> one remote channel/server each)
# ---------------------------------------------------------------------------
def load_bridges():
    bridges = []
    i = 1
    while os.environ.get(f"BRIDGE{i}_REMOTE_HOST"):
        p = f"BRIDGE{i}_"
        lc = env(p + "LOCAL_CHANNEL", required=True)
        rc = env(p + "REMOTE_CHANNEL", "LongFast")
        bridges.append({
            "name": env(p + "NAME", f"bridge{i}"),
            "local_channel": lc, "local_hash": channel_hash(lc),
            "remote_host": env(p + "REMOTE_HOST"),
            "remote_port": int(env(p + "REMOTE_PORT", "1883")),
            "remote_user": env(p + "REMOTE_USER", ""),
            "remote_pass": env(p + "REMOTE_PASS", ""),
            "remote_root": env(p + "REMOTE_ROOT", "msh"),
            "remote_channel": rc, "remote_hash": channel_hash(rc),
            "remote_decoded": env_bool(p + "REMOTE_DECODED", False),
            "connected": False, "out": 0, "in": 0, "client": None,
        })
        i += 1
    # legacy single-bridge fallback (old REMOTE_MQTT_* / LOCAL_CHANNEL config)
    if not bridges and os.environ.get("REMOTE_MQTT_HOST"):
        lc = env("LOCAL_CHANNEL", "LongFastCO"); rc = env("REMOTE_CHANNEL", "LongFast")
        bridges.append({
            "name": env("REMOTE_MQTT_HOST", "remote"),
            "local_channel": lc, "local_hash": channel_hash(lc),
            "remote_host": env("REMOTE_MQTT_HOST"),
            "remote_port": int(env("REMOTE_MQTT_PORT", "1883")),
            "remote_user": env("REMOTE_MQTT_USER", ""),
            "remote_pass": env("REMOTE_MQTT_PASS", ""),
            "remote_root": env("REMOTE_ROOT", "msh/US/CO"),
            "remote_channel": rc, "remote_hash": channel_hash(rc),
            "remote_decoded": env_bool("REMOTE_DECODED", False),
            "connected": False, "out": 0, "in": 0, "client": None,
        })
    return bridges

BRIDGES = load_bridges()
LOCAL_CONNECTED = {"v": False}
ERRORS = {"v": 0}
STARTED = time.time()

# local channel -> bridge (for routing local messages)
CH2BRIDGE = {b["local_channel"]: b for b in BRIDGES}

# ---------------------------------------------------------------------------
# Loop-prevention dedup (recently seen packet ids; shared across bridges)
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

def topic_channel(topic: str) -> str:
    # ".../2/e/<channel>/<gateway>" -> channel is second-to-last segment
    return topic.rsplit("/", 2)[-2]

def topic_gateway(topic: str) -> str:
    return topic.rsplit("/", 1)[-1]

def repackage(payload: bytes, new_hash: int, new_channel_id: str, make_decoded: bool = False):
    """Move a ServiceEnvelope onto a different channel by rewriting packet.channel
    + channel_id. Handles both encrypted and already-plaintext (decoded) packets.

    When make_decoded is set and the packet is encrypted, it is decrypted to
    plaintext (for remotes whose ecosystem publishes decoded packets). Returns
    (reserialized_bytes, packet_id) or (None, None) if not applicable /
    undecryptable."""
    se = mqtt_pb2.ServiceEnvelope()
    se.ParseFromString(payload)
    if not se.HasField("packet"):
        return None, None
    pkt = se.packet
    pid = pkt.id
    if pkt.HasField("encrypted") and len(pkt.encrypted) > 0:
        if make_decoded:
            data = decrypt_to_data(pkt)
            if data is None:
                return None, None  # foreign key / PKI -> can't convert, skip
            pkt.decoded.CopyFrom(data)  # oneof: setting `decoded` clears `encrypted`
    elif pkt.HasField("decoded"):
        pass  # already plaintext -> relay as-is
    else:
        return None, None
    pkt.channel = new_hash
    se.channel_id = new_channel_id
    return se.SerializeToString(), pid

# ---------------------------------------------------------------------------
# Message handlers
# ---------------------------------------------------------------------------
def on_local_message(local_client):
    def handler(client, userdata, msg):
        try:
            b = CH2BRIDGE.get(topic_channel(msg.topic))
            if b is None:
                return
            # outbound: convert to plaintext if the remote speaks decoded
            payload, pid = repackage(msg.payload, b["remote_hash"], b["remote_channel"],
                                     make_decoded=b["remote_decoded"])
            if payload is None:
                return
            if pid and already_seen(pid):
                return
            gw = topic_gateway(msg.topic)
            dst = f"{b['remote_root']}/2/e/{b['remote_channel']}/{gw}"
            b["client"].publish(dst, payload, qos=0)
            b["out"] += 1
            log.info("[%s out] id=0x%x %s -> %s (hash->%d%s)",
                     b["name"], pid or 0, msg.topic, dst, b["remote_hash"],
                     " plain" if b["remote_decoded"] else "")
        except Exception as e:
            ERRORS["v"] += 1
            log.warning("[local] error on %s: %s", msg.topic, e)
    return handler

def on_remote_message(b, local_client):
    def handler(client, userdata, msg):
        try:
            # inbound: relay as-is (the local device accepts both encrypted and
            # plaintext downlink); just move it onto the local channel hash.
            payload, pid = repackage(msg.payload, b["local_hash"], b["local_channel"],
                                     make_decoded=False)
            if payload is None:
                return
            if pid and already_seen(pid):
                return
            gw = topic_gateway(msg.topic)
            dst = f"{LOCAL_ROOT}/2/e/{b['local_channel']}/{gw}"
            local_client.publish(dst, payload, qos=0)
            b["in"] += 1
            log.info("[%s in] id=0x%x %s -> %s (hash->%d)",
                     b["name"], pid or 0, msg.topic, dst, b["local_hash"])
        except Exception as e:
            ERRORS["v"] += 1
            log.warning("[%s in] error on %s: %s", b["name"], msg.topic, e)
    return handler

def make_client(cid, user, password):
    # random suffix so two instances (or an overlapping update) never collide on
    # client_id, which would make the broker kick one of them in a loop.
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{cid}-{uuid.uuid4().hex[:6]}")
    if user:
        c.username_pw_set(user, password)
    c.reconnect_delay_set(min_delay=1, max_delay=30)
    return c

# ---------------------------------------------------------------------------
# Status page
# ---------------------------------------------------------------------------
def status_payload():
    return {
        "local": {"host": LOCAL_HOST, "root": LOCAL_ROOT, "connected": LOCAL_CONNECTED["v"]},
        "bridges": [{
            "name": b["name"], "connected": b["connected"],
            "local_channel": b["local_channel"], "local_hash": b["local_hash"],
            "remote": f"{b['remote_host']} {b['remote_root']}/{b['remote_channel']}",
            "remote_hash": b["remote_hash"], "out": b["out"], "in": b["in"],
            "remote_fmt": "plain" if b["remote_decoded"] else "encrypted",
        } for b in BRIDGES],
        "errors": ERRORS["v"],
        "uptime_seconds": int(time.time() - STARTED),
    }

class StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        s = status_payload()
        if self.path.rstrip("/") == "/status.json":
            body = json.dumps(s, indent=2).encode(); ctype = "application/json"
        else:
            def dot(ok):
                return ('<span style="color:#2ecc71">●</span>' if ok
                        else '<span style="color:#e74c3c">●</span>')
            rows = "".join(
                f"<tr><td>{b['name']}</td><td>{dot(b['connected'])}</td>"
                f"<td>{b['local_channel']} ({b['local_hash']})</td>"
                f"<td>{b['remote']} ({b['remote_hash']}, {b['remote_fmt']})</td>"
                f"<td>{b['out']}</td><td>{b['in']}</td></tr>"
                for b in s["bridges"])
            body = f"""<!doctype html><html><head><meta charset=utf-8>
<title>bridge-mqtt-multi-longfast</title><meta http-equiv=refresh content=5>
<style>body{{font-family:system-ui,sans-serif;background:#1a1a2e;color:#eee;max-width:760px;margin:40px auto;padding:0 16px}}
h1{{font-size:18px}} table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:6px 10px;border-bottom:1px solid #333}}
.k{{color:#9aa}}</style></head><body>
<h1>bridge-mqtt-multi-longfast</h1>
<p class=k>local broker {s['local']['host']} ({s['local']['root']}) {dot(s['local']['connected'])}</p>
<table><tr><th>Bridge</th><th>Conn</th><th>Local channel</th><th>Remote</th><th>out</th><th>in</th></tr>
{rows}</table>
<p class=k>errors: {s['errors']} &nbsp; uptime: {s['uptime_seconds']}s &nbsp;
<a href="/status.json" style="color:#6cf">status.json</a></p>
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
    if not BRIDGES:
        log.error("No bridges configured (set BRIDGE1_REMOTE_HOST etc).")
        sys.exit(1)
    log.info("LOCAL %s:%d root=%s", LOCAL_HOST, LOCAL_PORT, LOCAL_ROOT)
    for b in BRIDGES:
        log.info("BRIDGE %s: local %s(h%d) <-> %s %s/%s(h%d) [%s]", b["name"],
                 b["local_channel"], b["local_hash"], b["remote_host"],
                 b["remote_root"], b["remote_channel"], b["remote_hash"],
                 "plaintext" if b["remote_decoded"] else "encrypted")

    start_status_server()

    local = make_client("bridge-local", LOCAL_USER, LOCAL_PASS)
    local.on_message = on_local_message(local)

    def on_local_connect(c, u, f, rc, props):
        LOCAL_CONNECTED["v"] = (rc == 0 or str(rc) == "Success")
        log.info("[local] connected to %s:%d (rc=%s)", LOCAL_HOST, LOCAL_PORT, rc)
        for b in BRIDGES:
            c.subscribe(f"{LOCAL_ROOT}/2/e/{b['local_channel']}/#", qos=0)
        log.info("[local] subscribed to %d local channel(s)", len(BRIDGES))

    def on_local_disconnect(c, u, f, rc, props):
        LOCAL_CONNECTED["v"] = False
        log.warning("[local] disconnected (rc=%s)", rc)

    local.on_connect = on_local_connect
    local.on_disconnect = on_local_disconnect
    local.connect_async(LOCAL_HOST, LOCAL_PORT, keepalive=60)
    local.loop_start()

    for b in BRIDGES:
        rc_client = make_client(f"bridge-{b['name']}", b["remote_user"], b["remote_pass"])
        b["client"] = rc_client
        rc_client.on_message = on_remote_message(b, local)

        def mk_conn(bb):
            def on_connect(c, u, f, rc, props):
                bb["connected"] = (rc == 0 or str(rc) == "Success")
                log.info("[%s] connected to %s:%d (rc=%s)", bb["name"],
                         bb["remote_host"], bb["remote_port"], rc)
                c.subscribe(f"{bb['remote_root']}/2/e/{bb['remote_channel']}/#", qos=0)
            return on_connect

        def mk_disc(bb):
            def on_disconnect(c, u, f, rc, props):
                bb["connected"] = False
                log.warning("[%s] disconnected (rc=%s)", bb["name"], rc)
            return on_disconnect

        rc_client.on_connect = mk_conn(b)
        rc_client.on_disconnect = mk_disc(b)
        rc_client.connect_async(b["remote_host"], b["remote_port"], keepalive=60)
        rc_client.loop_start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
