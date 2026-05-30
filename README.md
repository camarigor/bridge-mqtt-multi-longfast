# bridge-mqtt-multi-longfast

Lets a single Meshtastic device be on the **public LongFast of several MQTT
servers** at once and **choose per message** which one to send to — something the
firmware alone can't do (a node connects to only one MQTT server, and the public
LongFast of each server is the same channel "LongFast" + public PSK `AQ==`,
differing only by the topic root).

## Architecture

```
  device ──(one connection)──►  mosquitto  ◄──►  this app ──►  meshbrasil (public)
  (base)                       (local broker)            └──►  US/CO (public)
```

- The **device** connects only to your **local broker** (mosquitto) and publishes
  its channels there (e.g. `LongFast`, `LongFastCO`).
- **This app** is the single router: it connects to the local broker **and to each
  remote public server**, and relays each local channel to/from a remote channel.
- The device never connects to the public servers directly. Everything it sends or
  receives flows through the local broker.

## How the channel trick works

On the device, the channel you pick is the destination selector. Each channel has
a **different local name** so you can choose it, but the **same public PSK
(`AQ==`)**. The Meshtastic channel identity is a 1-byte hash of `name + PSK`, which
travels inside the packet — so a different name means a different hash, and the
remote public node would reject it.

This app fixes exactly that: for each bridge it rewrites only the **channel-hash
byte** and the **channel_id** to the remote channel's values, leaving the
encrypted payload untouched (no re-encryption, since the PSK is the same). Loops
are prevented by packet-id dedup.

```
app picks bridge by channel:
  local "LongFast"   ──► meshbrasil  LongFast   (hash 8 -> 8, no-op)
  local "LongFastCO" ──► US/CO       LongFast   (hash 4 -> 8)
```

## Why not a plain mosquitto bridge

Mosquitto only renames topics — it can't recompute the channel hash inside the
packet, so a renamed channel would be rejected by the remote public mesh. This app
speaks the Meshtastic protobuf and rewrites the hash.

## Configuration (environment variables)

Shared local broker:

| Var | Default | Description |
|---|---|---|
| `LOCAL_MQTT_HOST` | `127.0.0.1` | local broker (mosquitto) |
| `LOCAL_MQTT_PORT` | `1883` | |
| `LOCAL_MQTT_USER` / `LOCAL_MQTT_PASS` | — | local broker credentials |
| `LOCAL_ROOT` | `meshdev` | local topic root |
| `STATUS_PORT` | `8080` | HTTP status page port |
| `LOG_LEVEL` | `INFO` | `DEBUG` to log every relay |

One block per bridge, numbered `BRIDGE1_`, `BRIDGE2_`, … (the app loads them until
a missing `BRIDGE{N}_REMOTE_HOST`):

| Var | Example | Description |
|---|---|---|
| `BRIDGE{N}_NAME` | `meshbrasil` | label for logs/status |
| `BRIDGE{N}_LOCAL_CHANNEL` | `LongFast` | device channel that routes to this server |
| `BRIDGE{N}_REMOTE_HOST` | `platform.meshbrasil.com` | remote MQTT server |
| `BRIDGE{N}_REMOTE_PORT` | `1883` | |
| `BRIDGE{N}_REMOTE_USER` / `_REMOTE_PASS` | `meshdev` / `large4cats` | remote credentials |
| `BRIDGE{N}_REMOTE_ROOT` | `meshdev` or `msh/US/CO` | remote topic root |
| `BRIDGE{N}_REMOTE_CHANNEL` | `LongFast` | remote channel (usually `LongFast`) |

Each `LOCAL_CHANNEL` on the device must use the **`AQ==` PSK** (the same as
LongFast), otherwise the payload won't decrypt on the remote public server.

A legacy single-bridge config via `LOCAL_CHANNEL` + `REMOTE_MQTT_*` is still
accepted for backward compatibility.

A status page is served on `STATUS_PORT` (`/` HTML, `/status.json` JSON): per-bridge
connection state and relay counters (no secrets).

## Notice

Publishing to a public MQTT server (e.g. `mqtt.meshtastic.org`) must respect that
server's usage policy. This service is meant to republish **your own nodes'
traffic**, not to relay entire networks.
