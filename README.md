# bridge-mqtt-multi-longfast

Republishes a Meshtastic channel between **two MQTT servers**, letting a single
device participate in the **public LongFast of each server** and **choose per
message** which one to send to — something the firmware alone can't do (a node
connects to only one MQTT server, and the public LongFast of each is the same
channel, differing only by the topic root).

## How it works

The device uses a **second channel with a different local name** (e.g.
`LongFastCO`) but the **same public LongFast PSK** (`AQ==`). The firmware
encrypts the payload with the correct key; the only difference from the public
LongFast is the **channel-hash byte** (it changes because the name changes).

This service then, **without re-encrypting anything**:

- **outbound:** reads `LOCAL_ROOT/2/e/LongFastCO/#` on the local broker, rewrites
  `packet.channel` to the LongFast hash (8) and `channel_id` to `LongFast`, and
  publishes to `REMOTE_ROOT/2/e/LongFast/#` on the remote (public) server.
- **inbound:** the reverse, so the device receives the remote public traffic on
  its local `LongFastCO` channel.

Loops are prevented by deduplicating on `packet.id`.

```
app (you choose)            server (what arrives)
channel "LongFast"   ──────► meshbrasil : LongFast  (native firmware MQTT)
channel "LongFastCO" ──swap─► US/CO      : LongFast  (this republisher)
```

## Why not a plain MQTT bridge (mosquitto)

Mosquitto only renames the topic — it **does not recompute the channel hash**
carried inside the packet, so the public node on the other server would reject
the message. This service speaks the Meshtastic protobuf and fixes the hash.

## Configuration (environment variables)

| Var | Default | Description |
|---|---|---|
| `LOCAL_MQTT_HOST` | `127.0.0.1` | local broker (mosquitto) |
| `LOCAL_MQTT_PORT` | `1883` | |
| `LOCAL_MQTT_USER` / `LOCAL_MQTT_PASS` | — | local broker credentials |
| `LOCAL_ROOT` | `meshdev` | local topic root |
| `LOCAL_CHANNEL` | `LongFastCO` | LOCAL channel name (the alias) |
| `REMOTE_MQTT_HOST` | `mqtt.meshtastic.org` | remote public server |
| `REMOTE_MQTT_PORT` | `1883` | |
| `REMOTE_MQTT_USER` / `REMOTE_MQTT_PASS` | `meshdev` / `large4cats` | public credentials |
| `REMOTE_ROOT` | `msh/US/CO` | remote topic root |
| `REMOTE_CHANNEL` | `LongFast` | remote public channel |
| `LOG_LEVEL` | `INFO` | `DEBUG` to log every republish |

The `LongFastCO` channel on the device **must use the `AQ==` PSK** (the same as
LongFast), otherwise the payload won't decrypt on the remote public server.

## Run

```bash
docker build -t bridge-mqtt-multi-longfast .
docker run -d --name bridge-mqtt \
  -e LOCAL_MQTT_HOST=<YOUR-BROKER-IP> \
  -e LOCAL_MQTT_USER=<user> -e LOCAL_MQTT_PASS=<password> \
  -e REMOTE_ROOT=msh/US/CO \
  bridge-mqtt-multi-longfast
```

## Notice

Publishing to a public MQTT server (e.g. `mqtt.meshtastic.org`) must respect that
server's usage policy. This service is meant to republish **your own nodes'
traffic**, not to relay entire networks.
