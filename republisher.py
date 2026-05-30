#!/usr/bin/env python3
"""
bridge-mqtt-multi-longfast — republicador de canal Meshtastic entre dois MQTT.

Problema que resolve: um node Meshtastic só conecta a UM servidor MQTT, e o
LongFast público de cada servidor é o MESMO canal (nome "LongFast", PSK pública
AQ==), diferindo só pelo ROOT do tópico. Isso impede "estar nos dois públicos E
escolher por mensagem" a partir de um device.

Solução: o device usa um 2º canal com um NOME LOCAL diferente (ex.: LongFastCO)
mas com a MESMA PSK pública (AQ==). Este serviço:
  - lê os pacotes desse canal local no broker LOCAL,
  - reescreve apenas o byte de hash do canal (-> hash do LongFast) e o channel_id
    (-> "LongFast"), SEM tocar no payload (já está cifrado com a chave certa),
  - republica no LongFast público do servidor REMOTO (root remapeado).
E o inverso, para receber.

Como a PSK é a mesma (AQ==), não há recriptografia: só troca de 1 campo de
protobuf + do tópico. Loop é evitado por dedup de packet.id.
"""
import os
import sys
import time
import logging

import paho.mqtt.client as mqtt

# Protobufs do Meshtastic (caminho novo; fallback p/ versões antigas)
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
        logging.error("Variável de ambiente obrigatória ausente: %s", key)
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

LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bridge")

# ---------------------------------------------------------------------------
# Channel hash (algoritmo do firmware: XOR de todos os bytes do nome XOR a chave)
# Chave default expandida (PSK "AQ==" / índice 1). Confere: LongFast -> 8.
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

LOCAL_HASH = channel_hash(LOCAL_CHANNEL)    # ex.: LongFastCO -> 4
REMOTE_HASH = channel_hash(REMOTE_CHANNEL)  # ex.: LongFast   -> 8

# Tópicos
LOCAL_SUB = f"{LOCAL_ROOT}/2/e/{LOCAL_CHANNEL}/#"
REMOTE_SUB = f"{REMOTE_ROOT}/2/e/{REMOTE_CHANNEL}/#"

# ---------------------------------------------------------------------------
# Dedup p/ loop-prevention (ids de pacote vistos recentemente).
# O eco imediato (nossa própria publicação voltando pela subscrição) é sempre
# pego: acabamos de adicionar o id. O clear() só descarta ids antigos, fora da
# janela de loop — inofensivo.
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
    """Último segmento do tópico = id do gateway (ex.: !f6709dc8)."""
    return topic.rsplit("/", 1)[-1]

# ---------------------------------------------------------------------------
# Republicação
# ---------------------------------------------------------------------------
def repackage(payload: bytes, new_hash: int, new_channel_id: str):
    """Reescreve packet.channel + channel_id de um ServiceEnvelope. Retorna
    (bytes_reserializados, packet_id) ou (None, None) se não aplicável."""
    se = mqtt_pb2.ServiceEnvelope()
    se.ParseFromString(payload)
    if not se.HasField("packet"):
        return None, None
    pkt = se.packet
    # só faz sentido p/ pacotes cifrados de canal
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
            log.info("[%s] id=0x%x %s -> %s (hash->%d)",
                     direction, pid or 0, msg.topic, dst_topic, new_hash)
        except Exception as e:
            log.warning("[%s] erro processando msg de %s: %s", direction, msg.topic, e)
    return on_message

def build_client(name, host, port, user, password):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"bridge-{name}")
    if user:
        c.username_pw_set(user, password)
    c.reconnect_delay_set(min_delay=1, max_delay=30)

    def on_connect(client, userdata, flags, reason_code, properties):
        log.info("[%s] conectado a %s:%d (rc=%s)", name, host, port, reason_code)

    def on_disconnect(client, userdata, flags, reason_code, properties):
        log.warning("[%s] desconectado de %s:%d (rc=%s)", name, host, port, reason_code)

    c.on_connect = on_connect
    c.on_disconnect = on_disconnect
    return c

def main():
    log.info("bridge-mqtt-multi-longfast iniciando")
    log.info("LOCAL  %s:%d root=%s canal=%s (hash=%d)  sub=%s",
             LOCAL_HOST, LOCAL_PORT, LOCAL_ROOT, LOCAL_CHANNEL, LOCAL_HASH, LOCAL_SUB)
    log.info("REMOTE %s:%d root=%s canal=%s (hash=%d)  sub=%s",
             REMOTE_HOST, REMOTE_PORT, REMOTE_ROOT, REMOTE_CHANNEL, REMOTE_HASH, REMOTE_SUB)

    local = build_client("local", LOCAL_HOST, LOCAL_PORT, LOCAL_USER, LOCAL_PASS)
    remote = build_client("remote", REMOTE_HOST, REMOTE_PORT, REMOTE_USER, REMOTE_PASS)

    # LOCAL (LongFastCO) -> REMOTE (LongFast público): reescreve hash -> REMOTE_HASH
    local.on_message = make_on_message(
        "out", remote, REMOTE_ROOT, REMOTE_CHANNEL, REMOTE_HASH, REMOTE_CHANNEL)
    # REMOTE (LongFast) -> LOCAL (LongFastCO): reescreve hash -> LOCAL_HASH
    remote.on_message = make_on_message(
        "in", local, LOCAL_ROOT, LOCAL_CHANNEL, LOCAL_HASH, LOCAL_CHANNEL)

    def sub_local(client, *a):
        client.subscribe(LOCAL_SUB, qos=0)
        log.info("[local] inscrito em %s", LOCAL_SUB)
    def sub_remote(client, *a):
        client.subscribe(REMOTE_SUB, qos=0)
        log.info("[remote] inscrito em %s", REMOTE_SUB)
    # encadeia a subscrição ao on_connect
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
