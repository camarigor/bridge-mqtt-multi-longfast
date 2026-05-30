# bridge-mqtt-multi-longfast

Republicador de canal Meshtastic entre **dois servidores MQTT**, permitindo que
um único device participe do **LongFast público de cada servidor** e **escolha
por mensagem** para qual ir — algo que o firmware sozinho não faz (um node só
conecta a um servidor MQTT, e o LongFast público de cada um é o mesmo canal,
diferindo só pelo root do tópico).

## Como funciona

O device usa um **2º canal com nome local diferente** (ex.: `LongFastCO`) mas com
a **mesma PSK pública** do LongFast (`AQ==`). O firmware cifra o payload com a
chave certa; a única diferença para o LongFast público é o **byte de hash do
canal** (muda porque o nome muda).

Este serviço então, **sem recriptografar nada**:

- **saída:** lê `LOCAL_ROOT/2/e/LongFastCO/#` no broker local, reescreve
  `packet.channel` → hash do LongFast (8) e `channel_id` → `LongFast`, e publica
  em `REMOTE_ROOT/2/e/LongFast/#` no servidor remoto (público).
- **entrada:** o inverso, para o device receber o tráfego do público remoto no
  canal local `LongFastCO`.

Loop é evitado por dedup de `packet.id`.

```
app (você escolhe)         servidor (o que chega)
canal "LongFast"   ───────► meshbrasil : LongFast  (nativo do firmware)
canal "LongFastCO" ──swap─► US/CO      : LongFast  (este republicador)
```

## Por que não um bridge MQTT comum (mosquitto)

Mosquitto só renomeia tópico — **não recalcula o hash do canal** que vai dentro
do pacote, então o nó público do outro servidor rejeitaria a mensagem. Este
serviço fala protobuf Meshtastic e corrige o hash.

## Configuração (variáveis de ambiente)

| Var | Default | Descrição |
|---|---|---|
| `LOCAL_MQTT_HOST` | `127.0.0.1` | broker local (mosquitto) |
| `LOCAL_MQTT_PORT` | `1883` | |
| `LOCAL_MQTT_USER` / `LOCAL_MQTT_PASS` | — | credenciais do broker local |
| `LOCAL_ROOT` | `meshdev` | root do tópico local |
| `LOCAL_CHANNEL` | `LongFastCO` | nome do canal LOCAL (apelido) |
| `REMOTE_MQTT_HOST` | `mqtt.meshtastic.org` | servidor público remoto |
| `REMOTE_MQTT_PORT` | `1883` | |
| `REMOTE_MQTT_USER` / `REMOTE_MQTT_PASS` | `meshdev` / `large4cats` | credenciais públicas |
| `REMOTE_ROOT` | `msh/US/CO` | root do tópico remoto |
| `REMOTE_CHANNEL` | `LongFast` | canal público remoto |
| `LOG_LEVEL` | `INFO` | `DEBUG` para ver cada republicação |

O canal `LongFastCO` no device **deve usar a PSK `AQ==`** (a mesma do LongFast),
senão o payload não decripta no público remoto.

## Rodar

```bash
docker build -t bridge-mqtt-multi-longfast .
docker run -d --name bridge-mqtt \
  -e LOCAL_MQTT_HOST=<IP-DO-SEU-BROKER> \
  -e LOCAL_MQTT_USER=<user> -e LOCAL_MQTT_PASS=<senha> \
  -e REMOTE_ROOT=msh/US/CO \
  bridge-mqtt-multi-longfast
```

## Aviso

Publicar num servidor MQTT público (ex.: `mqtt.meshtastic.org`) deve respeitar as
regras de uso do servidor. Este serviço foi feito para republicar **o tráfego dos
seus próprios nós**, não para relay de redes inteiras.
