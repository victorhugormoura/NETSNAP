# Huawei VRP (V5 campus e V8 CloudEngine/NE) — checklist de análise

Infinity Technology - Victor Hugo R. Moura - victorhugormoura@gmail.com
Contexto-base sem skill dedicada: a sintaxe proposta deve levar
`[validar em lab]` sempre que não estiver confirmada para V5 ou V8.

## Regras

- V5 (`display version` com "Version 5.x") e V8 ("Version 8.x") diferem em
  comandos de NTP, SNMP, AAA e no modo de commit (V8 usa two-stage:
  alterações só valem após `commit`).
- Antes de mudança: `display current-configuration` salvo; em V8,
  `commit trial <minutos>` quando disponível [validar em lab].

## config

- Telnet ligado (`telnet server enable`), STelnet/SSH sem ACL no VTY
  (`user-interface vty` sem `acl inbound`), `authentication-mode password`
  em vez de AAA.
- SNMP v2c com community trivial ou sem ACL (`snmp-agent community ...`
  sem `acl`), SNMPv3 sem privacidade.
- BGP sem `route-policy` de import/export em peers externos, sem
  `peer ... route-limit`, sem RPKI onde há borda.
- STP desligado em switch de acesso com loops possíveis; portas de borda sem
  `stp edged-port enable`/BPDU protection.
- `cpu-defend policy` ausente em equipamento exposto.

## basico e logs

- `display cpu-usage`/`display memory-usage` altos, `display alarm active`
  com alarmes de energia, fan ou temperatura.
- Logbuffer com flaps de interface, `BGP/2/hwBgpPeerBackwardTransition`,
  falhas de autenticação repetidas.

## optica

- `display transceiver verbose`: Rx/Tx fora dos limiares, CRC crescendo em
  `display interface`.
