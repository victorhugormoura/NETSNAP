# Cisco IOS / IOS-XE / NX-OS / IOS-XR — checklist de análise

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com
Contexto-base sem skill dedicada: marque com `[validar em lab]` a sintaxe que
não estiver confirmada para a família e a versão.

## Regras

- IOS/IOS-XE aplicam cada linha na hora (sem commit): para mudança remota,
  `reload in <min>` como rede de segurança [validar em lab] ou acesso
  out-of-band. IOS-XR e NX-OS (com checkpoint) têm commit/rollback.

## config

- IOS-XE com `ip http server` ou `ip http secure-server` ligados: superfície
  da Web UI explorada em massa em 2023 (CVE-2023-20198, CISA KEV). Sem uso,
  desligar; com uso, ACL.
- `transport input telnet`/`all` nas VTY, VTY sem `access-class`, `enable
  password` em vez de `enable secret`, `service password-encryption` como
  única proteção.
- SNMP com community trivial ou sem ACL; `snmp-server community ... RW`.
- BGP sem `route-map`/`prefix-list` de entrada e saída em vizinhos externos,
  sem `maximum-prefix`.
- `no ip source-route`, `no ip proxy-arp` e `no service pad` ausentes em
  borda; CoPP ausente.

## basico e logs

- `show version` com reload por crash ("System returned to ROM by ...
  error"), uptime curto inesperado.
- Logs com `%LINEPROTO-5-UPDOWN` repetido, `%BGP-5-ADJCHANGE` down,
  `%SEC_LOGIN-4-LOGIN_FAILED` em sequência.

## optica

- `show interfaces transceiver`: Rx/Tx fora da faixa; `show interfaces` com
  CRC, input errors ou output drops crescendo.
