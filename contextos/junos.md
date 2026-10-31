# Juniper Junos (linha MX) — checklist de análise

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com
Base: skill Juniper/Junos para ISP (out/2026). Versão completa na pasta
privada de contextos.

## Regras

- Descubra modelo e release (`show version`, `show chassis hardware`) antes
  de propor sintaxe. Junos OS e Junos OS Evolved diferem (MX é Junos OS).
- Entregue correções em `set`, com o fluxo: `configure private` →
  `show | compare` → `commit check` → `commit confirmed 5 comment "..."` →
  validar → `commit comment "..."`.
- `commit confirmed` em tudo que mexe no caminho até o roteador (filtro do
  lo0, management-instance, interfaces de gerência, BGP de borda).

## config (show configuration | display set)

- Crítico: grupo eBGP sem import/export, ou cadeia sem `then reject` final,
  e sem `protocols bgp defaults ebgp no-policy receive/advertise reject`
  (export default do BGP reanuncia todas as rotas BGP ativas = vazamento).
- Crítico: lo0 sem filtro de entrada, ou filtro aceitando SSH/SNMP de
  qualquer origem. Termos mínimos em v4 e v6: BGP via `apply-path`, SSH e
  NETCONF só da gerência com policer, SNMP, NTP, TACACS/RADIUS, DNS, IGP,
  BFD (3784/3785/4784), ICMP/ICMPv6 com ND/RA, `tcp-established`, discard
  final com count + syslog.
- Alto: trânsito, IX e clientes sem `prefix-limit`/`accepted-prefix-limit`.
- Alto: sem RPKI, ou `accept` no termo VALID. O match é
  `from validation-database` (`validation-state` dá erro de sintaxe); sem
  `port` a sessão usa 8282.
- Alto: iBGP montado em IP de VLAN de transporte em vez de loopback; NET
  IS-IS repetido em dois roteadores (config copiada).
- Alto: community padrão com ASN de 4 bytes (`65550:x` não commita: use
  large communities) ou `community set` apagando as recebidas.
- Médio: telnet/ftp ligados, `root-login allow`, SNMP v2c sem `client-list`,
  archival por FTP, `ntp peer` em vez de `server`.
- Médio: grupos BGP desativados ou sem sessão há meses; MTU divergente no
  mesmo transporte; `fec74` em porta 100G (é de 25/50G).
- Baixo: `chassis afeb/tfeb` em MX204 (herança de MX80), descrições faltando.
- 24.2R1+: syslog não usa a `mgmt_junos` por padrão; com management-instance
  o host de syslog precisa de `routing-instance mgmt_junos`.

## basico

- Release fora de suporte: 22.4 venceu em 22/06/2026; 23.1 em 31/03/2024.
- Último reboot por power cycle/failure: energia do site; PSUs em circuitos
  A/B diferentes?
- CPU idle baixo persistente; memória da VM da RE acima de 80%.
- Licenças "needed / invalid" em `show system license`.
- `show system commit` com commits sem comentário (rastreabilidade).
- `show system core-dumps` com cores recentes; `show system storage` cheio.
- Violações em `show ddos-protection protocols violations`.

## logs

- `SNMP_TRAP_LINK_DOWN` repetido (flap), `bgp_ifachange_group`, BFD Detect
  Timer Expiry, `RPD_BGP_NEIGHBOR_STATE_CHANGED`, `DDOS_PROTOCOL_VIOLATION`,
  `UI_COMMIT` sem comentário, login de origem inesperada.
- Cease/6 "Other Configuration Change" com "Interface change for the
  peer-group": a interface do peer caiu ou mudou.

## optica

- Rx abaixo do low warning, Tx fora da faixa, temperatura perto do alarme,
  lanes de QSFP desbalanceadas (> 3 dB), ótica sem DOM.
- Rx bom + `LOCAL-FAULT`: FEC diferente, ótica incompatível, porta com
  restrição. 100G-SR4 exige RS-FEC (fec91); LR4 normalmente sem FEC.
- EA0 do MX204 em 78–80 °C é normal.

## vizinhanca

- Peers Down/Idle/Active, flaps acumulados altos, uptime curto, adjacência
  IS-IS faltando, BFD com intervalo agressivo em sessão centralizada,
  sessões RPKI fora de Up.

## inventario

- Óticas "NON-JNPR" (JTAC pode recusar suporte), PSU única ou duas no mesmo
  circuito, fans com alarme, hardware em fim de vida (MX204: fim de software
  15/06/2030; MX104 fim de suporte 15/03/2028; MX5–80 fora de suporte desde
  30/06/2026).

## Armadilhas que não podem passar

| Armadilha | Consequência |
|---|---|
| Export BGP default | Vazamento de full table |
| Route-filter casa pelo prefixo mais longo, não pelo match type | Termo não casa |
| `per-packet` fora de `routing-options forwarding-table export` | ECMP não instala |
| `mtu` da IFD inclui L2 (1514 = IP 1500) | OSPF em ExStart, pseudowire caído |
| NSR e graceful-restart juntos | Commit falha |
| FlowSpec `rate-limit` no CLI em bits/s, community `traffic-rate` em bytes/s | Limite 8× errado |
| RTBH de IP de CGNAT | Derruba centenas de assinantes; use FlowSpec por porta |
| Mudar MTU no MX | Reseta BGP, OSPF e IS-IS (janela) |
| MX204 com as 4 QSFP a 100G | PIC 1 precisa de `number-of-ports 0` |
