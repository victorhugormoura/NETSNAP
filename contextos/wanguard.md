# Wanguard 9 (Andrisoft) — checklist de análise

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com

Referência: guia do Wanguard 9.0 (docs.andrisoft.com/wanguard/latest). A
configuração operacional fica no MariaDB da Console (`andrisoft`); o
snapshot traz as tabelas sem as colunas de segredo.

## Saúde da plataforma

- O WANsupervisor para quando o MariaDB da Console cai. MariaDB parado ou
  reiniciando é crítico: a detecção para junto.
- `genrrds_*: fail ... clickhouse/influxdb ... Couldn't connect to server`:
  o banco de séries configurado em Graphs & Storage não responde; gráficos,
  Flow Graphs e Profiling ficam sem dados. A detecção continua.
- Fuso e relógio: todos os servidores no mesmo fuso, com NTP. Erro
  "Received flow … seconds ago" com desvio múltiplo de 3600 s indica fuso
  errado no exportador ou no servidor.
- `UdpRcvbufErrors`/`RcvbufErrors` crescendo: o Flow Sensor perde flows.
  Medir antes de mexer em `net.core.rmem_*`.
- Disco: flows crus e RRD por IP enchem o volume (`df`, `du` de
  `/opt/andrisoft/flows` e dos bancos). Sem backup recente do
  `WANmaintenance backup_db` em `/root`: apontar.

## Detecção

- Prefixos do provedor ausentes do IP Zone não são protegidos e quebram o
  "Traffic Direction" automático. Pools CGNAT, caches (GGC/OCA/FNA),
  resolvedores DNS e BNG precisam de prefixo e template próprios.
- Thresholds: preferir pkts/s. Valores iniciais do fornecedor: TCP+SYN
  500–1000 pps por IP, ICMP 50–100 pps, UDP ~15k pps. Use os agregados
  "regras que mais disparam" e "alvos mais frequentes" para apontar falso
  positivo (mesma regra, muitas anomalias curtas no mesmo alvo).
- Flow Sensor: janela fixa de 5 minutos; exportador com active 60 s,
  inactive 15–30 s. MikroTik com `active-flow-timeout=30m` (padrão) não
  serve. "Stats Engine" Full guarda IPs externos e estoura RAM em ataque
  spoofado; recomendado Extended.
- Monitorar só interfaces de upstream (inclusive IX.br); o sensor não
  deduplica.
- "Sweep Merge" 3–4 e "Ignore Duplicates" contra carpet bombing.

## Mitigação

- RTBH /32 num IP de pool CGNAT derruba todos os assinantes daquele IP.
  Response do pool sem RTBH automático, ou com precondição de volume.
- BGP Connector: "Reject External IPs" ligado e "Reject Under /32" (e /128).
  "Source RTBH" desliga essas proteções: connector separado.
- Flowspec: "Max. Flowspec Rules" no connector abaixo do limite do roteador
  (Juniper 8000, ASR9k 3000, Nokia 512). No MX, conferir a versão do Junos
  contra o JSA112187 (CVE-2026-102178/101990/101948) antes de ligar
  Flowspec; corrigidas: 23.2R2-S7.7, 23.4R2-S8.13, 24.2R2-S5.5, 24.4R2-S5,
  25.2R2-S2, 25.4R1-S3, 25.4R2, 26.2R1-S2, 26.2R2, 26.4R1+.
- Precondição de Response usa `=`, `!=`, `>`, `incl`, `reg`, `and`, `or`,
  `not`. `==` e `&&` não funcionam (a ação nunca dispara).
- "Withdraw After" na Response é em minutos; na REST API, em segundos.
- Whitelist não suprime detecção: só impede o Filter de bloquear.

## Segurança

- Console em HTTP (padrão) ou fora da gerência; sem TOTP/SAML.
- MariaDB em 0.0.0.0:3306 sem firewall. Só sensores remotos precisam.
- bgpd/zebra (2605/2601) fora do localhost; vty por telnet.
- Pipe do ExaBGP gravável por todos (`prw-rw-rw-`): qualquer usuário local
  anuncia rotas. Correto: 0660, grupo do ExaBGP, `andrisoft` no grupo.
- Sessões BGP com o roteador sem MD5; `ebgp-multihop` desnecessário.
- WANsupervisor sem `-n`: Server Commands executa shell pela Console como
  `andrisoft`.
- Coletor UDP de flow sem firewall restringindo aos exportadores: flows
  forjados podem induzir blackhole.
- Componentes com CVE: GoBGP < 3.35.0 (CVE-2025-43971/43972/43973, parser
  flowspec), < 4.6.0 / < 4.7.0 (CVE-2026-49837/49838); FRR stable/10.0
  (CVE-2026-37457, flowspec). Wanguard/Wansight: nenhum CVE público até
  22/10/2026, o que não prova ausência de falha.

## Cuidados ao recomendar

- Nada de mudança em BGP de produção sem rollback e `commit confirmed`
  (Junos). Mudança em threshold ou Response vale para todos os prefixos que
  herdam o template.
- Não inventar nome de campo da Console: usar o nome em inglês, como na UI.
