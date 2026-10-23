# MikroTik RouterOS 7 — checklist de análise

Infinity Technology - Victor Hugo R. Moura - victorhugormoura@gmail.com
Base: pacote de conhecimento MikroTik do netsnap (RouterOS 7.23.7 long-term
e 7.24.5 stable, out/2026). Versão completa na pasta privada de contextos.

## Regras

- Descubra versão e modelo (`/system resource print`,
  `/system routerboard print`). A sintaxe mudou em 7.13, 7.17, 7.20, 7.21,
  7.22 e 7.23; sem versão, assuma 7.23.7 e diga isso.
- Correção remota: Safe Mode (Ctrl+X; rollback ~9 min após queda) ou
  scheduler de rollback; antes, `/export file=pre-mudanca`.
- Não invente parâmetro: o que não estiver confirmado leva
  `[validar em lab]` e a instrução de conferir com `?` na versão.

## Segurança (prioridade máxima)

- MikroTrick (CVE-2026-67279 + CVE-2026-86060, SSH pré-autenticação;
  CVE-2026-67277 no bandwidth-test): exploração desde 02/09/2026, no CISA
  KEV. Corrigido em 7.23.4/7.24.2/6.49.21; CVE-2026-67278 só completa em
  7.23.6/7.24.3. Recomende 7.23.7 ou 7.24.5. O netcve já avalia versão e
  exposição; confirme no snapshot:
  - `/ip service print detail`: SSH, Winbox, www, api sem `address`
    (`available-from` na 7.24+) restrito às redes de gerência;
  - `/tool bandwidth-server print`: `enabled: yes`;
  - `/system device-mode print`: `flagged: yes` = suspeita de invasão;
  - `/user print`: conta desconhecida (a campanha criou `ops`).
- Indícios de comprometimento: scheduler/script desconhecido, `/ip socks` ou
  `/ip proxy` ligados, DNS estático estranho, dst-nat inesperado. Com indício:
  netinstall em versão corrigida, troca de todos os segredos e restauração
  por export revisado (nunca backup binário).
- Hardening esperado: telnet/ftp/www/api/api-ssl desligados; SSH e Winbox só
  da gerência; `/ip ssh strong-crypto=yes`; bandwidth-server, mac-server e
  neighbor discovery restritos à lista MGMT; `/ip dns allow-remote-requests=no`
  quando não é resolvedor; usuário `admin` desativado.
- `address`/`available-from` só nega o serviço: a chain input do firewall
  continua obrigatória. Winbox/SSH abertos para 100.64.0.0/10 (assinantes)
  ou blocos públicos de clientes é crítico.
- Chain input: established/related/untracked aceito, invalid descartado,
  ICMP, BGP só de BGP-PEERS, BFD, OSPF, LDP só de loopbacks, SNMP restrito,
  gerência, drop final.

## Roteamento

- BGP 7.20+: `/routing/bgp/instance` com AS obrigatório; instance migrada
  sem AS derruba todas as sessões.
- **Sessão sem `output.filter-chain` repassa todas as rotas BGP recebidas**:
  vazamento de trânsito entre operadoras. Crítico.
- `output.network` só anuncia com rota idêntica ativa (blackhole do agregado).
- Filtro de saída com `reject` no fim derruba L3VPN se não houver
  `if (afi vpnv4) { accept; }` antes.
- RPKI: `rpki-verify` + `if (rpki invalid) { reject; }`; não rejeite
  `unverified`.
- OSPF em ExStart/Exchange = MTU diferente (não existe mtu-ignore).
- LDP preso em Throttled: firewall 646 sem os loopbacks ou falta
  `accept-dynamic-neighbors`.

## Firewall, NAT e QoS

- CGNAT com IP fixo: `src-nat`/`netmap`, nunca `masquerade`. Descartar
  100.64.0.0/10 vindo ou indo para a WAN pública.
- `log=yes` por conexão no CGNAT: volume e CPU; a trilha do Marco Civil é a
  tabela público+portas → privado versionada, NTP e accounting RADIUS.
- FastTrack ignora simple queue e queue tree `parent=global`: plano que não
  limita.
- `default-small` (pfifo de 10 pacotes) em fila de assinante causa perda e
  bufferbloat; fq_codel é o recomendado.
- CCR2116/2216 com L3HW: firewall/NAT ignorados em portas com
  `l3-hw-offloading=yes`.

## Interfaces e ópticas

- `/interface ethernet monitor` com Rx/Tx fora da faixa do módulo, link
  partner diferente do esperado, contadores de erro/fcs crescendo.
- Bridge com `vlan-filtering` sem a VLAN de gerência tagged na própria
  bridge = risco de lockout.

## Versões

- Long-term 7.23.7, stable 7.24.5 (out/2026). 7.22 moveu MLAG para a bridge;
  7.23 removeu `add-dhcp-option82` (scripts quebram).
- `/system package update print` com atualização disponível; RouterBOOT
  (`/system routerboard print`) diferente do RouterOS.
