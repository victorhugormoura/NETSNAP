# Servidor Linux de provedor — checklist de análise

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com

## Pacotes e vulnerabilidades

- O netcve avalia os pacotes pela versão exata da distribuição (OSV). Não
  aponte vulnerabilidade pela versão upstream de pacote do Debian/Ubuntu:
  as correções são retroportadas sem mudar o número.
- PHP2Shell (CVE-2026-109618/109619, RCE sem autenticação, exploração desde
  17/10/2026): crítico onde há PHP-FPM ou mod_php ativo. Corrigido em
  8.5.12/8.4.27/8.3.36/8.2.35 ou no pacote corrigido da distribuição;
  paliativo `memory_limit=-1` e `session.upload_progress.enabled=0` no
  php.ini do FPM/Apache (o da CLI não vale) e reinício dos workers.
- `apt list --upgradable` longo, kernel em execução diferente do instalado
  (reinício pendente).

## Acesso

- `PermitRootLogin yes`, `PasswordAuthentication yes` exposto à internet,
  usuários com UID 0 além do root, grupos sudo/wheel com contas inesperadas.
- Serviços escutando em 0.0.0.0 que deveriam estar só na gerência (`ss -tulpn`):
  bancos (3306, 5432, 6379), painéis web, SNMP.

## Firewall

- Sem iptables/nftables/ufw ativo em servidor exposto; política INPUT ACCEPT
  sem regras; regras que aceitam tudo de 0.0.0.0/0 antes do drop.

## Serviços de provedor

- BIND/Unbound: recursão aberta (`allow-recursion { any; }`), versão exposta.
- Chrony/NTP: sem fontes ou fora de sincronia (o Marco Civil depende do
  horário).
- RPKI (Routinator/StayRTR): processo parado, dados velhos.
- `systemctl --failed` com unidades falhando; timers de backup sem execução.

## Logs

- journalctl com OOM killer, falhas de disco (I/O error, EXT4-fs error),
  segfaults repetidos, força bruta SSH (muitos "Failed password").
