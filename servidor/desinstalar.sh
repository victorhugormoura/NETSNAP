#!/bin/bash
# desinstalar.sh — remove o servidor netsnap
#
# Por padrão mantém dados (/var/lib/netsnap) e configuração com a chave-mestra
# (/etc/netsnap): uma reinstalação depois encontra tudo como estava.
#
# Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
# Licenciado sob a licença MIT.

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

sim() {
  local padrao=${2:-n} op r
  if [ "$padrao" = s ]; then op="S/n"; else op="s/N"; fi
  while true; do
    read -r -p "$1 [$op]: " r || exit 1
    r=${r:-$padrao}
    case "${r,,}" in
      s|sim|y|yes) return 0 ;;
      n|nao|não|no) return 1 ;;
    esac
  done
}

[ "$(id -u)" -eq 0 ] || { echo "Execute como root." >&2; exit 1; }
echo "Remover o servidor netsnap deste computador."
sim "Continuar?" n || exit 0

WEB=nginx
if [ -f /etc/netsnap/instalacao.conf ]; then
  WEB=$(sed -n 's/^servidor_web *= *//p' /etc/netsnap/instalacao.conf | head -1)
fi

# O socket primeiro: ativo, ele tentaria subir o serviço de novo.
systemctl disable --now netsnap-servidor.socket netsnap-servidor.service \
  netsnap-certificado.timer 2>/dev/null || true
rm -f /etc/systemd/system/netsnap-servidor.socket \
      /etc/systemd/system/netsnap-servidor.service \
      /etc/systemd/system/netsnap-certificado.service \
      /etc/systemd/system/netsnap-certificado.timer
systemctl daemon-reload
echo "[OK] serviço removido"

if [ "$WEB" = apache ]; then
  a2dissite -q netsnap >/dev/null 2>&1 || true
  rm -f /etc/apache2/sites-available/netsnap.conf
  systemctl reload apache2 2>/dev/null || true
else
  rm -f /etc/nginx/sites-enabled/netsnap.conf /etc/nginx/sites-available/netsnap.conf \
        /etc/nginx/netsnap-proxy.conf
  systemctl reload nginx 2>/dev/null || true
fi
echo "[OK] site do $WEB removido (o pacote do $WEB continua instalado)"

rm -rf /opt/netsnap /usr/local/sbin/netsnapctl /var/lib/netsnap-acme
echo "[OK] programa removido"

if sim "Apagar também os dados (snapshots, pacotes de análise, banco com usuários e cofre)?" n; then
  rm -rf /var/lib/netsnap
  echo "[OK] dados apagados"
  if sim "Apagar a configuração e a chave-mestra (/etc/netsnap)? Sem a chave, backups antigos do banco não abrem" n; then
    rm -rf /etc/netsnap
    rm -f /etc/sysctl.d/60-netsnap-ping.conf
    echo "[OK] configuração e chave apagadas"
  fi
  if id netsnap >/dev/null 2>&1 && sim "Remover o usuário de sistema 'netsnap'?" s; then
    userdel netsnap 2>/dev/null || true
    echo "[OK] usuário removido"
  fi
else
  echo "Dados mantidos em /var/lib/netsnap e configuração em /etc/netsnap."
fi
if [ -d /etc/letsencrypt/live ]; then
  echo "Certificados do Let's Encrypt não foram tocados (certbot certificates / certbot delete)."
fi
