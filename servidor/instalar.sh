#!/bin/bash
# instalar.sh — instala ou atualiza o servidor netsnap
#
# Debian 12+ ou Ubuntu 22.04+, com systemd. Execute como root, de dentro da
# pasta extraída do pacote:   sudo ./instalar.sh
#
# Tudo é perguntado com um valor padrão entre colchetes; Enter aceita.
#
# Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
# Licenciado sob a licença MIT.

set -euo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

AQUI=$(cd "$(dirname "$0")" && pwd)
VERSAO=$(cat "$AQUI/VERSAO" 2>/dev/null || echo "?")
PREFIXO=/opt/netsnap
ETC=/etc/netsnap
DADOS=/var/lib/netsnap
USUARIO=netsnap
PORTA_INTERNA=8765
CTL=/usr/local/sbin/netsnapctl

# ---------------------------------------------------------------------------
# Saída e perguntas
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  N=$'\e[1m'; V=$'\e[32m'; A=$'\e[33m'; R=$'\e[31m'; F=$'\e[0m'
else
  N=""; V=""; A=""; R=""; F=""
fi
titulo() { printf '\n%s== %s ==%s\n' "$N" "$1" "$F"; }
ok()     { printf '%s[OK]%s %s\n' "$V" "$F" "$1"; }
aviso()  { printf '%s[!]%s %s\n' "$A" "$F" "$1"; }
falha()  { printf '%s[ERRO]%s %s\n' "$R" "$F" "$1" >&2; exit 1; }

perguntar() {  # perguntar "texto" "padrão" -> RESPOSTA
  local texto=$1 padrao=${2:-}
  if [ -n "$padrao" ]; then
    read -r -p "$texto [$padrao]: " RESPOSTA || falha "entrada encerrada"
    RESPOSTA=${RESPOSTA:-$padrao}
  else
    read -r -p "$texto: " RESPOSTA || falha "entrada encerrada"
  fi
}

sim() {  # sim "pergunta" s|n
  local padrao=${2:-s} op r
  if [ "$padrao" = s ]; then op="S/n"; else op="s/N"; fi
  while true; do
    read -r -p "$1 [$op]: " r || falha "entrada encerrada"
    r=${r:-$padrao}
    case "${r,,}" in
      s|sim|y|yes) return 0 ;;
      n|nao|não|no) return 1 ;;
    esac
  done
}

escolher() {  # escolher "título" padrão "op1" "op2" ... -> ESCOLHA (número)
  local tit=$1 padrao=$2 i=1
  shift 2
  echo "$tit"
  for op in "$@"; do echo "  $i) $op"; i=$((i + 1)); done
  while true; do
    perguntar "Opção" "$padrao"
    if [[ "$RESPOSTA" =~ ^[0-9]+$ ]] && [ "$RESPOSTA" -ge 1 ] && [ "$RESPOSTA" -le $# ]; then
      ESCOLHA=$RESPOSTA
      return
    fi
  done
}

trap 'falha "instalação interrompida na linha $LINENO. Corrija o problema e rode o instalador de novo: ele retoma sem perder dados."' ERR

valido_cidr() {
  python3 -I - "$1" <<'PY'
import ipaddress, sys
try:
    for r in sys.argv[1].split(","):
        if r.strip():
            ipaddress.ip_network(r.strip(), strict=False)
except ValueError:
    sys.exit(1)
PY
}

valido_nome() {  # FQDN, nome simples ou IP
  python3 -I - "$1" <<'PY'
import ipaddress, re, sys
n = sys.argv[1].strip()
try:
    ipaddress.ip_address(n)
    sys.exit(0)
except ValueError:
    pass
ok = re.fullmatch(r"(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
                  r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", n)
sys.exit(0 if ok else 1)
PY
}

eh_ip() { python3 -I -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Pré-requisitos
# ---------------------------------------------------------------------------
titulo "netsnap servidor $VERSAO"
[ "$(id -u)" -eq 0 ] || falha "execute como root: sudo ./instalar.sh"
if [ ! -d "$AQUI/app" ] || [ ! -f "$AQUI/requirements.lock" ]; then
  falha "rode de dentro da pasta extraída do pacote (no repositório, monte antes com servidor/montar.sh)"
fi
[ -r /etc/os-release ] || falha "sistema não identificado (/etc/os-release)"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian) [ "${VERSION_ID%%.*}" -ge 12 ] 2>/dev/null || falha "Debian 12 ou mais novo é necessário (encontrado ${PRETTY_NAME:-?})" ;;
  ubuntu) [ "${VERSION_ID%%.*}" -ge 22 ] 2>/dev/null || falha "Ubuntu 22.04 ou mais novo é necessário (encontrado ${PRETTY_NAME:-?})" ;;
  *) falha "sistema não suportado: ${PRETTY_NAME:-desconhecido}. Use Debian 12+ ou Ubuntu 22.04+." ;;
esac
command -v systemctl >/dev/null || falha "systemd é necessário"
command -v python3 >/dev/null || { apt-get update -q && apt-get install -y -q python3; }
python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 10))' || falha "Python 3.10 ou mais novo é necessário"
ok "${PRETTY_NAME}, Python $(python3 -I -c 'import platform; print(platform.python_version())')"

MODO=nova
if [ -f "$ETC/instalacao.conf" ]; then
  titulo "Instalação existente encontrada"
  escolher "O que fazer?" 1 \
    "Atualizar o programa (mantém dados, usuários, cofre, configuração e chave)" \
    "Refazer a configuração do servidor web e do certificado" \
    "Cancelar"
  case "$ESCOLHA" in
    1) MODO=atualizar ;;
    2) MODO=reconfigurar ;;
    3) exit 0 ;;
  esac
fi

# ---------------------------------------------------------------------------
# Perguntas (instalação nova ou reconfiguração)
# ---------------------------------------------------------------------------
ler_ini() { python3 -I - "$ETC/instalacao.conf" "$1" "$2" <<'PY'
import configparser, sys
cp = configparser.ConfigParser(); cp.read(sys.argv[1])
print(cp.get("instalacao", sys.argv[2], fallback=sys.argv[3]))
PY
}

if [ "$MODO" != atualizar ]; then
  titulo "Acesso"
  HOST_PADRAO=$(hostname -f 2>/dev/null || hostname)
  IP_PADRAO=$({ ip -4 route get 1.1.1.1 2>/dev/null || true; } | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  if [ "$MODO" = reconfigurar ]; then
    NOMES_ATUAIS=$(ler_ini nomes "")
    HOST_PADRAO=${NOMES_ATUAIS%%,*}
    EXTRAS_PADRAO=${NOMES_ATUAIS#*,}
    [ "$EXTRAS_PADRAO" = "$NOMES_ATUAIS" ] && EXTRAS_PADRAO=""
  else
    EXTRAS_PADRAO=$IP_PADRAO
  fi
  echo "Nome pelo qual os técnicos acessam o painel (DNS ou IP). Ele vai no certificado."
  while true; do
    perguntar "Nome principal" "$HOST_PADRAO"
    NOME=$RESPOSTA
    valido_nome "$NOME" && break
    aviso "nome inválido"
  done
  echo "Outros nomes ou IPs que também abrem o painel, separados por vírgula (vazio = nenhum)."
  while true; do
    perguntar "Outros nomes/IPs" "${EXTRAS_PADRAO:--}"
    EXTRAS=${RESPOSTA//[[:space:]]/}
    [ "$EXTRAS" = "-" ] && EXTRAS=""
    bom=1
    IFS=',' read -r -a lista <<< "$EXTRAS"
    for n in "${lista[@]}"; do
      [ -z "$n" ] && continue
      valido_nome "$n" || { aviso "nome inválido: $n"; bom=0; }
    done
    [ "$bom" = 1 ] && break
  done
  NOMES=$NOME
  [ -n "$EXTRAS" ] && NOMES="$NOME,$EXTRAS"

  titulo "Servidor web"
  PADRAO_WEB=1
  if command -v apache2 >/dev/null && ! command -v nginx >/dev/null; then PADRAO_WEB=2; fi
  [ "$MODO" = reconfigurar ] && [ "$(ler_ini servidor_web nginx)" = apache ] && PADRAO_WEB=2
  escolher "Qual servidor web vai publicar o painel com HTTPS?" "$PADRAO_WEB" "Nginx (recomendado)" "Apache 2"
  if [ "$ESCOLHA" = 1 ]; then WEB=nginx; PACOTE_WEB=nginx; else WEB=apache; PACOTE_WEB=apache2; fi

  while true; do
    perguntar "Porta HTTPS" "$( [ "$MODO" = reconfigurar ] && ler_ini porta_https 443 || echo 443)"
    PORTA=$RESPOSTA
    [[ "$PORTA" =~ ^[0-9]+$ ]] && [ "$PORTA" -ge 1 ] && [ "$PORTA" -le 65535 ] && [ "$PORTA" != "$PORTA_INTERNA" ] && break
    aviso "porta inválida"
  done

  echo
  echo "Restringir o acesso ao painel a algumas redes (ex.: rede de gerência e VPN)?"
  echo "Separe por vírgula, em CIDR (10.0.0.0/8,192.168.10.0/24). Vazio = qualquer origem."
  while true; do
    REDES_ATUAIS=""
    [ "$MODO" = reconfigurar ] && REDES_ATUAIS=$(ler_ini redes_permitidas "")
    perguntar "Redes permitidas" "${REDES_ATUAIS:--}"
    REDES=${RESPOSTA//[[:space:]]/}
    [ "$REDES" = "-" ] && REDES=""
    { [ -z "$REDES" ] || valido_cidr "$REDES"; } && break
    aviso "rede inválida"
  done
  [ -z "$REDES" ] && aviso "sem restrição de origem: o login (senha + TOTP) é a única barreira. Prefira limitar às redes de gerência."

  titulo "Certificado HTTPS"
  TEM_IP=0
  IFS=',' read -r -a lista <<< "$NOMES"
  for n in "${lista[@]}"; do eh_ip "$n" && TEM_IP=1; done
  escolher "Como obter o certificado?" 1 \
    "CA interna do netsnap (rede interna; funciona com IP; técnicos instalam a CA uma vez)" \
    "Let's Encrypt (nome DNS público e porta 80 aberta para a internet)" \
    "Importar certificado próprio (arquivos PEM do certificado e da chave)"
  case "$ESCOLHA" in
    1) CERT=ca-interna ;;
    2) CERT=letsencrypt
       if [ "$TEM_IP" = 1 ]; then
         aviso "Let's Encrypt não emite para IP aqui. Tire os IPs da lista de nomes ou use a CA interna."
         falha "lista de nomes com IP"
       fi
       while true; do
         perguntar "E-mail para avisos de expiração" ""
         EMAIL=$RESPOSTA
         [[ "$EMAIL" == *@*.* ]] && break
       done ;;
    3) CERT=importado
       while true; do perguntar "Arquivo do certificado (PEM)" ""; CERT_ARQ=$RESPOSTA; [ -r "$CERT_ARQ" ] && break; aviso "arquivo não encontrado"; done
       while true; do perguntar "Arquivo da chave privada (PEM)" ""; CHAVE_ARQ=$RESPOSTA; [ -r "$CHAVE_ARQ" ] && break; aviso "arquivo não encontrado"; done
       perguntar "Cadeia intermediária (PEM, vazio se já está no certificado)" "-"
       CADEIA_ARQ=$RESPOSTA; [ "$CADEIA_ARQ" = "-" ] && CADEIA_ARQ="" ;;
  esac

  if [ "$MODO" = nova ]; then
    titulo "Coletas"
    while true; do
      perguntar "Dias para guardar snapshots (o último de cada equipamento nunca é apagado; 0 = para sempre)" 180
      RETENCAO=$RESPOSTA; [[ "$RETENCAO" =~ ^[0-9]+$ ]] && break
    done
    echo "Execuções simultâneas: cada uma usa até 10 conexões SSH."
    while true; do
      perguntar "Máximo de execuções ao mesmo tempo" 3
      MAXEXEC=$RESPOSTA; [[ "$MAXEXEC" =~ ^[0-9]+$ ]] && [ "$MAXEXEC" -ge 1 ] && break
    done
    if sim "Permitir coletas por Telnet (OLTs antigas)? O Telnet trafega senha em texto claro" s; then TELNET=sim; else TELNET=nao; fi

    FUSO=$(timedatectl show -p Timezone --value 2>/dev/null || echo "?")
    echo "Os agendamentos usam o horário deste servidor. Fuso atual: $FUSO"
    if [[ "$FUSO" == "Etc/UTC" || "$FUSO" == "UTC" ]] && sim "Ajustar para America/Sao_Paulo?" s; then
      AJUSTAR_FUSO=1
    fi
  fi

  if [ "$MODO" = nova ]; then
    DESATIVAR_PADRAO=0
    SITE_PADRAO=""
    [ "$WEB" = nginx ] && [ -e /etc/nginx/sites-enabled/default ] && SITE_PADRAO=1
    [ "$WEB" = apache ] && [ -e /etc/apache2/sites-enabled/000-default.conf ] && SITE_PADRAO=1
    if [ -n "$SITE_PADRAO" ]; then
      sim "Desativar o site padrão do $WEB (recomendado em servidor dedicado)?" s && DESATIVAR_PADRAO=1
    fi
  fi

  UFW=0
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    sim "O firewall ufw está ativo. Liberar a porta $PORTA/tcp$( [ "$CERT" = letsencrypt ] && echo " e 80/tcp")?" s && UFW=1
  fi

  PING_RANGE=$( (sysctl -n net.ipv4.ping_group_range 2>/dev/null || echo "1 0") | tr -s "[:space:]" " " | sed "s/ $//")
  PING_FIX=0
  if [ "${PING_RANGE%%[[:space:]]*}" -gt "${PING_RANGE##*[[:space:]]}" ] 2>/dev/null; then
    echo "A varredura por ping roda sem privilégio e precisa de net.ipv4.ping_group_range (hoje: $PING_RANGE)."
    sim "Liberar ping sem privilégio (arquivo /etc/sysctl.d/60-netsnap-ping.conf)?" s && PING_FIX=1
  fi

  titulo "Resumo"
  echo "  Endereço:        https://$NOME$( [ "$PORTA" != 443 ] && echo ":$PORTA")/"
  echo "  Nomes:           $NOMES"
  echo "  Servidor web:    $WEB"
  echo "  Redes:           ${REDES:-qualquer origem}"
  echo "  Certificado:     $CERT"
  [ "$MODO" = nova ] && echo "  Retenção:        $RETENCAO dias · até $MAXEXEC execuções · Telnet: $TELNET"
  echo "  Programa:        $PREFIXO   Dados: $DADOS   Configuração: $ETC"
  sim "Continuar?" s || exit 0
fi

# ---------------------------------------------------------------------------
# Pacotes do sistema
# ---------------------------------------------------------------------------
if [ "$MODO" = atualizar ]; then
  WEB=$(ler_ini servidor_web nginx)
  PACOTE_WEB=$([ "$WEB" = nginx ] && echo nginx || echo apache2)
  CERT=$(ler_ini certificado ca-interna)
fi
titulo "Pacotes do sistema"
PACOTES=(python3 python3-venv qrencode ca-certificates iputils-ping openssl "$PACOTE_WEB")
[ "$CERT" = letsencrypt ] && PACOTES+=(certbot)
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends "${PACOTES[@]}"
ok "instalados: ${PACOTES[*]}"

# ---------------------------------------------------------------------------
# Usuário, pastas e programa
# ---------------------------------------------------------------------------
titulo "Programa"
if ! id "$USUARIO" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$DADOS" --no-create-home \
    --shell /usr/sbin/nologin --comment "netsnap servidor" "$USUARIO"
  ok "usuário de serviço '$USUARIO' criado"
fi
install -d -m 755 -o root -g root "$PREFIXO" "$ETC"
install -d -m 700 -o root -g root "$ETC/credenciais" "$ETC/pki"
install -d -m 700 -o "$USUARIO" -g "$USUARIO" "$DADOS"

rm -rf "$PREFIXO/app.novo"
cp -r "$AQUI/app" "$PREFIXO/app.novo"
find "$PREFIXO/app.novo" -name '__pycache__' -prune -exec rm -rf {} +
chown -R root:root "$PREFIXO/app.novo"
find "$PREFIXO/app.novo" -type d -exec chmod 755 {} +
find "$PREFIXO/app.novo" -type f -exec chmod 644 {} +
if [ -d "$PREFIXO/app" ]; then
  rm -rf "$PREFIXO/app.anterior"
  mv "$PREFIXO/app" "$PREFIXO/app.anterior"
fi
mv "$PREFIXO/app.novo" "$PREFIXO/app"
for f in LEIA-ME.md VERSAO requirements.lock desinstalar.sh; do
  [ -f "$AQUI/$f" ] && install -m 644 -o root -g root "$AQUI/$f" "$PREFIXO/$f"
done
chmod 755 "$PREFIXO/desinstalar.sh" 2>/dev/null || true
ok "programa em $PREFIXO/app"

PY_SISTEMA=$(python3 -I -c 'import platform; print(platform.python_version())')
if [ ! -x "$PREFIXO/venv/bin/python" ] || [ "$("$PREFIXO/venv/bin/python" -I -c 'import platform; print(platform.python_version())' 2>/dev/null)" != "$PY_SISTEMA" ]; then
  rm -rf "$PREFIXO/venv"
  python3 -I -m venv "$PREFIXO/venv"
fi
echo "Instalando dependências Python com conferência de hash (netmiko, cryptography)..."
"$PREFIXO/venv/bin/pip" install -q --disable-pip-version-check --no-cache-dir \
  --require-hashes --no-deps -r "$PREFIXO/requirements.lock"
ok "dependências instaladas em $PREFIXO/venv"

cat > "$CTL" <<EOF
#!/bin/sh
# Gerado pelo instalador do netsnap.
exec $PREFIXO/venv/bin/python -I $PREFIXO/app/netsnapctl.py "\$@"
EOF
chmod 755 "$CTL"
ok "comando de administração: netsnapctl"

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
if [ "$MODO" != atualizar ]; then
  titulo "Configuração"
  if [ "$MODO" = nova ]; then
    if systemctl --version | awk 'NR==1 {exit !($2 >= 250)}' && command -v systemd-creds >/dev/null; then
      MODO_CHAVE=credencial
    else
      MODO_CHAVE=arquivo
    fi
  else
    MODO_CHAVE=$(ler_ini modo_chave arquivo)
  fi
  # Valores pelo ambiente, nunca interpolados no código Python.
  I_WEB=$WEB I_NOMES=$NOMES I_PORTA=$PORTA I_PORTA_INTERNA=$PORTA_INTERNA \
  I_REDES=$REDES I_CERT=$CERT I_EMAIL=${EMAIL:-} I_MODO_CHAVE=$MODO_CHAVE \
  I_DADOS=$DADOS "$PREFIXO/venv/bin/python" -I - "$ETC/instalacao.conf" <<'PY'
import configparser, os, sys
cp = configparser.ConfigParser(interpolation=None)
cp.read(sys.argv[1])
if not cp.has_section("instalacao"):
    cp.add_section("instalacao")
s = cp["instalacao"]
for chave, var in (("servidor_web", "I_WEB"), ("nomes", "I_NOMES"),
                   ("porta_https", "I_PORTA"), ("porta_interna", "I_PORTA_INTERNA"),
                   ("redes_permitidas", "I_REDES"), ("certificado", "I_CERT"),
                   ("email_letsencrypt", "I_EMAIL"), ("modo_chave", "I_MODO_CHAVE"),
                   ("dados", "I_DADOS")):
    s[chave] = os.environ[var].replace("\n", "")
with open(sys.argv[1], "w") as f:
    f.write("# Gerado pelo instalador do netsnap.\n")
    cp.write(f)
PY
  chmod 644 "$ETC/instalacao.conf"

  NOMES_SERVIDOR=$NOMES
  RETENCAO=${RETENCAO:-180}; MAXEXEC=${MAXEXEC:-3}; TELNET=${TELNET:-sim}
  if [ "$MODO" = nova ] || [ ! -f "$ETC/servidor.conf" ]; then
    cat > "$ETC/servidor.conf" <<EOF
# Configuração do serviço netsnap-servidor. Depois de editar:
#   systemctl restart netsnap-servidor
[servidor]
endereco = 127.0.0.1
porta = $PORTA_INTERNA
; Nomes aceitos no cabeçalho Host (os mesmos do certificado)
nomes = $NOMES_SERVIDOR
porta_publica = $PORTA
dados = $DADOS

[sessao]
ociosidade_minutos = 30
duracao_maxima_horas = 12
exigir_totp = sim
emissor_totp = netsnap $NOME

[coleta]
max_execucoes_simultaneas = $MAXEXEC
; Snapshots com senhas e communities em claro (só administradores)
permitir_dados_sensiveis = nao
permitir_telnet = $TELNET

[retencao]
snapshots_dias = $RETENCAO
analises_dias = 365
execucoes_dias = 365
EOF
  else
    # Reconfiguração: só nomes e porta pública mudam no servidor.conf.
    "$PREFIXO/venv/bin/python" -I - "$ETC/servidor.conf" "$NOMES_SERVIDOR" "$PORTA" <<'PY'
import re, sys
caminho, nomes, porta = sys.argv[1:]
texto = open(caminho, encoding="utf-8").read()
texto = re.sub(r"(?m)^nomes\s*=.*$", f"nomes = {nomes}", texto)
texto = re.sub(r"(?m)^porta_publica\s*=.*$", f"porta_publica = {porta}", texto)
open(caminho, "w", encoding="utf-8").write(texto)
PY
  fi
  chown root:"$USUARIO" "$ETC/servidor.conf"
  chmod 640 "$ETC/servidor.conf"
  ok "configuração em $ETC"

  if [ "${AJUSTAR_FUSO:-0}" = 1 ]; then
    timedatectl set-timezone America/Sao_Paulo && ok "fuso horário: America/Sao_Paulo"
  fi
  if [ "${PING_FIX:-0}" = 1 ]; then
    echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/60-netsnap-ping.conf
    sysctl -q -p /etc/sysctl.d/60-netsnap-ping.conf && ok "ping sem privilégio liberado"
  fi
fi

# ---------------------------------------------------------------------------
# Chave, banco e serviço
# ---------------------------------------------------------------------------
titulo "Cofre e serviço"
"$CTL" chave criar
"$CTL" inicializar
"$CTL" systemd instalar
systemctl restart netsnap-servidor

echo -n "Aguardando o serviço responder"
for _ in $(seq 1 40); do
  if "$PREFIXO/venv/bin/python" -I - <<'PY' 2>/dev/null
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect("/run/netsnap/netsnap.sock")
s.sendall(b"GET /api/saude HTTP/1.0\r\nHost: localhost\r\n\r\n")
resposta = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    resposta += d
corpo = resposta.split(b"\r\n\r\n", 1)[1]
sys.exit(0 if json.loads(corpo).get("ok") else 1)
PY
  then echo; ok "serviço respondendo"; SERVICO_OK=1; break; fi
  echo -n "."; sleep 1
done
if [ "${SERVICO_OK:-0}" != 1 ]; then
  echo
  journalctl -u netsnap-servidor -n 30 --no-pager || true
  if [ "$MODO" = atualizar ] && [ -d "$PREFIXO/app.anterior" ]; then
    aviso "o serviço não subiu com a versão nova; voltando à anterior"
    rm -rf "$PREFIXO/app"
    mv "$PREFIXO/app.anterior" "$PREFIXO/app"
    systemctl restart netsnap-servidor
  fi
  falha "o serviço netsnap-servidor não respondeu (veja o log acima: journalctl -u netsnap-servidor)"
fi

# ---------------------------------------------------------------------------
# Certificado e servidor web
# ---------------------------------------------------------------------------
titulo "HTTPS"
if [ "$MODO" = atualizar ]; then
  # Recria a CA interna se o modelo dela for de versão anterior.
  if [ "$CERT" = ca-interna ]; then "$CTL" certificado renovar --se-necessario; fi
  "$CTL" web configurar
else
  if [ "${DESATIVAR_PADRAO:-0}" = 1 ]; then
    if [ "$WEB" = nginx ]; then rm -f /etc/nginx/sites-enabled/default
    else a2dissite -q 000-default >/dev/null 2>&1 || true; fi
    ok "site padrão do $WEB desativado"
  fi
  # Firewall antes do certificado: o Let's Encrypt precisa da porta 80.
  if [ "$UFW" = 1 ]; then
    ufw allow "$PORTA/tcp" >/dev/null && ok "ufw: porta $PORTA/tcp liberada"
    if [ "$CERT" = letsencrypt ]; then ufw allow 80/tcp >/dev/null && ok "ufw: porta 80/tcp liberada"; fi
  fi
  case "$CERT" in
    ca-interna)  "$CTL" certificado ca-interna ;;
    importado)   "$CTL" certificado importar --cert "$CERT_ARQ" --chave "$CHAVE_ARQ" ${CADEIA_ARQ:+--cadeia "$CADEIA_ARQ"} ;;
    letsencrypt) "$CTL" certificado letsencrypt --email "$EMAIL" ;;
  esac
fi

# Conferência de ponta a ponta: TLS no nome principal, passando pelo proxy.
NOME_PRINCIPAL=$(ler_ini nomes localhost); NOME_PRINCIPAL=${NOME_PRINCIPAL%%,*}
PORTA_PUB=$(ler_ini porta_https 443)
if "$PREFIXO/venv/bin/python" -I - "$NOME_PRINCIPAL" "$PORTA_PUB" "$ETC/pki/ca.crt" "$(ler_ini certificado ca-interna)" <<'PY'
import http.client, os, socket, ssl, sys
nome, porta, ca, modo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(cafile=ca if modo == "ca-interna" and os.path.exists(ca) else None)
bruto = socket.create_connection(("127.0.0.1", porta), timeout=10)
tls = ctx.wrap_socket(bruto, server_hostname=nome)
c = http.client.HTTPSConnection(nome, porta, context=ctx)
c.sock = tls
c.request("GET", "/", headers={"Host": nome})
sys.exit(0 if c.getresponse().status == 200 else 1)
PY
then
  ok "HTTPS conferido de ponta a ponta em https://$NOME_PRINCIPAL$( [ "$PORTA_PUB" != 443 ] && echo ":$PORTA_PUB")"
else
  aviso "não consegui abrir https://$NOME_PRINCIPAL:$PORTA_PUB por aqui (pode ser só resolução de nome/certificado nesta máquina). Teste pelo navegador."
fi

# ---------------------------------------------------------------------------
# Administrador e cópia da chave
# ---------------------------------------------------------------------------
# Também numa retomada: se a instalação anterior parou antes desta etapa,
# ainda não há administrador.
ADMIN_CRIADO=0
titulo "Administrador inicial"
RC=0
"$CTL" usuario criar --inicial --se-necessario || RC=$?
case "$RC" in
  0) ADMIN_CRIADO=1 ;;
  3) ;;
  *) falha "não foi possível criar o administrador (rode: sudo netsnapctl usuario criar --inicial)" ;;
esac

if [ "$ADMIN_CRIADO" = 1 ]; then
  MODO_CHAVE=${MODO_CHAVE:-$(ler_ini modo_chave arquivo)}
  titulo "Cópia da chave-mestra"
  echo "Sem a chave-mestra, o cofre e o backup do banco não abrem em outra máquina."
  [ "$MODO_CHAVE" = credencial ] && echo "Ela está selada neste servidor (systemd-creds/TPM): se o disco ou a placa-mãe morrer, só a cópia salva."
  if sim "Exportar agora uma cópia protegida por frase? (recomendado)" s; then
    "$CTL" chave exportar
  else
    aviso "lembre-se: netsnapctl chave exportar"
  fi
fi

rm -rf "$PREFIXO/app.anterior"
trap - ERR
titulo "Pronto"
echo "  Painel:        https://$NOME_PRINCIPAL$( [ "$PORTA_PUB" != 443 ] && echo ":$PORTA_PUB")/"
[ "$(ler_ini certificado ca-interna)" = ca-interna ] && echo "  CA interna:    baixe pela tela de login e instale como autoridade raiz confiável"
echo "  Administração: sudo netsnapctl          (menu)"
echo "                 sudo netsnapctl status"
echo "  Logs:          journalctl -u netsnap-servidor -f"
echo "  Manual:        $PREFIXO/LEIA-ME.md"
