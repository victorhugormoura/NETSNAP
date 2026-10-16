#!/bin/bash
# montar.sh — monta o pacote de instalação do servidor netsnap
#
#   ./servidor/montar.sh            pasta servidor/build/netsnap-servidor
#   ./servidor/montar.sh --zip      a pasta e servidor/dist/netsnap-servidor-<versão>.zip
#
# O pacote junta o núcleo do netsnap (raiz do repositório) com os módulos,
# telas e scripts desta pasta. É ele que vai para o servidor: o instalar.sh
# precisa da estrutura app/ montada aqui.
#
# Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
# Licenciado sob a licença MIT.

set -euo pipefail
export LC_ALL=C

AQUI=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$AQUI/.." && pwd)
VERSAO=$(cat "$AQUI/VERSAO")
DEST="$AQUI/build/netsnap-servidor"

NUCLEO="netsnap.py netsnap_md.py netsnap_topologia.py netsnap_desenho.py
        netsnap_transporte.py netdiag.py netcve.py netsnap_web.py"

rm -rf "$AQUI/build"
mkdir -p "$DEST/app/web" "$DEST/testes"

for f in $NUCLEO; do cp "$REPO/$f" "$DEST/app/"; done
cp "$REPO/LICENSE" "$DEST/app/"
cp "$REPO"/web/index.html "$REPO"/web/app.js "$REPO"/web/app.css "$DEST/app/web/"
cp "$AQUI"/*.py "$DEST/app/"
cp "$AQUI"/web/* "$DEST/app/web/"
cp "$AQUI"/testes/*.py "$DEST/testes/"
cp "$REPO/LICENSE" "$DEST/"
for f in instalar.sh desinstalar.sh LEIA-ME.md requirements.lock VERSAO; do
  cp "$AQUI/$f" "$DEST/"
done
chmod 755 "$DEST"/*.sh
find "$DEST" -name '__pycache__' -prune -exec rm -rf {} +

if [ "${1:-}" = "--zip" ]; then
  mkdir -p "$AQUI/dist"
  ZIP="$AQUI/dist/netsnap-servidor-$VERSAO.zip"
  rm -f "$ZIP"
  # Ordem e datas fixas: o mesmo commit gera o mesmo zip (sha256 conferível).
  DATA=$(git -C "$REPO" log -1 --format=%cd --date=format:%Y%m%d%H%M.%S 2>/dev/null || date +%Y%m%d%H%M.%S)
  find "$DEST" -exec touch -h -t "$DATA" {} +
  (cd "$AQUI/build" && find netsnap-servidor -type f | sort | zip -X -q -@ "$ZIP")
  echo "$ZIP"
  (cd "$AQUI/dist" && sha256sum "$(basename "$ZIP")")
else
  echo "$DEST"
fi
