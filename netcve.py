#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netcve — Triagem de vulnerabilidades a partir de snapshots do netsnap

Lê os arquivos Markdown gerados pelo netsnap, extrai versões de software e
indicadores de configuração insegura e cruza com:

- NVD (NIST), por CPE, para sistemas de equipamentos e aplicações;
- OSV.dev, por pacote-fonte e versão exata, para os pacotes de servidores
  Debian, Ubuntu, Rocky Linux e AlmaLinux (respeita as correções que essas
  distribuições retroportam sem mudar o número de versão);
- CISA KEV (exploração confirmada) e EPSS (probabilidade de exploração);
- um catálogo próprio de falhas graves, com a condição de configuração que
  torna o equipamento explorável (PHP2Shell, MikroTrick e outras).

Gera um relatório Markdown e, com --json, a mesma informação em JSON para
integração (painel, API, análise por IA).

Não acessa equipamentos: opera exclusivamente sobre os snapshots já coletados.

IMPORTANTE — natureza do resultado:
A correspondência é feita por versão declarada e por heurísticas de
configuração. Isso produz FALSOS POSITIVOS (correções retroportadas pelo
fabricante na mesma versão, recursos não habilitados, mitigações externas) e
FALSOS NEGATIVOS (cobertura CPE incompleta na NVD para equipamentos de rede,
sobretudo OLTs e plataformas regionais). O resultado é uma triagem para
priorizar investigação, não um laudo de vulnerabilidade. A fonte autoritativa
é sempre o PSIRT/boletim do fabricante.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "0.4.0"

import os
import re
import sys
import csv
import ssl
import json
import time
import argparse
import importlib.util
import math
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_LOTE = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
CACHE = os.path.join(os.path.expanduser("~"), ".netcve_cache.json")
UA = f"netcve/{__version__} (network inventory triage)"

# Limites publicados pela NVD: 5 req/30s sem chave, 50 req/30s com chave.
DELAY_SEM_CHAVE = 6.5
DELAY_COM_CHAVE = 0.8


# ---------------------------------------------------------------------------
# Extração de versões dos snapshots
#
# Cada entrada: (regex, fornecedor_cpe, produto_cpe, rotulo)
# O grupo 1 da regex deve capturar a versão.
# ---------------------------------------------------------------------------
MAPA_VERSAO = {
    "juniper_junos": [
        (r"(?im)^[ \t]*Junos:\s*([0-9][\w.\-]+)", "juniper", "junos", "Junos"),
        # A configuração em 'display set' declara a release; permite triagem
        # mesmo em snapshot coletado apenas no modo Configuração.
        (r"(?im)^set version\s+([0-9][\w.\-]+)", "juniper", "junos", "Junos"),
        (r"(?im)^[ \t]*version\s+([0-9]+\.[0-9]+[A-Z][\w.\-]*)",
         "juniper", "junos", "Junos"),
        (r"(?i)JUNOS\s+(?:Software\s+Release\s+)?\[?([0-9][\w.\-]+)\]?",
         "juniper", "junos", "Junos"),
    ],
    # A NVD não cataloga o VRP como produto único: os CPEs Huawei são por
    # modelo (ex.: s6730-h_firmware), e "huawei:vrp" não retorna nada. Sem
    # mapeamento modelo -> CPE, a versão é listada como não consultável em
    # vez de aparecer como "nenhuma CVE".
    "huawei": [
        (r"(?i)\b(V\d{3}R\d{3}C\d{2}(?:SPC\d+)?)", None, None, "VRP"),
        (r"(?i)VRP\s*\(R\)\s*software,?\s*Version\s*([0-9][\w.]*)",
         None, None, "VRP"),
    ],
    "huawei_ce": [
        (r"(?i)\b(V\d{3}R\d{3}C\d{2}(?:SPC\d+)?)", None, None, "VRP V8"),
        (r"(?i)Version\s+(8\.\d+)", None, None, "VRP V8"),
    ],
    # 'display version' traz o modelo colado à versão (MA5800V100R019C10),
    # por isso a âncora é "não precedido de letra", e não \b.
    "huawei_smartax": [
        (r"(?i)(?<![A-Za-z])(V\d{3}R\d{3}C\d{2}(?:SPC\d+)?)", "huawei",
         "ma5800_firmware", "SmartAX"),
    ],
    "cisco_ios": [
        (r"(?i)Cisco IOS XE Software,? Version\s*([0-9][\w.()\-]*)",
         "cisco", "ios_xe", "IOS-XE"),
        (r"(?i)Cisco IOS Software,?.*?Version\s*([0-9][\w.()\-]*)",
         "cisco", "ios", "IOS"),
    ],
    "cisco_nxos": [
        (r"(?im)^[ \t]*(?:system|NXOS):\s*version\s*([0-9][\w.()\-]*)",
         "cisco", "nx-os", "NX-OS"),
        (r"(?im)^version\s+([0-9]+\.[0-9]+\([0-9][\w.)]*)",
         "cisco", "nx-os", "NX-OS"),
    ],
    "cisco_xr": [
        (r"(?i)Cisco IOS XR Software,?.*?Version\s*([0-9][\w.\-]*)",
         "cisco", "ios_xr", "IOS-XR"),
    ],
    "mikrotik_routeros": [
        (r"(?im)^[ \t]*version:\s*([0-9][\w.\-]*)", "mikrotik", "routeros",
         "RouterOS"),
        (r"(?i)RouterOS\s+v?([0-9]+\.[0-9][\w.\-]*)", "mikrotik", "routeros",
         "RouterOS"),
    ],
    "linux": [
        (r"(?i)Linux\s+\S+\s+([0-9]+\.[0-9]+\.[0-9]+)[\w.\-]*",
         "linux", "linux_kernel", "Kernel Linux"),
        (r"(?im)^VERSION_ID=\"?([0-9][\w.]*)\"?", None, None, "Sistema"),
    ],
    "fiberhome": [
        (r"(?i)version\s*[:\s]\s*([A-Z0-9][\w.\-]{3,})", None, None,
         "FiberHome"),
    ],
}

# Softwares de aplicação procurados em qualquer snapshot
MAPA_APP = [
    # Apenas a versão upstream: sufixos de distribuição (-0ubuntu0.22.04.1)
    # não existem na base CPE e quebrariam a correspondência.
    # A âncora evita casar 'rpcbind 1.2.6' no inventário de pacotes, que
    # vem antes de 'named -v' e escondia a versão real do BIND.
    (r"(?i)(?<![\w-])BIND\s+(9\.[0-9]+\.[0-9]+(?:-?P[0-9]+|-S[0-9]+)?)",
     "isc", "bind", "BIND"),
    (r"(?i)OpenSSH[_\s]([0-9]+\.[0-9]+(?:p[0-9])?)", "openbsd", "openssh",
     "OpenSSH"),
    (r"(?i)\bnginx/([0-9]+\.[0-9]+\.[0-9]+)", "f5", "nginx", "nginx"),
    (r"(?i)Apache/([0-9]+\.[0-9]+\.[0-9]+)", "apache", "http_server",
     "Apache httpd"),
    # 'php -v' do inventário Linux: "PHP 8.3.6 (cli) (built: ...)"
    (r"(?m)^PHP ([5-9]\.[0-9]+\.[0-9]+)\b", "php", "php", "PHP"),
    # Daemons BGP da mitigação do Wanguard. GoBGP em binário do GitHub não
    # aparece no gerenciador de pacotes: a versão vem do 'gobgpd --version'.
    (r"(?im)^gobgpd? version v?([0-9]+\.[0-9]+\.[0-9]+)", "osrg", "gobgp",
     "GoBGP"),
    (r"(?im)^(?:frr version|FRRouting) ([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
     "frrouting", "frrouting", "FRRouting"),
]

# Software que, num servidor com pacotes da distribuição, é avaliado pelo
# OSV (versão exata do pacote) em vez da NVD (versão upstream, que ignora as
# correções retroportadas). Rótulo -> regex do pacote-fonte.
COBERTO_PELO_OSV = {
    "BIND": r"^bind9?$",
    "OpenSSH": r"^openssh$",
    "nginx": r"^nginx$",
    "Apache httpd": r"^(apache2|httpd)$",
    "PHP": r"^php(\d+(\.\d+)?)?$",
    "GoBGP": r"^gobgp$",
    "FRRouting": r"^frr$",
    # O OSV avalia o pacote do kernel instalado; o kernel em execução pode
    # ser mais antigo se falta reiniciar.
    "Kernel Linux": r"^(linux|linux-signed(-\w+)?|kernel)$",
}

# ---------------------------------------------------------------------------
# Regras de configuração insegura (heurísticas locais, sem consulta externa)
# ---------------------------------------------------------------------------
REGRAS_CONFIG = [
    {
        "id": "CFG-TELNET",
        "titulo": "Telnet habilitado (credenciais em texto claro)",
        "severidade": "ALTA",
        "plataformas": None,
        "padrao": r"(?im)^[ \t]*(?:set\s+system\s+services\s+telnet|"
                  r"telnet\s+server\s+enable|"
                  r"transport\s+input\s+(?:all|telnet))",
        "recomendacao": "Desabilitar Telnet e usar exclusivamente SSHv2.",
    },
    {
        "id": "CFG-SNMP-COMUNIDADE-PADRAO",
        "titulo": "Community SNMP padrão ou trivial (public/private)",
        "severidade": "ALTA",
        "plataformas": None,
        # Ancorado à declaração SNMP: 'community' solto casava nomes de
        # community BGP (policy-options community private ...).
        "padrao": r"(?im)(?:snmp-server\s+community|snmp-agent\s+community"
                  r"(?:\s+(?:read|write))?(?:\s+cipher)?|"
                  r"set\s+snmp\s+community|^\s*r[ow]community6?)"
                  r"\s+[\"']?(public|private|cisco|admin)[\"']?(?![\w-])",
        "recomendacao": "Substituir a community e restringir por ACL; "
                        "migrar para SNMPv3 com autenticação e criptografia.",
    },
    {
        "id": "CFG-SNMPV1V2",
        "titulo": "SNMP v1/v2c em uso (sem autenticação nem criptografia)",
        "severidade": "MEDIA",
        "plataformas": None,
        "padrao": r"(?im)(snmp-server\s+community|snmp-agent\s+community|"
                  r"set\s+snmp\s+community|/snmp\s+community)",
        "recomendacao": "Migrar para SNMPv3 (authPriv) e restringir origens.",
    },
    {
        "id": "CFG-HTTP",
        "titulo": "Servidor HTTP de gerência sem TLS habilitado",
        "severidade": "MEDIA",
        "plataformas": None,
        "padrao": r"(?im)^[ \t]*(?:ip\s+http\s+server|"
                  r"set\s+system\s+services\s+web-management\s+http\b|"
                  r"http\s+server\s+enable)",
        "recomendacao": "Desabilitar HTTP ou usar somente HTTPS com "
                        "certificado válido e ACL de gerência.",
    },
    {
        "id": "CFG-MIKROTIK-SERVICOS",
        "titulo": "Serviços legados do RouterOS expostos (api/ftp/telnet/www)",
        "severidade": "ALTA",
        "plataformas": ["mikrotik_routeros"],
        # Saída de '/ip service print': serviço desabilitado traz a flag X
        # entre o índice e o nome; habilitado não traz flag. O export não
        # serve, porque serviço habilitado é o padrão e não aparece nele.
        "padrao": r"(?im)^[ \t]*\d+\s+(telnet|ftp|www|api)\s+\d+",
        "recomendacao": "Desabilitar serviços não utilizados em "
                        "/ip service e restringir 'available from'.",
    },
    {
        "id": "CFG-SSH-SENHA-ROOT",
        "titulo": "Login SSH direto como root permitido",
        "severidade": "ALTA",
        "plataformas": ["linux"],
        "padrao": r"(?im)^[ \t]*PermitRootLogin\s+yes",
        "recomendacao": "Definir PermitRootLogin no (ou prohibit-password) "
                        "e usar chaves com sudo.",
    },
    {
        "id": "CFG-DNS-RECURSAO-ABERTA",
        "titulo": "Possível recursão DNS sem restrição de origem",
        "severidade": "ALTA",
        "plataformas": ["linux"],
        "padrao": r"(?is)recursion\s+yes.*?allow-recursion\s*\{\s*any\s*;",
        "recomendacao": "Restringir allow-recursion às redes do provedor; "
                        "recursor aberto é usado em ataques de amplificação.",
    },
    {
        "id": "CFG-BIND-VERSAO-EXPOSTA",
        "titulo": "Versão do BIND exposta em consultas version.bind",
        "severidade": "BAIXA",
        "plataformas": ["linux"],
        "padrao": r"(?im)^[ \t]*(?!.*version\s+\"?none)"
                  r"\s*options\s*\{(?![\s\S]{0,2000}?version\s)",
        "recomendacao": "Definir version \"none\"; em options{} para não "
                        "revelar a release em uso.",
    },
    {
        "id": "CFG-BANCO-EXPOSTO",
        "titulo": "Banco de dados escutando em todas as interfaces",
        "severidade": "MEDIA",
        "plataformas": ["linux"],
        # Linha do 'ss -tulpn': MariaDB/MySQL, PostgreSQL, Redis, InfluxDB,
        # ClickHouse ou MongoDB em 0.0.0.0, [::] ou *.
        "padrao": r"(?im)^tcp\s+LISTEN\s+\d+\s+\d+\s+(?:0\.0\.0\.0|\[::\]|\*)"
                  r":(?:3306|5432|6379|8086|8123|9000|27017)\s",
        "recomendacao": "Limitar o bind ao localhost ou à gerência. No "
                        "Wanguard, a Console precisa do 3306 aberto só se "
                        "houver Sensor/Filter remoto; nesse caso, liberar no "
                        "firewall apenas os IPs desses servidores.",
    },
    {
        "id": "CFG-WG-PIPE-EXABGP",
        "titulo": "Pipe do ExaBGP gravável por qualquer usuário local",
        "severidade": "ALTA",
        "plataformas": ["linux"],
        "padrao": r"(?m)^p[r-][w-][x-][r-][w-][x-][r-]w[x-]\s+\S+\s+"
                  r"(?:/var)?/run/exabgp\S*",
        "recomendacao": "Quem escreve no pipe anuncia rotas (RTBH/Flowspec) "
                        "em nome do Wanguard. Deixar 0660 com grupo do "
                        "ExaBGP e o usuário andrisoft nesse grupo (drop-in "
                        "systemd com RuntimeDirectoryMode=0770 e UMask=0007).",
    },
    {
        "id": "CFG-WG-SERVER-COMMANDS",
        "titulo": "WANsupervisor sem -n: comandos de shell pela Console "
                  "(Server Commands) habilitados",
        "severidade": "MEDIA",
        "plataformas": ["linux"],
        # Processo sem argumentos no ps ou no CGroup do systemctl status.
        "padrao": r"(?m)(?:[├└]─\d+|\s\d+(?:\.\d+)?)\s+"
                  r"/opt/andrisoft/bin/WANsupervisor[ \t]*$",
        "recomendacao": "Se o recurso não é usado, iniciar o WANsupervisor "
                        "com -n (override do ExecStart na unit): qualquer "
                        "conta da Console com acesso executa comandos no "
                        "servidor como andrisoft.",
    },
    {
        "id": "CFG-WG-GRAFICOS-SEM-BANCO",
        "titulo": "Wanguard sem gravar gráficos: banco de séries inacessível",
        "severidade": "MEDIA",
        "plataformas": ["linux"],
        "padrao": r"genrrds_\w+(?:\[\d+\])?: fail \d+ (?:clickhouse|influxdb)"
                  r" \d+ \(Couldn't connect to server\)",
        "recomendacao": "Subir o ClickHouse/InfluxDB configurado em Graphs & "
                        "Storage ou removê-lo da configuração. Sem ele, "
                        "gráficos, Flow Graphs e Profiling ficam sem dados.",
    },
    {
        "id": "CFG-NTP-SEM-AUTENTICACAO",
        "titulo": "NTP sem autenticação configurada",
        "severidade": "BAIXA",
        "plataformas": None,
        "padrao": r"(?im)^[ \t]*(?:ntp\s+server\s+(?!disable\b|enable\b|"
                  r"source-interface\b)\S|set\s+system\s+ntp\s+server|"
                  r"ntp(?:-service)?\s+unicast-server)"
                  r"(?![\s\S]{0,400}?(?:key|authentication))",
        "recomendacao": "Habilitar autenticação NTP quando suportada.",
    },
]


# ---------------------------------------------------------------------------
# Leitura dos snapshots
# ---------------------------------------------------------------------------
def ler_snapshot(caminho):
    """Retorna (metadados, texto_completo) de um snapshot netsnap."""
    # utf-8-sig: um snapshot salvo de novo pelo Bloco de Notas ganha BOM, e
    # o cabeçalho deixaria de ser reconhecido.
    with open(caminho, "r", encoding="utf-8-sig", errors="replace") as f:
        texto = f.read()
    meta = {}
    m = re.match(r"^---\n(.*?)\n---\n", texto, re.S)
    if m:
        for linha in m.group(1).splitlines():
            if ":" not in linha:
                continue
            chave, _, valor = linha.partition(":")
            valor = valor.strip()
            try:
                meta[chave.strip()] = json.loads(valor)
            except Exception:
                meta[chave.strip()] = valor.strip('"')
    meta.setdefault("host", os.path.basename(caminho).split("_")[0])
    meta.setdefault("ip", "")
    meta.setdefault("platform_key", "")
    meta.setdefault("platform_name", meta.get("platform_key") or "desconhecida")
    return meta, texto


def secoes_do_snapshot(texto):
    """Divide o snapshot nas seções "## ", ignorando cabeçalhos dentro dos
    blocos de código: a saída dos equipamentos não é escapada, e uma linha
    "## Inventário" vinda de um banner não pode virar seção."""
    partes, atual, cerca = [], [], None
    for linha in texto.split("\n"):
        if cerca:
            if linha.rstrip("\r") == cerca:
                cerca = None
        elif linha.startswith("```"):
            cerca = re.match(r"`+", linha).group(0)
        elif linha.startswith("## ") and atual:
            partes.append("\n".join(atual))
            atual = []
        atual.append(linha)
    if atual:
        partes.append("\n".join(atual))
    return partes


def texto_para_versao(texto):
    """Reordena o snapshot para a busca de versão.

    A seção Inventário vem primeiro; Vizinhança e Logs ficam de fora, porque
    descrevem outros equipamentos. Num CE6860 (VRP 8.191) a primeira
    ocorrência de "Version 5.170" no arquivo era a de um vizinho LLDP, e a
    versão relatada era a dele."""
    partes = secoes_do_snapshot(texto)
    inventario = [p for p in partes if re.match(r"## .*Invent", p)]
    fora = re.compile(r"## .*(Vizinhan|Logs)")
    demais = [p for p in partes
              if p not in inventario and not fora.match(p)]
    return "\n".join(inventario + demais)


def escapar_cpe(valor):
    """Escapa caracteres especiais do formato CPE 2.3 (ex.: '9.3(8)')."""
    return re.sub(r"([^A-Za-z0-9._\-])", r"\\\1", valor)


def extrair_versoes(meta, texto):
    """Identifica versões de sistema e de aplicações no snapshot."""
    texto = texto_para_versao(texto)
    achados = []
    vistos = set()
    regras = list(MAPA_VERSAO.get(meta.get("platform_key", ""), [])) + list(MAPA_APP)
    for padrao, fornecedor, produto, rotulo in regras:
        for m in re.finditer(padrao, texto):
            versao = m.group(1).strip().rstrip(".,;")
            # Preserva o parêntese final de versões Cisco (ex.: 9.3(8))
            if versao.endswith(")") and versao.count("(") != versao.count(")"):
                versao = versao[:-1]
            if not versao or len(versao) > 40:
                continue
            chave = (rotulo, versao)
            if chave in vistos:
                continue
            vistos.add(chave)
            achados.append({
                "rotulo": rotulo,
                "versao": versao,
                "cpe_fornecedor": fornecedor,
                "cpe_produto": produto,
                "consultavel": bool(fornecedor and produto),
            })
            break  # primeira ocorrência por regra basta

    # No IOS-XE o 'show version' também traz a linha "Cisco IOS Software
    # ... Version 17.x", que casaria a regra do IOS clássico e geraria uma
    # consulta a cisco:ios, produto que não tem versões 17.x.
    if any(a["cpe_produto"] == "ios_xe" for a in achados):
        achados = [a for a in achados if a["cpe_produto"] != "ios"]
    # O CPE do SmartAX na NVD é por modelo; o MA5600 não pode ser consultado
    # com o CPE do MA5800.
    if not re.search(r"(?i)MA5800", texto):
        for a in achados:
            if a["cpe_produto"] == "ma5800_firmware":
                a["cpe_fornecedor"] = a["cpe_produto"] = None
                a["consultavel"] = False
    return achados


def cpe_versao(produto, versao):
    """Converte a versão declarada nos campos version e update do CPE.

    A NVD cataloga o Junos com a release no campo version e o restante no
    update (21.4R3-S5.4 -> 21.4 / r3-s5), e o IOS-XE sem os zeros à esquerda
    que o 'show version' imprime (17.03.04a -> 17.3.4a). Os valores do
    dicionário CPE são minúsculos."""
    atualizacao = ""
    if produto == "junos":
        m = re.match(r"(?i)(\d+\.\d+)([RXD]\d+(?:-S\d+)?)?", versao)
        if m:
            versao, atualizacao = m.group(1), (m.group(2) or "")
    elif produto == "ios_xe":
        versao = re.sub(r"(?<!\d)0+(?=\d)", "", versao)
    return versao.lower(), atualizacao.lower()


def avaliar_config(meta, texto):
    """Aplica as heurísticas locais de configuração insegura."""
    plataforma = meta.get("platform_key", "")
    achados = []
    for regra in REGRAS_CONFIG:
        if regra["plataformas"] and plataforma not in regra["plataformas"]:
            continue
        m = re.search(regra["padrao"], texto)
        if not m:
            continue
        trecho = " ".join(m.group(0).split())[:120].replace("|", "/").replace("`", "'")
        achados.append({
            "id": regra["id"],
            "titulo": regra["titulo"],
            "severidade": regra["severidade"],
            "evidencia": trecho,
            "recomendacao": regra["recomendacao"],
        })
    return achados


# ---------------------------------------------------------------------------
# Consulta NVD e CISA KEV
# ---------------------------------------------------------------------------
# Verificação TLS. Em estações com repositório de certificados desatualizado
# (comum no Windows e em sistemas antigos), a validação falha com
# "certificate has expired" mesmo o servidor estando correto. O pacote
# certifi traz um conjunto atualizado de autoridades e é usado quando presente.
VERIFICAR_TLS = True


def contexto_ssl():
    if not VERIFICAR_TLS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if importlib.util.find_spec("certifi") is not None:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


LIMITE_RESPOSTA = 64 * 1024 * 1024


class _Redirecionamento(urllib.request.HTTPRedirectHandler):
    """Redirecionamento para outro host, ou para fora do HTTPS, não leva a
    chave da API (o urllib repassa todos os cabeçalhos por padrão)."""

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        novo = super().redirect_request(req, fp, code, msg, hdrs, newurl)
        origem = urllib.parse.urlsplit(req.full_url)
        destino = urllib.parse.urlsplit(newurl)
        if novo is not None and (destino.hostname != origem.hostname
                                 or destino.scheme != "https"):
            for nome in list(novo.headers):
                if nome.lower() == "apikey":
                    del novo.headers[nome]
        return novo


def http_json(url, timeout=45, headers=None, corpo=None):
    """GET (ou POST de JSON, com 'corpo') e devolve a resposta decodificada."""
    headers = dict(headers or {"User-Agent": UA})
    if not VERIFICAR_TLS:
        # Sem validação de certificado, quem estiver no caminho leria a chave.
        headers = {k: v for k, v in headers.items() if k.lower() != "apikey"}
    abridor = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=contexto_ssl()), _Redirecionamento)
    dados_envio = None
    if corpo is not None:
        dados_envio = json.dumps(corpo).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=dados_envio, headers=headers)
    with abridor.open(req, timeout=timeout) as r:
        dados = r.read(LIMITE_RESPOSTA + 1)
    if len(dados) > LIMITE_RESPOSTA:
        raise ValueError("resposta da API maior que o limite de 64 MB")
    return json.loads(dados.decode("utf-8", "replace"))


def explicar_falha_tls(e) -> str:
    """Traduz a falha de validação TLS em uma orientação prática."""
    texto = str(e)
    if "CERTIFICATE_VERIFY_FAILED" not in texto:
        return ""
    tem_certifi = importlib.util.find_spec("certifi") is not None
    aviso = ["", "[!] A validação do certificado TLS falhou.",
             "    Isso costuma indicar repositório de autoridades "
             "desatualizado na estação, não problema no servidor consultado.",
             "    Soluções, em ordem de preferência:"]
    if not tem_certifi:
        aviso.append("      1. pip install --upgrade certifi   "
                     "(o netcve passa a usar esse conjunto automaticamente)")
    else:
        aviso.append("      1. pip install --upgrade certifi   "
                     "(certifi está instalado, mas pode estar desatualizado)")
    aviso.append("      2. atualizar os certificados do sistema operacional")
    aviso.append("      3. --sem-rede  (aplica apenas as heurísticas locais "
                 "de configuração)")
    aviso.append("      4. --inseguro  (ignora a validação TLS; use apenas "
                 "em rede confiável e sabendo do risco)")
    return "\n".join(aviso)


def carregar_cache():
    try:
        with open(CACHE, "r", encoding="utf-8") as f:
            dados = json.load(f)
        if time.time() - dados.get("_gerado_em", 0) > 86400 * 7:
            return {"_gerado_em": time.time()}
        return dados
    except Exception:
        return {"_gerado_em": time.time()}


def salvar_cache(cache):
    # Gravação atômica: uma interrupção no meio da escrita não deixa o
    # cache corrompido.
    try:
        cache["_gerado_em"] = cache.get("_gerado_em", time.time())
        temporario = CACHE + ".tmp"
        with open(temporario, "w", encoding="utf-8") as f:
            json.dump(cache, f)
        os.replace(temporario, CACHE)
    except Exception:
        pass


def baixar_kev():
    """Catálogo CISA de vulnerabilidades comprovadamente exploradas.

    Devolve {cve: metadados}; 'cve in kev' continua valendo como teste."""
    try:
        dados = http_json(KEV_URL)
        return {v["cveID"]: {
            "fabricante": v.get("vendorProject", ""),
            "produto": v.get("product", ""),
            "nome": v.get("vulnerabilityName", ""),
            "incluido_em": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", ""),
            "descricao": v.get("shortDescription", ""),
        } for v in dados.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as e:
        print(f"[!] Não foi possível obter o catálogo CISA KEV: {e}")
        ajuda = explicar_falha_tls(e)
        if ajuda:
            print(ajuda)
        return {}


def falha_transitoria(e) -> bool:
    """Indica se vale repetir a consulta: limite de taxa, erro do servidor ou
    rede. Falha de TLS e erro de requisição (4xx) se repetiriam igual."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code in (403, 429) or e.code >= 500
    if isinstance(e, urllib.error.URLError):
        return not isinstance(e.reason, ssl.SSLError)
    return not isinstance(e, ssl.SSLError)


def consultar_nvd(fornecedor, produto, versao, chave_api, cache):
    """Consulta CVEs por CPE amplo (virtualMatchString)."""
    versao, atualizacao = cpe_versao(produto, versao)
    cpe = f"cpe:2.3:*:{fornecedor}:{produto}:{escapar_cpe(versao)}"
    if atualizacao:
        cpe += f":{escapar_cpe(atualizacao)}"
    if cpe in cache:
        return cache[cpe], True

    headers = {"User-Agent": UA}
    if chave_api:
        headers["apiKey"] = chave_api

    # A API devolve no máximo 2000 itens por página, dos mais antigos para
    # os mais novos. Sem seguir a paginação, versões com muitas CVEs (kernel
    # Linux) ficavam só com as antigas e perdiam as do catálogo KEV.
    itens, inicio, total = [], 0, None
    while total is None or inicio < total:
        params = {"virtualMatchString": cpe, "resultsPerPage": "2000",
                  "startIndex": str(inicio)}
        url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
        for tentativa in range(3):
            try:
                # Página de 2000 CVEs (kernel) passa de 45 s pela NVD.
                dados = http_json(url, headers=headers, timeout=120)
                break
            except Exception as e:
                if tentativa == 2 or not falha_transitoria(e):
                    raise
                espera = 10 * (tentativa + 1)
                print(f"    [!] Falha na consulta ({e}); nova tentativa em {espera}s")
                time.sleep(espera)
        pagina = dados.get("vulnerabilities", [])
        itens.extend(pagina)
        total = int(dados.get("totalResults", len(itens)))
        inicio += len(pagina)
        if not pagina:
            break
        if inicio < total:
            time.sleep(DELAY_COM_CHAVE if chave_api else DELAY_SEM_CHAVE)

    resultado = []
    for item in itens:
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        descricao = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                descricao = d.get("value", "")
                break
        nota, severidade, vetor = None, "DESCONHECIDA", ""
        metricas = cve.get("metrics", {})
        for campo in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metricas.get(campo):
                dado = metricas[campo][0].get("cvssData", {})
                nota = dado.get("baseScore")
                severidade = (dado.get("baseSeverity")
                              or metricas[campo][0].get("baseSeverity")
                              or "DESCONHECIDA")
                vetor = dado.get("vectorString", "")
                break
        resultado.append({
            "id": cve.get("id"),
            "nota": nota,
            "severidade": str(severidade).upper(),
            "vetor": vetor,
            "publicado": (cve.get("published") or "")[:10],
            "descricao": descricao,
        })

    resultado.sort(key=lambda c: (c["nota"] is None, -(c["nota"] or 0)))
    cache[cpe] = resultado
    return resultado, False


# ---------------------------------------------------------------------------
# CVSS 3.x: nota base a partir do vetor
#
# O OSV traz o vetor, não a nota. Fórmula da especificação CVSS v3.1
# (FIRST), seção 7.1, com o arredondamento "Roundup" da seção A.1.
# ---------------------------------------------------------------------------
_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _arredondar_cima(valor):
    inteiro = int(round(valor * 100000))
    if inteiro % 10000 == 0:
        return inteiro / 100000.0
    return (math.floor(inteiro / 10000) + 1) / 10.0


def nota_cvss3(vetor):
    """Nota base de um vetor 'CVSS:3.x/AV:N/...'; None se inválido."""
    if not vetor or not vetor.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vetor.split("/")[1:])
        escopo_muda = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if escopo_muda else 0.62,
              "H": 0.5 if escopo_muda else 0.27}[m["PR"]]
        iss = 1 - ((1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["I"][m["I"]])
                   * (1 - _CVSS3["A"][m["A"]]))
        if escopo_muda:
            impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impacto = 6.42 * iss
        explor = (8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr
                  * _CVSS3["UI"][m["UI"]])
    except (KeyError, ValueError):
        return None
    if impacto <= 0:
        return 0.0
    if escopo_muda:
        return _arredondar_cima(min(1.08 * (impacto + explor), 10))
    return _arredondar_cima(min(impacto + explor, 10))


def severidade_da_nota(nota):
    if nota is None:
        return "DESCONHECIDA"
    if nota >= 9.0:
        return "CRITICAL"
    if nota >= 7.0:
        return "HIGH"
    if nota >= 4.0:
        return "MEDIUM"
    return "LOW" if nota > 0 else "NONE"


# ---------------------------------------------------------------------------
# Pacotes de servidores Linux (OSV.dev)
#
# A versão upstream não serve para Debian e Ubuntu: as correções são
# retroportadas sem mudar o número (o PHP 8.3.6 do Ubuntu 24.04 recebe as
# correções de segurança e continua 8.3.6). O OSV indexa pelas versões
# exatas dos pacotes da distribuição, pelo pacote-fonte.
# ---------------------------------------------------------------------------
_CMD_PACOTES = re.compile(r"dpkg-query|rpm -qa")


def ecossistema_osv(texto):
    """Ecossistema OSV a partir do /etc/os-release do snapshot, ou None."""
    def campo(nome):
        m = re.search(rf"(?m)^{nome}=\"?([^\"\n]*)\"?", texto)
        return m.group(1).strip() if m else ""
    ident, versao = campo("ID").lower(), campo("VERSION_ID")
    if not ident or not versao:
        return None
    maior = versao.split(".")[0]
    if ident == "debian":
        return f"Debian:{maior}"
    if ident == "ubuntu":
        lts = "LTS" in (campo("VERSION") + campo("PRETTY_NAME"))
        return f"Ubuntu:{versao}" + (":LTS" if lts else "")
    if ident == "rocky":
        return f"Rocky Linux:{maior}"
    if ident == "almalinux":
        return f"AlmaLinux:{maior}"
    return None


def _bloco_do_comando(texto, filtro):
    """Conteúdo do bloco de código cujo cabeçalho '### `...`' casa o filtro."""
    linhas = texto.split("\n")
    for i, linha in enumerate(linhas):
        if not (linha.startswith("### `") and filtro.search(linha)):
            continue
        for j in range(i + 1, min(i + 4, len(linhas))):
            m = re.match(r"^(`{3,})", linhas[j])
            if m:
                cerca, corpo = m.group(1), []
                for k in range(j + 1, len(linhas)):
                    if linhas[k].rstrip("\r") == cerca:
                        return "\n".join(corpo)
                    corpo.append(linhas[k])
                return "\n".join(corpo)
    return ""


def extrair_pacotes(texto):
    """Lista de pacotes instalados: [{binario, versao, fonte, versao_fonte}].

    Snapshots anteriores à 1.17.1 não têm o pacote-fonte; nesse caso a
    consulta usa o nome do binário, que só coincide com o fonte em parte dos
    pacotes ('precisao': 'binario')."""
    bloco = _bloco_do_comando(texto, _CMD_PACOTES)
    pacotes, precisao = [], "fonte"
    for linha in bloco.splitlines():
        c = linha.split("\t")
        if len(c) >= 5 and c[3]:
            # dpkg: nome, versão, arquitetura, fonte, versão do fonte
            fonte = re.sub(r"\s*\(.*\)$", "", c[3]).strip()
            pacotes.append({"binario": c[0], "versao": c[1],
                            "fonte": fonte, "versao_fonte": c[4] or c[1]})
        elif len(c) == 4 and c[3].endswith(".src.rpm"):
            # rpm: nome, época:versão-release, arquitetura, SRPM
            m = re.match(r"(.+)-[^-]+-[^-]+\.src\.rpm$", c[3])
            versao = re.sub(r"^\(none\):|^0:", "", c[1])
            pacotes.append({"binario": c[0], "versao": versao,
                            "fonte": m.group(1) if m else c[0],
                            "versao_fonte": versao})
        elif len(c) >= 3 and c[1] and re.match(r"[\w.+:~-]+$", c[1]):
            precisao = "binario"
            versao = re.sub(r"^\(none\):|^0:", "", c[1])
            pacotes.append({"binario": c[0], "versao": versao,
                            "fonte": c[0], "versao_fonte": versao})
    return pacotes, precisao


def _ordem_deb(c):
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256 if c else 0


def _comparar_parte_deb(a, b):
    """Comparação de upstream/revisão do dpkg (Debian Policy 5.6.12)."""
    while a or b:
        na = re.match(r"[^\d]*", a).group(0)
        nb = re.match(r"[^\d]*", b).group(0)
        for i in range(max(len(na), len(nb))):
            ca = _ordem_deb(na[i] if i < len(na) else "")
            cb = _ordem_deb(nb[i] if i < len(nb) else "")
            if ca != cb:
                return -1 if ca < cb else 1
        a, b = a[len(na):], b[len(nb):]
        da = re.match(r"\d*", a).group(0)
        db = re.match(r"\d*", b).group(0)
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
        a, b = a[len(da):], b[len(db):]
    return 0


def chave_versao_pacote(versao):
    """Chave de ordenação para versões dpkg (serve de aproximação para RPM)."""
    class _Chave:
        def __init__(self, v):
            epoca, _, resto = v.rpartition(":") if ":" in v else ("0", "", v)
            up, _, rev = resto.rpartition("-") if "-" in resto else (resto, "", "0")
            self.t = (int(epoca) if epoca.isdigit() else 0, up, rev)

        def __lt__(self, outro):
            if self.t[0] != outro.t[0]:
                return self.t[0] < outro.t[0]
            c = _comparar_parte_deb(self.t[1], outro.t[1])
            if c:
                return c < 0
            return _comparar_parte_deb(self.t[2], outro.t[2]) < 0
    return _Chave(versao)


def _vuln_osv(id_vuln, ecossistema, pacote, cache):
    """Registro OSV resumido para o pacote; o cache guarda só o resumo (o
    registro completo de um CVE do kernel passa de 100 KB)."""
    chave = f"osv:{id_vuln}|{ecossistema}|{pacote}"
    if chave in cache:
        return cache[chave]
    for tentativa in range(3):
        try:
            dados = http_json(OSV_VULN + urllib.parse.quote(id_vuln), timeout=30)
            break
        except Exception as e:
            if tentativa == 2 or not falha_transitoria(e):
                return None
            time.sleep(3 * (tentativa + 1))
    resumo = resumir_vuln_osv(dados, ecossistema, pacote)
    cache[chave] = resumo
    return resumo


def resumir_vuln_osv(dados, ecossistema, pacote):
    """Campos úteis de um registro OSV para o pacote no ecossistema."""
    cves = [a for a in (dados.get("upstream") or []) + (dados.get("aliases") or [])
            if a.startswith("CVE-")]
    if dados.get("id", "").startswith("CVE-"):
        cves.insert(0, dados["id"])
    vetor, prioridade_ubuntu = "", ""
    for sev in dados.get("severity") or []:
        if sev.get("type", "").startswith("CVSS_V3") and not vetor:
            vetor = sev.get("score", "")
        elif sev.get("type") == "Ubuntu":
            prioridade_ubuntu = sev.get("score", "")
    corrigida, urgencia = None, ""
    for afetado in dados.get("affected") or []:
        pkg = afetado.get("package") or {}
        if pkg.get("ecosystem") != ecossistema or pkg.get("name") != pacote:
            continue
        urgencia = (afetado.get("ecosystem_specific") or {}).get("urgency", "")
        for faixa in afetado.get("ranges") or []:
            for ev in faixa.get("events") or []:
                if ev.get("fixed"):
                    corrigida = ev["fixed"]
    nota = nota_cvss3(vetor)
    severidade = severidade_da_nota(nota)
    if severidade == "DESCONHECIDA" and prioridade_ubuntu:
        severidade = {"critical": "CRITICAL", "high": "HIGH",
                      "medium": "MEDIUM", "low": "LOW",
                      "negligible": "LOW"}.get(prioridade_ubuntu, "DESCONHECIDA")
    return {
        "id": dados.get("id"),
        "cves": list(dict.fromkeys(cves)),
        "nota": nota,
        "severidade": severidade,
        "vetor": vetor,
        "prioridade_ubuntu": prioridade_ubuntu,
        "urgencia_debian": urgencia,
        "corrigida": corrigida,
        "resumo": " ".join((dados.get("summary") or dados.get("details")
                            or "").split())[:300],
    }


def consultar_osv(ecossistema, pacotes, cache, paralelo=8):
    """Vulnerabilidades por pacote-fonte. Devolve [{pacote, versao, vulns}]."""
    unicos = {}
    for p in pacotes:
        unicos.setdefault((p["fonte"], p["versao_fonte"]), []).append(p["binario"])
    chaves = list(unicos)
    ids_por_pacote = {}
    for inicio in range(0, len(chaves), 1000):
        lote = chaves[inicio:inicio + 1000]
        consultas = [{"package": {"name": n, "ecosystem": ecossistema},
                      "version": v} for n, v in lote]
        resposta = http_json(OSV_LOTE, timeout=90, corpo={"queries": consultas})
        for (nome, versao), r in zip(lote, resposta.get("results", [])):
            ids = [x["id"] for x in r.get("vulns") or []]
            token = r.get("next_page_token")
            while token:
                extra = http_json(OSV_LOTE, timeout=90, corpo={"queries": [{
                    "package": {"name": nome, "ecosystem": ecossistema},
                    "version": versao, "page_token": token}]})
                r2 = (extra.get("results") or [{}])[0]
                ids += [x["id"] for x in r2.get("vulns") or []]
                token = r2.get("next_page_token")
            if ids:
                ids_por_pacote[(nome, versao)] = ids

    pares = sorted({(i, nome) for (nome, _), ids in ids_por_pacote.items()
                    for i in ids})
    with ThreadPoolExecutor(max_workers=paralelo) as ex:
        detalhes = dict(zip(pares, ex.map(
            lambda par: _vuln_osv(par[0], ecossistema, par[1], cache), pares)))
    resultado = []
    for (nome, versao), ids in sorted(ids_por_pacote.items()):
        vulns = []
        # Registros por CVE (UBUNTU-CVE-*, DEBIAN-CVE-*) antes dos boletins
        # que agrupam várias (USN-*, DSA-*): o boletim só entra se trouxer
        # alguma CVE que os registros individuais não cobrem.
        ids = sorted(ids, key=lambda i: not re.match(r"^[A-Z]+-CVE-", i))
        cobertas = set()
        for i in ids:
            v = detalhes.get((i, nome))
            if not v:
                vulns.append({"id": i, "cves": [], "nota": None,
                              "severidade": "DESCONHECIDA", "vetor": "",
                              "prioridade_ubuntu": "", "urgencia_debian": "",
                              "corrigida": None, "resumo": "(detalhe indisponível)"})
                continue
            # O tracker do Debian marca como 'unimportant' o que não afeta o
            # pacote como distribuído (ex.: recurso não compilado).
            if v["urgencia_debian"] == "unimportant":
                continue
            if v["cves"] and set(v["cves"]) <= cobertas:
                continue
            cobertas |= set(v["cves"])
            vulns.append(v)
        if vulns:
            resultado.append({"pacote": nome, "versao": versao,
                              "binarios": sorted(set(unicos[(nome, versao)])),
                              "vulns": vulns})
    return resultado


# ---------------------------------------------------------------------------
# EPSS (FIRST): probabilidade de exploração nos próximos 30 dias
# ---------------------------------------------------------------------------
def consultar_epss(cves, cache):
    resultado, faltam = {}, []
    for c in sorted(set(cves)):
        if "epss:" + c in cache:
            resultado[c] = cache["epss:" + c]
        else:
            faltam.append(c)
    for inicio in range(0, len(faltam), 80):
        lote = faltam[inicio:inicio + 80]
        try:
            dados = http_json(f"{EPSS_API}?cve={','.join(lote)}", timeout=45)
        except Exception as e:
            print(f"    [!] EPSS indisponível: {e}")
            break
        recebidos = {d["cve"]: float(d.get("epss", 0)) for d in dados.get("data", [])}
        for c in lote:
            resultado[c] = cache["epss:" + c] = recebidos.get(c)
    return resultado


# ---------------------------------------------------------------------------
# KEV do fabricante: CVEs exploradas do produto em uso que a consulta por
# versão não confirmou (CPE incompleto na NVD, plataforma sem CPE). São para
# conferir no boletim do fabricante, não achados confirmados.
# ---------------------------------------------------------------------------
KEV_POR_PLATAFORMA = {
    "juniper_junos": (r"^Juniper$", r"Junos"),
    "mikrotik_routeros": (r"^MikroTik$", r"RouterOS"),
    "cisco_ios": (r"^Cisco$", r"\bIOS\b(?! XR$)|IOS XE"),
    "cisco_xr": (r"^Cisco$", r"\bXR\b"),
    "cisco_nxos": (r"^Cisco$", r"NX-OS"),
    "huawei": (r"^Huawei$", r"."),
    "huawei_ce": (r"^Huawei$", r"."),
    "huawei_smartax": (r"^Huawei$", r"."),
    "fiberhome": (r"^FiberHome$", r"."),
}
KEV_PHP = (r"^PHP( Group)?$", r"^(PHP|FastCGI Process Manager \(FPM\))$")


def kev_do_fabricante(plataforma, tem_php, kev, ja_vistos, limite=15):
    regras = []
    if plataforma in KEV_POR_PLATAFORMA:
        regras.append(KEV_POR_PLATAFORMA[plataforma])
    if tem_php:
        regras.append(KEV_PHP)
    itens = []
    for cve, meta in kev.items():
        if cve in ja_vistos:
            continue
        for fab, prod in regras:
            if re.search(fab, meta["fabricante"]) and re.search(prod, meta["produto"]):
                itens.append(dict(meta, cve=cve))
                break
    itens.sort(key=lambda i: i["incluido_em"], reverse=True)
    return itens[:limite]


# ---------------------------------------------------------------------------
# Catálogo de falhas graves
#
# Cada entrada diz quais versões são afetadas e, principalmente, o que na
# configuração torna o equipamento explorável — a parte que a consulta por
# versão não alcança. Só entra aqui o que foi conferido em fonte primária ou
# em mais de uma fonte secundária; 'verificado_em' registra a data.
#
# faixas: [de, até_exclusive, situação]. Situação 'vulneravel' ou
# 'sem_correcao' (ramo sem release oficial) ou 'parcial'.
# exposicao: regex sobre o snapshot; 'presente' significa que o achado
# confirma a exposição, 'mitiga' que reduz o risco.
# ---------------------------------------------------------------------------
CATALOGO = [
    {
        "id": "PHP2SHELL",
        "titulo": "PHP2Shell — execução remota de código no PHP sem autenticação",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "produto": "PHP",
        "pacotes_fonte": r"^php(\d+(\.\d+)?)?$",
        "faixas": [
            ["8.5.0", "8.5.12", "vulneravel"],
            ["8.4.0", "8.4.27", "vulneravel"],
            ["8.3.0", "8.3.36", "vulneravel"],
            ["8.2.0", "8.2.35", "vulneravel"],
            ["7.4.0", "8.2.0", "sem_correcao"],
            ["5.4.0", "7.4.0", "sem_correcao"],
        ],
        "exposicao": [
            {"comando": r"php -v", "efeito": "presente",
             "padrao": r"(?im)^\S*php[\d.]*-fpm\S*\.service\s+loaded\s+active",
             "texto": "PHP-FPM ativo"},
            {"comando": r"php -v", "efeito": "presente",
             "padrao": r"(?im)^(php[\d.]*\.(load|conf)|\d+-php\.conf)$|mod_php|libphp",
             "texto": "mod_php carregado no Apache"},
            # O bloco do arquivo vai do cabeçalho '===== caminho' até o
            # próximo: um valor do php.ini da CLI não pode contar como
            # mitigação do FPM.
            {"comando": r"php -v", "efeito": "mitiga",
             "padrao": r"(?im)^===== \S*/(fpm|apache2)/php\.ini$"
                       r"(?:\n(?!=====).*)*?\n\s*memory_limit\s*=\s*-1\s*$",
             "texto": "memory_limit = -1 no FPM/Apache (mitiga CVE-2026-109618)"},
            {"comando": r"php -v", "efeito": "mitiga",
             "padrao": r"(?im)^===== \S*/(fpm|apache2)/php\.ini$"
                       r"(?:\n(?!=====).*)*?\n\s*session\.upload_progress\.enabled"
                       r"\s*=\s*(0|off)\s*$",
             "texto": "session.upload_progress.enabled = 0 no FPM/Apache "
                      "(mitiga CVE-2026-109619)"},
        ],
        "correcao": "Atualizar para 8.5.12, 8.4.27, 8.3.36 ou 8.2.35 (ou o pacote "
                    "corrigido da distribuição) e reiniciar todos os workers. "
                    "Paliativo: memory_limit=-1 imposto e "
                    "session.upload_progress.enabled=0 (no 8.5, também "
                    "fatal_error_backtraces=0). Do 7.4 ao 8.1 só há backport "
                    "no código-fonte; do 5.4 ao 7.3 não há correção.",
        "exploracao": "Exploração observada desde 17/10/2026 (Amazon, Cloudflare, "
                      "watchTowr). Fora do CISA KEV em 22/10/2026.",
        "fontes": [
            "https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote",
            "https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php",
        ],
        "verificado_em": "2026-10-22",
    },
    {
        "id": "MIKROTRICK",
        "titulo": "MikroTrick — tomada do RouterOS por SSH sem autenticação",
        "cves": ["CVE-2026-67279", "CVE-2026-86060", "CVE-2026-67277",
                 "CVE-2026-67276", "CVE-2026-67278", "CVE-2026-67281"],
        "produto": "RouterOS",
        "faixas": [
            ["6.0", "6.49.21", "vulneravel"],
            ["7.0", "7.23.4", "vulneravel"],
            ["7.24.0", "7.24.2", "vulneravel"],
            ["7.23.4", "7.23.6", "parcial"],
            ["7.24.2", "7.24.3", "parcial"],
        ],
        # Formatos de saída conferidos na documentação do RouterOS 7;
        # [validar em equipamento real] as variações entre 7.20 e 7.24.
        "exposicao": [
            {"comando": r"/ip service print detail", "efeito": "presente",
             "padrao": r"(?im)^\s*\d+\s+(?!X)[A-Z ]*name=\"ssh\"[^\n]*"
                       r"(address|available-from)=\"\"",
             "texto": "SSH habilitado sem restrição de origem (/ip service)"},
            {"comando": r"/tool bandwidth-server print", "efeito": "presente",
             "padrao": r"(?im)^\s*enabled:\s*yes\b",
             "texto": "bandwidth-server habilitado (CVE-2026-67277)"},
            {"comando": r"/system device-mode print", "efeito": "presente",
             "padrao": r"(?im)^\s*flagged:\s*yes\b",
             "texto": "device-mode flagged=yes: o RouterOS registrou suspeita "
                      "de invasão"},
            {"comando": r"/user print", "efeito": "presente",
             "padrao": r"(?im)^\s*\d+\s+[A-Z ]*\bops\b\s+\w",
             "texto": "conta 'ops' existe (nome usado pela campanha MikroTrick)"},
        ],
        "correcao": "Atualizar para 7.23.7 (long-term) ou 7.24.5 (stable); "
                    "CVE-2026-67278 só fica completa a partir de 7.23.6/7.24.3, "
                    "e o ramo 6 corrige em 6.49.21. Restringir SSH, Winbox e "
                    "WebFig às redes de gerência e desligar o bandwidth-server. "
                    "Com indício de invasão: netinstall, troca de todos os "
                    "segredos e restauração por export revisado.",
        "exploracao": "Cadeia explorada desde 02/09/2026 (CERT Polska). "
                      "CVE-2026-67277 e CVE-2026-86060 no CISA KEV em "
                      "10/09/2026; CVE-2026-67279 em 25/09/2026.",
        "fontes": [
            "https://www.securityweek.com/mikrotik-patches-critical-flaws-chained-to-hack-routers/",
            "https://www.rescana.com/post/mikrotik-routeros-mikrotrick-cve-2026-67277-86060-kev",
        ],
        "verificado_em": "2026-10-22",
    },
]


def _tupla_versao(texto):
    partes = re.findall(r"\d+", texto or "")
    return tuple(int(p) for p in partes[:4]) or None


def situacao_por_faixa(versao, faixas):
    """'vulneravel', 'sem_correcao', 'parcial', 'corrigida' ou None."""
    v = _tupla_versao(versao)
    if not v:
        return None
    situacao = "corrigida"
    for de, ate, estado in faixas:
        if _tupla_versao(de) <= v < _tupla_versao(ate):
            if estado != "parcial":
                return estado
            situacao = "parcial"
    return situacao


def avaliar_catalogo(meta, texto, versoes, pacotes_osv, catalogo=None):
    """Aplica o catálogo ao snapshot. 'pacotes_osv' é a lista devolvida por
    consultar_osv (ou None se não houve consulta)."""
    achados = []
    for entrada in catalogo or CATALOGO:
        versao = next((v["versao"] for v in versoes
                       if v["rotulo"] == entrada["produto"]), None)
        situacao, base = None, ""
        padrao_pkg = entrada.get("pacotes_fonte")
        pkgs = [p for p in (pacotes_osv or [])
                if padrao_pkg and re.match(padrao_pkg, p["pacote"])]
        if padrao_pkg and pacotes_osv is not None and _tem_pacote(texto, padrao_pkg):
            # Pacote da distribuição: vale a versão exata pelo OSV.
            achou = sorted({(p["pacote"], p["versao"], v["corrigida"] or "sem correção")
                            for p in pkgs for v in p["vulns"]
                            if set(v["cves"]) & set(entrada["cves"])})
            situacao = "vulneravel" if achou else "corrigida"
            base = ("pacote da distribuição: "
                    + ("; ".join(f"{n} {v}, corrigido em {c}" for n, v, c in achou)
                       if achou else "versão instalada já corrigida (OSV)"))
        elif versao:
            situacao = situacao_por_faixa(versao, entrada["faixas"])
            base = f"versão {versao}"
            if padrao_pkg:
                base += (" (versão upstream; se o PHP veio da distribuição, "
                         "confira o pacote: correções retroportadas não mudam "
                         "o número)")
        if situacao in (None, "corrigida"):
            continue
        exposicao, mitigacoes = [], []
        for regra in entrada["exposicao"]:
            alvo = texto
            if regra.get("comando"):
                alvo = _bloco_do_comando(texto, re.compile(re.escape(regra["comando"])))
            if alvo and re.search(regra["padrao"], alvo):
                (mitigacoes if regra["efeito"] == "mitiga" else exposicao).append(
                    regra["texto"])
        achados.append({
            "id": entrada["id"],
            "titulo": entrada["titulo"],
            "cves": entrada["cves"],
            "situacao": situacao,
            "base": base,
            "exposicao": exposicao,
            "mitigacoes": mitigacoes,
            "correcao": entrada["correcao"],
            "exploracao": entrada["exploracao"],
            "fontes": entrada["fontes"],
            "verificado_em": entrada["verificado_em"],
        })
    return achados


def marcar_cobertura_osv(versoes, texto, pacotes):
    """Tira da consulta à NVD o software que veio de pacote da distribuição
    (avaliado pelo OSV pela versão exata) e o kernel de distribuição que não
    deu para casar com o pacote."""
    fontes = {p["fonte"] for p in pacotes}
    for v in versoes:
        padrao = COBERTO_PELO_OSV.get(v["rotulo"])
        if not padrao:
            continue
        if v["rotulo"] == "Kernel Linux":
            if _kernel_e_do_pacote(texto, pacotes, padrao):
                v["consultavel"], v["coberto_osv"] = False, True
            elif _kernel_de_distribuicao(texto):
                # Kernel da distribuição que não é o do pacote
                # avaliado (reinício pendente, snapshot sem
                # pacote-fonte): a NVD pela versão upstream lista
                # milhares de CVEs já corrigidas pela distribuição.
                v["consultavel"] = False
                v["motivo"] = ("kernel da distribuição que não pôde ser "
                               "casado com o pacote instalado (reinício "
                               "pendente ou snapshot sem pacote-fonte); "
                               "confira no boletim da distribuição")
            # Kernel sem sufixo de distribuição (compilado à mão,
            # do hipervisor): segue para a NVD.
            continue
        if any(re.match(padrao, f) for f in fontes):
            v["consultavel"] = False
            v["coberto_osv"] = True


def _kernel_e_do_pacote(texto, pacotes, padrao_fonte):
    """O kernel do 'uname -a' é o de algum pacote linux instalado?"""
    m = re.search(r"(?m)^Linux \S+ (\d+\.\d+\.\d+-\d+)", texto)
    if not m:
        return False
    return any(re.match(padrao_fonte, p["fonte"]) and
               p["versao_fonte"].startswith(m.group(1)) for p in pacotes)


def _kernel_de_distribuicao(texto):
    """'uname -a' com a numeração de ABI das distribuições (5.15.0-91-generic,
    6.1.0-18-amd64, 5.14.0-427.el9) e não um kernel upstream (6.18.44)."""
    return bool(re.search(r"(?m)^Linux \S+ \d+\.\d+\.\d+-\d+", texto))


def _tem_pacote(texto, padrao_fonte):
    pacotes, _ = extrair_pacotes(texto)
    return any(re.match(padrao_fonte, p["fonte"]) for p in pacotes)


def carregar_catalogo_extra(caminho):
    """Entradas adicionais num JSON com a mesma estrutura de CATALOGO."""
    with open(caminho, encoding="utf-8") as f:
        extra = json.load(f)
    if not isinstance(extra, list):
        raise ValueError("o catálogo extra deve ser uma lista de entradas")
    obrig = {"id", "titulo", "cves", "produto", "faixas", "exposicao",
             "correcao", "exploracao", "fontes", "verificado_em"}
    for e in extra:
        faltam = obrig - set(e)
        if faltam:
            raise ValueError(f"entrada {e.get('id', '?')}: faltam {sorted(faltam)}")
        for regra in e["exposicao"]:
            re.compile(regra["padrao"])
    return extra


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
ORDEM_SEV = {"CRITICAL": 0, "CRÍTICA": 0, "HIGH": 1, "ALTA": 1,
             "MEDIUM": 2, "MEDIA": 2, "MÉDIA": 2, "LOW": 3, "BAIXA": 3}
SEV_PT = {"CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MEDIUM": "MÉDIA",
          "LOW": "BAIXA", "NONE": "NENHUMA", "DESCONHECIDA": "DESCONHECIDA"}


def _osv_vulns(h):
    for p in (h.get("osv") or {}).get("resultado") or []:
        for v in p["vulns"]:
            yield p, v


def _kev_osv(h, kev):
    """(pacote, vuln, cve) das vulnerabilidades de pacote no catálogo KEV."""
    for p, v in _osv_vulns(h):
        for c in v["cves"]:
            if c in kev:
                yield p, v, c


def _relevante_osv(v, kev, epss):
    """Entra na tabela do relatório: KEV, crítica/alta ou EPSS >= 10%."""
    if any(c in kev for c in v["cves"]):
        return True
    if v["severidade"] in ("CRITICAL", "HIGH"):
        return True
    return any((epss.get(c) or 0) >= 0.10 for c in v["cves"])


def _fmt_epss(cves, epss):
    valores = [epss.get(c) for c in cves if epss.get(c) is not None]
    return f"{max(valores) * 100:.1f}%" if valores else "—"


def gerar_relatorio(hosts, kev, pasta, sem_rede, limite_cve, epss=None,
                    carimbo=None, fontes=None):
    agora = carimbo or datetime.now()
    epss = epss or {}
    total_cve = sum(len(v["cves"] or []) for h in hosts for v in h["versoes"])
    total_kev = (sum(1 for h in hosts for v in h["versoes"]
                     for c in (v["cves"] or []) if c["id"] in kev)
                 + sum(1 for h in hosts for _ in _kev_osv(h, kev)))
    total_cfg = sum(len(h["config"]) for h in hosts)
    total_osv = sum(1 for h in hosts for _ in _osv_vulns(h))
    total_cat = sum(len(h.get("catalogo") or []) for h in hosts)

    md = ["---",
          f"netcve_version: {json.dumps(__version__)}",
          f"document_type: {json.dumps('vulnerability_triage')}",
          f"generated_at: {json.dumps(agora.isoformat(timespec='seconds'))}",
          f"hosts_analyzed: {len(hosts)}",
          f"cve_matches: {total_cve}",
          f"kev_matches: {total_kev}",
          f"config_findings: {total_cfg}",
          f"package_vulns: {total_osv}",
          f"critical_catalog_findings: {total_cat}",
          f"sources: {json.dumps(fontes or (['NVD CVE API 2.0', 'CISA KEV'] if not sem_rede else ['heurísticas locais']), ensure_ascii=False)}",
          f"confidence: {json.dumps('triage_only')}",
          "---\n",
          f"# Triagem de vulnerabilidades — {agora:%d/%m/%Y %H:%M}\n"]

    md.append("> **Como interpretar este relatório.** As correspondências são "
              "feitas pela **versão declarada** pelo equipamento e por "
              "**heurísticas de configuração**. Não há verificação ativa de "
              "exploração. Portanto:\n>\n"
              "> - **Falsos positivos são esperados**: fabricantes "
              "retroportam correções mantendo o mesmo número de versão, e o "
              "recurso vulnerável pode não estar habilitado.\n"
              "> - **Falsos negativos são esperados**: a cobertura de CPE na "
              "NVD é incompleta para equipamentos de rede, especialmente OLTs "
              "e plataformas regionais. Ausência de CVE aqui **não** significa "
              "ausência de vulnerabilidade.\n"
              "> - A fonte autoritativa é o boletim do fabricante "
              "(Juniper SIRT, Cisco PSIRT, Huawei PSIRT, MikroTik). Use este "
              "documento para **priorizar investigação**, não como laudo.\n>\n"
              "> Itens marcados **KEV** constam do catálogo CISA de "
              "vulnerabilidades comprovadamente exploradas — são a "
              "prioridade real.\n")

    md.append("## Resumo\n")
    md.append(f"- Hosts analisados: **{len(hosts)}**")
    md.append(f"- Correspondências CVE por versão: **{total_cve}**")
    md.append(f"- Vulnerabilidades de pacotes do sistema (OSV): **{total_osv}**")
    md.append(f"- No catálogo CISA KEV (versão ou pacote): **{total_kev}**")
    md.append(f"- Falhas graves do catálogo: **{total_cat}**")
    md.append(f"- Apontamentos de configuração: **{total_cfg}**\n")

    # Prioridade: KEV primeiro
    if total_kev:
        md.append("## Prioridade máxima — exploração confirmada (CISA KEV)\n")
        md.append("| Host | Software | Versão | CVE | CVSS | EPSS | Correção |")
        md.append("|---|---|---|---|---|---|---|")
        for h in hosts:
            for v in h["versoes"]:
                for c in v["cves"] or []:
                    if c["id"] in kev:
                        md.append(f"| {h['host']} | {v['rotulo']} | "
                                  f"`{v['versao']}` | {c['id']} | "
                                  f"{c['nota'] or '—'} | "
                                  f"{_fmt_epss([c['id']], epss)} | boletim do fabricante |")
            grupos = {}
            for p, v, c in _kev_osv(h, kev):
                g = grupos.setdefault((p["pacote"], p["versao"], v["corrigida"]),
                                      {"cves": [], "notas": []})
                if c not in g["cves"]:
                    g["cves"].append(c)
                    g["notas"].append(v["nota"] or 0)
            for (pacote, versao, corrigida), g in grupos.items():
                lista = ", ".join(g["cves"][:4]) + (
                    f" e mais {len(g['cves']) - 4}" if len(g["cves"]) > 4 else "")
                md.append(f"| {h['host']} | pacote {pacote} | `{versao}` | "
                          f"{lista} | {max(g['notas']) or '—'} | "
                          f"{_fmt_epss(g['cves'], epss)} | "
                          f"{('`' + corrigida + '`') if corrigida else 'sem correção na distribuição'} |")
        md.append("")

    if total_cat:
        md.append("## Falhas graves do catálogo\n")
        md.append("Falhas com exploração ativa ou impacto crítico, avaliadas "
                  "pela versão **e** pela configuração que torna o "
                  "equipamento explorável.\n")
        for h in hosts:
            for a in h.get("catalogo") or []:
                estado = {"vulneravel": "VULNERÁVEL",
                          "sem_correcao": "VULNERÁVEL — ramo sem correção oficial",
                          "parcial": "corrigido em parte"}[a["situacao"]]
                md.append(f"### {h['host']} ({h['ip']}) — {a['titulo']}\n")
                md.append(f"- **Situação:** {estado} ({a['base']})")
                md.append(f"- **CVEs:** {', '.join(a['cves'])}")
                md.append("- **Exposição confirmada no snapshot:** "
                          + ("; ".join(a["exposicao"]) if a["exposicao"]
                             else "nenhum indicador encontrado (confira manualmente)"))
                if a["mitigacoes"]:
                    md.append("- **Mitigações encontradas:** " + "; ".join(a["mitigacoes"]))
                md.append(f"- **Exploração:** {a['exploracao']}")
                md.append(f"- **Correção:** {a['correcao']}")
                md.append(f"- **Fontes** (conferidas em {a['verificado_em']}): "
                          + " · ".join(a["fontes"]) + "\n")

    md.append("## Inventário de versões identificadas\n")
    md.append("| Host | IP | Plataforma | Software | Versão | CVEs |")
    md.append("|---|---|---|---|---|---|")
    for h in hosts:
        if not h["versoes"]:
            md.append(f"| {h['host']} | {h['ip']} | {h['plataforma']} | "
                      f"_nenhuma versão reconhecida_ | — | — |")
        for v in h["versoes"]:
            qtd = ("ver pacotes (OSV)" if v.get("coberto_osv") else
                   "n/d" if not v["consultavel"] else
                   "não consultado" if v["cves"] is None else len(v["cves"]))
            md.append(f"| {h['host']} | {h['ip']} | {h['plataforma']} | "
                      f"{v['rotulo']} | `{v['versao']}` | {qtd} |")
    md.append("")

    md.append("## Detalhamento por host\n")
    for h in hosts:
        md.append(f"### {h['host']} ({h['ip']}) — {h['plataforma']}\n")
        if not h["versoes"] and not h["config"]:
            md.append("_Nenhum indicador identificado neste snapshot._\n")
            continue

        for v in h["versoes"]:
            md.append(f"#### {v['rotulo']} `{v['versao']}`\n")
            if v.get("coberto_osv"):
                md.append("_Pacote da distribuição: avaliado pela versão "
                          "exata do pacote na seção de pacotes (OSV), não pela "
                          "versão upstream._\n")
                continue
            if v.get("motivo"):
                md.append(f"_Não consultado na NVD: {v['motivo']}._\n")
                continue
            if not v["consultavel"]:
                md.append("_Sem mapeamento CPE conhecido para esta "
                          "plataforma na NVD; consulte o boletim do "
                          "fabricante manualmente._\n")
                continue
            if v["cves"] is None:
                md.append("_Versão não consultada na NVD (modo sem rede ou "
                          "falha na consulta)._\n")
                continue
            if not v["cves"]:
                md.append("_Nenhuma correspondência retornada pela NVD para "
                          "esta versão (ver ressalva sobre falsos negativos)._\n")
                continue
            md.append("| CVE | Sev. | CVSS | Publicado | Resumo |")
            md.append("|---|---|---|---|---|")
            for c in v["cves"][:limite_cve]:
                marca = " **KEV**" if c["id"] in kev else ""
                sev = SEV_PT.get(c["severidade"], c["severidade"])
                resumo = " ".join(c["descricao"].split())[:150].replace("|", "\\|")
                md.append(f"| {c['id']}{marca} | {sev} | {c['nota'] or '—'} | "
                          f"{c['publicado']} | {resumo} |")
            if len(v["cves"]) > limite_cve:
                md.append(f"\n_({len(v['cves']) - limite_cve} correspondência(s) "
                          "adicional(is) omitida(s) — use `--limite-cve` para "
                          "ampliar.)_")
            md.append("")

        osv = h.get("osv") or {}
        if osv.get("ecossistema") or osv.get("motivo"):
            md.append("#### Pacotes do sistema (OSV)\n")
            if osv.get("motivo"):
                md.append(f"_{osv['motivo']}_\n")
            elif osv.get("resultado") is None:
                md.append(f"_{osv.get('pacotes_total', 0)} pacotes em "
                          f"{osv['ecossistema']}; não consultados "
                          f"({osv.get('erro') or 'modo sem rede'})._\n")
            else:
                todas = list(_osv_vulns(h))
                por_sev = {}
                for _, v in todas:
                    por_sev[v["severidade"]] = por_sev.get(v["severidade"], 0) + 1
                resumo = ", ".join(f"{SEV_PT.get(k, k).lower()} {n}" for k, n in
                                   sorted(por_sev.items(),
                                          key=lambda i: ORDEM_SEV.get(i[0], 9)))
                md.append(f"{osv['pacotes_total']} pacotes em "
                          f"`{osv['ecossistema']}`; {len(osv['resultado'])} "
                          f"pacote(s)-fonte com vulnerabilidade, "
                          f"{len(todas)} no total ({resumo or 'nenhuma'}).")
                if osv.get("precisao") == "binario":
                    md.append("\n_Snapshot sem o pacote-fonte (netsnap "
                              "anterior à 1.17.1): só os pacotes cujo binário "
                              "tem o nome do fonte foram avaliados. Colete de "
                              "novo para cobertura completa._")
                linhas_pkg = []
                for p in osv["resultado"]:
                    rel = [v for v in p["vulns"] if _relevante_osv(v, kev, epss)]
                    if not rel:
                        continue
                    cves = [c for v in rel for c in v["cves"]]
                    n_kev = len({c for c in cves if c in kev})
                    n_crit = sum(1 for v in rel if v["severidade"] == "CRITICAL")
                    n_alta = sum(1 for v in rel if v["severidade"] == "HIGH")
                    maior_epss = max([epss.get(c) or 0 for c in cves] or [0])
                    corr = [v["corrigida"] for v in rel if v["corrigida"]]
                    sem = sum(1 for v in rel if not v["corrigida"])
                    principais = sorted(rel, key=lambda v: (
                        not any(c in kev for c in v["cves"]),
                        ORDEM_SEV.get(v["severidade"], 9),
                        -max([epss.get(c) or 0 for c in v["cves"]] or [0])))[:3]
                    linhas_pkg.append(((-n_kev, -n_crit, -n_alta, -maior_epss), p,
                                       n_kev, n_crit, n_alta, maior_epss, corr, sem,
                                       principais))
                linhas_pkg.sort(key=lambda x: x[0])
                limite_pkg = max(limite_cve * 2, 30)
                if linhas_pkg:
                    md.append("\n| Pacote-fonte | Instalado | KEV | Críticas | Altas | "
                              "Maior EPSS | Atualizar para | Principais |")
                    md.append("|---|---|---|---|---|---|---|---|")
                    for (_, p, n_kev, n_crit, n_alta, maior_epss, corr, sem,
                         principais) in linhas_pkg[:limite_pkg]:
                        alvo = (f"`{max(corr, key=chave_versao_pacote)}`" if corr
                                else "sem correção")
                        if corr and sem:
                            alvo += f" ({sem} sem correção)"
                        lista = ", ".join(
                            (v["cves"][0] if v["cves"] else v["id"])
                            + (" **KEV**" if any(c in kev for c in v["cves"]) else "")
                            for v in principais)
                        md.append(f"| {p['pacote']} | `{p['versao']}` | {n_kev or '—'} | "
                                  f"{n_crit or '—'} | {n_alta or '—'} | "
                                  f"{maior_epss * 100:.1f}% | {alvo} | {lista} |")
                    if len(linhas_pkg) > limite_pkg:
                        md.append(f"\n_({len(linhas_pkg) - limite_pkg} outro(s) "
                                  "pacote(s) com críticas/altas; o JSON traz todos.)_")
                md.append("\nUma linha por pacote-fonte, contando só KEV, crítica, "
                          "alta ou EPSS ≥ 10%. \"Atualizar para\" é a maior versão "
                          "corrigida entre elas. Médias e baixas entram na "
                          "contagem e no JSON.\n")

        if h.get("kev_fabricante"):
            md.append("#### KEV do fabricante — conferir no boletim\n")
            md.append("CVEs com exploração confirmada no produto em uso que a "
                      "consulta por versão não confirmou (CPE incompleto na "
                      "NVD ou plataforma sem CPE). Confira se a versão "
                      "instalada é afetada.\n")
            md.append("| CVE | Produto | Incluída no KEV | Ransomware | Descrição |")
            md.append("|---|---|---|---|---|")
            for k in h["kev_fabricante"]:
                desc = " ".join(k["descricao"].split())[:140].replace("|", "\\|")
                md.append(f"| {k['cve']} | {k['fabricante']} {k['produto']} | "
                          f"{k['incluido_em']} | {k['ransomware'] or '—'} | {desc} |")
            md.append("")

        if h["config"]:
            md.append("#### Apontamentos de configuração\n")
            md.append("| Severidade | Achado | Evidência | Recomendação |")
            md.append("|---|---|---|---|")
            for a in sorted(h["config"],
                            key=lambda x: ORDEM_SEV.get(x["severidade"], 9)):
                md.append(f"| {a['severidade']} | {a['titulo']} | "
                          f"`{a['evidencia']}` | {a['recomendacao']} |")
            md.append("")

    caminho = os.path.join(pasta, f"_cve_triagem_{agora:%Y%m%d_%H%M%S}.md")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return caminho


def gerar_json(hosts, kev, pasta, epss, carimbo, fontes):
    """Mesma informação do relatório, para painel, API ou análise por IA."""
    def vuln_saida(c):
        return dict(c, kev=c["id"] in kev, epss=epss.get(c["id"]))

    saida = {
        "formato": "netcve/1",
        "netcve_version": __version__,
        "gerado_em": carimbo.isoformat(timespec="seconds"),
        "fontes": fontes,
        "hosts": [],
    }
    for h in hosts:
        osv = dict(h.get("osv") or {})
        if osv.get("resultado"):
            osv["resultado"] = [dict(p, vulns=[dict(v, kev=[c for c in v["cves"] if c in kev],
                                                   epss={c: epss.get(c) for c in v["cves"]})
                                              for v in p["vulns"]])
                                for p in osv["resultado"]]
        saida["hosts"].append({
            "host": h["host"], "ip": h["ip"], "plataforma": h["plataforma"],
            "arquivo": h["arquivo"],
            "versoes": [dict(v, cves=None if v["cves"] is None else
                             [vuln_saida(c) for c in v["cves"]])
                        for v in h["versoes"]],
            "pacotes": osv,
            "catalogo": h.get("catalogo") or [],
            "kev_fabricante": h.get("kev_fabricante") or [],
            "config": h["config"],
        })
    caminho = os.path.join(pasta, f"_cve_triagem_{carimbo:%Y%m%d_%H%M%S}.json")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, indent=1)
    return caminho


def gerar_csv(hosts, kev, pasta):
    agora = datetime.now()
    caminho = os.path.join(pasta, f"_cve_triagem_{agora:%Y%m%d_%H%M%S}.csv")
    # utf-8-sig: sem BOM, o Excel no Windows abre o CSV como ANSI e
    # corrompe a acentuação.
    with open(caminho, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["host", "ip", "plataforma", "tipo", "software", "versao",
                    "identificador", "severidade", "cvss", "kev", "detalhe"])
        for h in hosts:
            for v in h["versoes"]:
                for c in v["cves"] or []:
                    w.writerow([h["host"], h["ip"], h["plataforma"], "CVE",
                                v["rotulo"], v["versao"], c["id"],
                                SEV_PT.get(c["severidade"], c["severidade"]),
                                c["nota"] or "", "sim" if c["id"] in kev else "",
                                " ".join(c["descricao"].split())[:300]])
            for a in h["config"]:
                w.writerow([h["host"], h["ip"], h["plataforma"], "CONFIG",
                            "", "", a["id"], a["severidade"], "", "",
                            a["titulo"]])
            for a in h.get("catalogo") or []:
                w.writerow([h["host"], h["ip"], h["plataforma"], "FALHA-GRAVE",
                            "", a["base"], a["id"], a["situacao"].upper(), "",
                            "sim" if any(c in kev for c in a["cves"]) else "",
                            f"{a['titulo']} ({', '.join(a['cves'])})"])
            for pacote, v in _osv_vulns(h):
                w.writerow([h["host"], h["ip"], h["plataforma"], "PACOTE",
                            pacote["pacote"], pacote["versao"],
                            ", ".join(v["cves"]) or v["id"],
                            SEV_PT.get(v["severidade"], v["severidade"]),
                            v["nota"] if v["nota"] is not None else "",
                            "sim" if any(c in kev for c in v["cves"]) else "",
                            f"corrigido em {v['corrigida']}" if v["corrigida"]
                            else "sem correção na distribuição"])
    return caminho


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------
def main():
    # Snapshots, relatórios e logs descrevem a rede: legíveis só pelo dono
    # (em Linux e macOS; no Windows valem as permissões da pasta).
    if os.name == "posix":
        os.umask(0o077)
    ap = argparse.ArgumentParser(
        description="Triagem de vulnerabilidades a partir de snapshots netsnap.")
    ap.add_argument("pasta", nargs="?", default="snapshots",
                    help="pasta com os snapshots .md (padrão: snapshots)")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                    help="chave da API NVD (ou variável NVD_API_KEY). "
                         "Sem chave: 5 req/30s; com chave: 50 req/30s. "
                         "Gratuita em nvd.nist.gov/developers/request-an-api-key")
    ap.add_argument("--sem-rede", action="store_true",
                    help="não consulta NVD/KEV; aplica apenas as heurísticas "
                         "locais de configuração")
    ap.add_argument("--limite-cve", type=int, default=15,
                    help="máximo de CVEs listados por versão (padrão: 15)")
    ap.add_argument("--csv", action="store_true",
                    help="gera também um CSV para planilha")
    ap.add_argument("--todos", action="store_true",
                    help="analisa todos os snapshots, inclusive coletas "
                         "antigas do mesmo host (padrão: só a mais recente)")
    ap.add_argument("--sem-osv", action="store_true",
                    help="não consulta o OSV para os pacotes de servidores Linux")
    ap.add_argument("--sem-epss", action="store_true",
                    help="não consulta o EPSS (probabilidade de exploração)")
    ap.add_argument("--json", action="store_true",
                    help="gera também o resultado em JSON (painel, API, IA)")
    ap.add_argument("--catalogo", metavar="ARQUIVO",
                    help="JSON com entradas adicionais para o catálogo de "
                         "falhas graves (mesma estrutura do embutido)")
    ap.add_argument("--inseguro", action="store_true",
                    help="ignora a validação do certificado TLS nas consultas "
                         "à NVD e à CISA (use apenas em rede confiável)")
    ap.add_argument("-v", "--version", action="version",
                    version=f"netcve {__version__}")
    args = ap.parse_args()

    global VERIFICAR_TLS
    if args.inseguro:
        VERIFICAR_TLS = False
        print("[!] Validação de certificado TLS desativada (--inseguro).")

    if not os.path.isdir(args.pasta):
        alternativa = os.path.join(os.path.expanduser("~"), "netsnap_snapshots")
        if os.path.isdir(alternativa):
            args.pasta = alternativa
        else:
            print(f"[ERRO] Pasta não encontrada: {args.pasta}")
            sys.exit(1)

    arquivos = sorted(
        os.path.join(args.pasta, f) for f in os.listdir(args.pasta)
        if f.endswith(".md") and not f.startswith("_")
    )
    if not arquivos:
        print(f"[ERRO] Nenhum snapshot .md em {args.pasta}")
        sys.exit(1)

    print("=" * 68)
    print(f" netcve v{__version__} — triagem de vulnerabilidades"
          + (" (sem rede)" if args.sem_rede else ""))
    print("=" * 68)
    print(f"[+] {len(arquivos)} snapshot(s) em {args.pasta}")
    if not args.sem_rede and not args.api_key:
        print("[!] Sem chave da API NVD: limite de 5 req/30s "
              "(~6,5s por consulta). Chave gratuita acelera 10x.")

    # A pasta costuma acumular coletas sucessivas do mesmo equipamento.
    # Analisar todas produz linhas repetidas no relatório e consultas
    # desnecessárias; por padrão fica apenas a mais recente de cada host.
    if not args.todos:
        recentes = {}
        for caminho in arquivos:
            meta, _ = ler_snapshot(caminho)
            chave = (meta.get("host"), meta.get("ip"))
            anterior = recentes.get(chave)
            if not anterior or meta.get("collected_at", "") >= anterior[0]:
                recentes[chave] = (meta.get("collected_at", ""), caminho)
        selecionados = sorted(c for _, c in recentes.values())
        if len(selecionados) < len(arquivos):
            print(f"[+] {len(arquivos) - len(selecionados)} snapshot(s) "
                  f"antigo(s) do mesmo host ignorado(s) "
                  f"(use --todos para incluir)")
        arquivos = selecionados

    catalogo = list(CATALOGO)
    if args.catalogo:
        try:
            catalogo += carregar_catalogo_extra(args.catalogo)
        except (OSError, ValueError, re.error) as e:
            print(f"[ERRO] Catálogo extra inválido: {e}")
            sys.exit(1)

    hosts = []
    consultas = {}
    sem_inventario = []
    textos = {}
    for caminho in arquivos:
        meta, texto = ler_snapshot(caminho)
        versoes = [dict(v, cves=None) for v in extrair_versoes(meta, texto)]
        config = avaliar_config(meta, texto)
        secoes = meta.get("sections") or []
        if isinstance(secoes, list) and secoes and "inventario" not in secoes:
            sem_inventario.append(meta.get("host"))
        osv = None
        pacotes, precisao = extrair_pacotes(texto)
        if not pacotes or not ecossistema_osv(texto):
            # Sem pacotes avaliáveis pelo OSV, só o kernel de distribuição
            # sai da NVD (a versão upstream superestima muito).
            marcar_cobertura_osv(versoes, texto, [])
        if pacotes:
            eco = ecossistema_osv(texto)
            if eco:
                osv = {"ecossistema": eco, "precisao": precisao,
                       "pacotes_total": len(pacotes), "resultado": None,
                       "_pacotes": pacotes}
                marcar_cobertura_osv(versoes, texto, pacotes)
            else:
                osv = {"motivo": f"{len(pacotes)} pacotes, mas a distribuição "
                                 "não tem base no OSV suportada aqui (Debian, "
                                 "Ubuntu, Rocky Linux, AlmaLinux)."}
        hosts.append({
            "host": meta.get("host"),
            "ip": meta.get("ip"),
            "plataforma": meta.get("platform_name"),
            "plataforma_chave": meta.get("platform_key", ""),
            "arquivo": os.path.basename(caminho),
            "versoes": versoes,
            "config": config,
            "osv": osv,
        })
        textos[id(hosts[-1])] = (meta, texto)
        print(f"    {str(meta.get('host') or '?'):22} {len(versoes)} versão(ões), "
              f"{len(config)} apontamento(s) de configuração"
              + (f", {len(pacotes)} pacote(s)" if pacotes else ""))
        for v in versoes:
            if v["consultavel"]:
                consultas.setdefault(
                    (v["cpe_fornecedor"], v["cpe_produto"], v["versao"]), [])

    if sem_inventario:
        print(f"\n[!] {len(sem_inventario)} snapshot(s) sem a seção "
              "*Inventário*: a versão só pode ser deduzida da configuração, "
              "quando declarada.")
        print("    Para triagem completa, colete com a opção 'Inventário' ou "
              "'Extração total' no netsnap.")
        print(f"    Host(s): {', '.join(sem_inventario[:8])}"
              + (" ..." if len(sem_inventario) > 8 else ""))

    kev = {}
    epss = {}
    cache = {}
    if not args.sem_rede:
        print(f"\n[+] {len(consultas)} consulta(s) única(s) à NVD "
              f"(versões repetidas são consultadas uma só vez)")
        cache = carregar_cache()
        delay = DELAY_COM_CHAVE if args.api_key else DELAY_SEM_CHAVE
        print("[+] Obtendo catálogo CISA KEV ...")
        kev = baixar_kev()
        print(f"    {len(kev)} CVEs com exploração confirmada")

        for i, (fornecedor, produto, versao) in enumerate(consultas, 1):
            rotulo = f"{fornecedor}:{produto}:{versao}"
            print(f"    [{i}/{len(consultas)}] {rotulo}")
            try:
                cves, do_cache = consultar_nvd(fornecedor, produto, versao,
                                               args.api_key, cache)
                consultas[(fornecedor, produto, versao)] = cves
                origem = "cache" if do_cache else "NVD"
                print(f"        {len(cves)} correspondência(s) [{origem}]")
                if not do_cache:
                    # Salva a cada consulta: um Ctrl+C no meio de uma
                    # varredura longa não perde o que já foi obtido.
                    salvar_cache(cache)
                    if i < len(consultas):
                        time.sleep(delay)
            except Exception as e:
                print(f"        [!] Falha: {e}")
                ajuda = explicar_falha_tls(e)
                if ajuda:
                    print(ajuda)
                    print("    Consultas à NVD interrompidas; o relatório "
                          "será gerado apenas com as heurísticas locais.\n")
                    consultas = {k: None for k in consultas}
                    break
                consultas[(fornecedor, produto, versao)] = None
        salvar_cache(cache)

        for h in hosts:
            for v in h["versoes"]:
                if v["consultavel"]:
                    v["cves"] = consultas.get(
                        (v["cpe_fornecedor"], v["cpe_produto"], v["versao"]))

        # Pacotes de servidores Linux: uma consulta por servidor ao OSV,
        # mais o detalhe de cada vulnerabilidade (em cache por 7 dias).
        com_osv = [h for h in hosts if h["osv"] and h["osv"].get("ecossistema")]
        if com_osv and not args.sem_osv:
            print(f"\n[+] OSV: pacotes de {len(com_osv)} servidor(es) Linux")
            for h in com_osv:
                o = h["osv"]
                try:
                    o["resultado"] = consultar_osv(o["ecossistema"], o["_pacotes"], cache)
                    n = sum(len(p["vulns"]) for p in o["resultado"])
                    print(f"    {str(h['host']):22} {o['ecossistema']}: "
                          f"{len(o['resultado'])} pacote(s) afetado(s), {n} vulnerabilidade(s)")
                except Exception as e:
                    o["erro"] = f"falha na consulta ao OSV: {e}"
                    print(f"    [!] {h['host']}: {o['erro']}")
                salvar_cache(cache)
        elif com_osv:
            for h in com_osv:
                h["osv"]["erro"] = "consulta ao OSV desativada (--sem-osv)"

        if not args.sem_epss:
            todas = {c["id"] for h in hosts for v in h["versoes"] for c in (v["cves"] or [])}
            todas |= {c for h in hosts for _, v in _osv_vulns(h) for c in v["cves"]}
            todas |= {c for e in catalogo for c in e["cves"]}
            if todas:
                print(f"\n[+] EPSS: {len(todas)} CVE(s)")
                epss = consultar_epss(todas, cache)
                salvar_cache(cache)
    else:
        print("[+] Modo sem rede: apenas heurísticas locais de configuração")

    # Catálogo de falhas graves e KEV do fabricante (precisa do resultado OSV)
    for h in hosts:
        meta, texto = textos[id(h)]
        osv_res = (h["osv"] or {}).get("resultado")
        h["catalogo"] = avaliar_catalogo(meta, texto, h["versoes"], osv_res, catalogo)
        if kev:
            vistos = {c["id"] for v in h["versoes"] for c in (v["cves"] or [])}
            vistos |= {c for _, v in _osv_vulns(h) for c in v["cves"]}
            vistos |= {c for a in h["catalogo"] for c in a["cves"]}
            # PHP de pacote da distribuição já foi conferido pelo OSV.
            tem_php = any(v["rotulo"] == "PHP" and not v.get("coberto_osv")
                          for v in h["versoes"])
            h["kev_fabricante"] = kev_do_fabricante(h["plataforma_chave"], tem_php,
                                                    kev, vistos)
        if h["osv"]:
            h["osv"].pop("_pacotes", None)

    fontes = ["heurísticas locais", "catálogo de falhas graves"]
    if not args.sem_rede:
        fontes = ["NVD CVE API 2.0", "CISA KEV"] + fontes
        if not args.sem_osv:
            fontes.append("OSV.dev")
        if not args.sem_epss:
            fontes.append("EPSS (FIRST)")
    carimbo = datetime.now()
    rel = gerar_relatorio(hosts, kev, args.pasta, args.sem_rede, args.limite_cve,
                          epss, carimbo, fontes)
    print(f"\n[+] Relatório: {rel}")
    if args.csv:
        print(f"[+] CSV: {gerar_csv(hosts, kev, args.pasta)}")
    if args.json:
        print(f"[+] JSON: {gerar_json(hosts, kev, args.pasta, epss, carimbo, fontes)}")

    graves = [(h["host"], a["id"]) for h in hosts for a in h["catalogo"]
              if a["situacao"] != "parcial"]
    if graves:
        print("\n[!] Falhas graves do catálogo: "
              + ", ".join(f"{a} em {hh}" for hh, a in graves[:10]))
    total_kev = (sum(1 for h in hosts for v in h["versoes"]
                     for c in (v["cves"] or []) if c["id"] in kev)
                 + sum(1 for h in hosts for _ in _kev_osv(h, kev)))
    if total_kev:
        print(f"\n[!] {total_kev} correspondência(s) no catálogo CISA KEV "
              "(exploração confirmada) — priorizar.")


if __name__ == "__main__":
    main()
