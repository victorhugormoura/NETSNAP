#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netcve — Triagem de vulnerabilidades a partir de snapshots do netsnap

Lê os arquivos Markdown gerados pelo netsnap, extrai versões de software e
indicadores de configuração insegura, consulta a base NVD (NIST) e o catálogo
CISA KEV, e gera um relatório consolidado de exposição.

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

__version__ = "0.3.1"

import os
import re
import sys
import csv
import ssl
import json
import time
import argparse
import importlib.util
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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
        (r"(?im)^\s*Junos:\s*([0-9][\w.\-]+)", "juniper", "junos", "Junos"),
        # A configuração em 'display set' declara a release; permite triagem
        # mesmo em snapshot coletado apenas no modo Configuração.
        (r"(?im)^set version\s+([0-9][\w.\-]+)", "juniper", "junos", "Junos"),
        (r"(?im)^\s*version\s+([0-9]+\.[0-9]+[A-Z][\w.\-]*)",
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
        (r"(?im)^\s*(?:system|NXOS):\s*version\s*([0-9][\w.()\-]*)",
         "cisco", "nx-os", "NX-OS"),
        (r"(?im)^version\s+([0-9]+\.[0-9]+\([0-9][\w.)]*)",
         "cisco", "nx-os", "NX-OS"),
    ],
    "cisco_xr": [
        (r"(?i)Cisco IOS XR Software,?.*?Version\s*([0-9][\w.\-]*)",
         "cisco", "ios_xr", "IOS-XR"),
    ],
    "mikrotik_routeros": [
        (r"(?im)^\s*version:\s*([0-9][\w.\-]*)", "mikrotik", "routeros",
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
]

# ---------------------------------------------------------------------------
# Regras de configuração insegura (heurísticas locais, sem consulta externa)
# ---------------------------------------------------------------------------
REGRAS_CONFIG = [
    {
        "id": "CFG-TELNET",
        "titulo": "Telnet habilitado (credenciais em texto claro)",
        "severidade": "ALTA",
        "plataformas": None,
        "padrao": r"(?im)^\s*(?:set\s+system\s+services\s+telnet|"
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
        "padrao": r"(?im)^\s*(?:ip\s+http\s+server|"
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
        "padrao": r"(?im)^\s*\d+\s+(telnet|ftp|www|api)\s+\d+",
        "recomendacao": "Desabilitar serviços não utilizados em "
                        "/ip service e restringir 'available from'.",
    },
    {
        "id": "CFG-SSH-SENHA-ROOT",
        "titulo": "Login SSH direto como root permitido",
        "severidade": "ALTA",
        "plataformas": ["linux"],
        "padrao": r"(?im)^\s*PermitRootLogin\s+yes",
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
        "padrao": r"(?im)^\s*(?!.*version\s+\"?none)"
                  r"\s*options\s*\{(?![\s\S]{0,2000}?version\s)",
        "recomendacao": "Definir version \"none\"; em options{} para não "
                        "revelar a release em uso.",
    },
    {
        "id": "CFG-NTP-SEM-AUTENTICACAO",
        "titulo": "NTP sem autenticação configurada",
        "severidade": "BAIXA",
        "plataformas": None,
        "padrao": r"(?im)^\s*(?:ntp\s+server\s+(?!disable\b|enable\b|"
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


def texto_para_versao(texto):
    """Reordena o snapshot para a busca de versão.

    A seção Inventário vem primeiro; Vizinhança e Logs ficam de fora, porque
    descrevem outros equipamentos. Num CE6860 (VRP 8.191) a primeira
    ocorrência de "Version 5.170" no arquivo era a de um vizinho LLDP, e a
    versão relatada era a dele."""
    partes = re.split(r"(?m)^(?=## )", texto)
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


def http_json(url, timeout=45, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout,
                                context=contexto_ssl()) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


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
    """Catálogo CISA de vulnerabilidades comprovadamente exploradas."""
    try:
        dados = http_json(KEV_URL)
        return {v["cveID"] for v in dados.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[!] Não foi possível obter o catálogo CISA KEV: {e}")
        ajuda = explicar_falha_tls(e)
        if ajuda:
            print(ajuda)
        return set()


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
                dados = http_json(url, headers=headers)
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
# Relatório
# ---------------------------------------------------------------------------
ORDEM_SEV = {"CRITICAL": 0, "CRÍTICA": 0, "HIGH": 1, "ALTA": 1,
             "MEDIUM": 2, "MEDIA": 2, "MÉDIA": 2, "LOW": 3, "BAIXA": 3}
SEV_PT = {"CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MEDIUM": "MÉDIA",
          "LOW": "BAIXA", "NONE": "NENHUMA", "DESCONHECIDA": "DESCONHECIDA"}


def gerar_relatorio(hosts, kev, pasta, sem_rede, limite_cve):
    agora = datetime.now()
    total_cve = sum(len(v["cves"] or []) for h in hosts for v in h["versoes"])
    total_kev = sum(1 for h in hosts for v in h["versoes"]
                    for c in (v["cves"] or []) if c["id"] in kev)
    total_cfg = sum(len(h["config"]) for h in hosts)

    md = ["---",
          f"netcve_version: {json.dumps(__version__)}",
          f"document_type: {json.dumps('vulnerability_triage')}",
          f"generated_at: {json.dumps(agora.isoformat(timespec='seconds'))}",
          f"hosts_analyzed: {len(hosts)}",
          f"cve_matches: {total_cve}",
          f"kev_matches: {total_kev}",
          f"config_findings: {total_cfg}",
          f"sources: {json.dumps(['NVD CVE API 2.0', 'CISA KEV'] if not sem_rede else ['heurísticas locais'])}",
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
    md.append(f"- Delas, no catálogo CISA KEV: **{total_kev}**")
    md.append(f"- Apontamentos de configuração: **{total_cfg}**\n")

    # Prioridade: KEV primeiro
    if total_kev:
        md.append("## Prioridade máxima — exploração confirmada (CISA KEV)\n")
        md.append("| Host | Software | Versão | CVE | CVSS |")
        md.append("|---|---|---|---|---|")
        for h in hosts:
            for v in h["versoes"]:
                for c in v["cves"] or []:
                    if c["id"] in kev:
                        md.append(f"| {h['host']} | {v['rotulo']} | "
                                  f"`{v['versao']}` | {c['id']} | "
                                  f"{c['nota'] or '—'} |")
        md.append("")

    md.append("## Inventário de versões identificadas\n")
    md.append("| Host | IP | Plataforma | Software | Versão | CVEs |")
    md.append("|---|---|---|---|---|---|")
    for h in hosts:
        if not h["versoes"]:
            md.append(f"| {h['host']} | {h['ip']} | {h['plataforma']} | "
                      f"_nenhuma versão reconhecida_ | — | — |")
        for v in h["versoes"]:
            qtd = ("n/d" if not v["consultavel"] else
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
    return caminho


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------
def main():
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

    hosts = []
    consultas = {}
    sem_inventario = []
    for caminho in arquivos:
        meta, texto = ler_snapshot(caminho)
        versoes = extrair_versoes(meta, texto)
        config = avaliar_config(meta, texto)
        secoes = meta.get("sections") or []
        if isinstance(secoes, list) and secoes and "inventario" not in secoes:
            sem_inventario.append(meta.get("host"))
        hosts.append({
            "host": meta.get("host"),
            "ip": meta.get("ip"),
            "plataforma": meta.get("platform_name"),
            "arquivo": os.path.basename(caminho),
            "versoes": [dict(v, cves=None) for v in versoes],
            "config": config,
        })
        print(f"    {str(meta.get('host') or '?'):22} {len(versoes)} versão(ões), "
              f"{len(config)} apontamento(s) de configuração")
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

    kev = set()
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
    else:
        print("[+] Modo sem rede: apenas heurísticas locais de configuração")

    rel = gerar_relatorio(hosts, kev, args.pasta, args.sem_rede, args.limite_cve)
    print(f"\n[+] Relatório: {rel}")
    if args.csv:
        print(f"[+] CSV: {gerar_csv(hosts, kev, args.pasta)}")

    total_kev = sum(1 for h in hosts for v in h["versoes"]
                    for c in (v["cves"] or []) if c["id"] in kev)
    if total_kev:
        print(f"\n[!] {total_kev} correspondência(s) no catálogo CISA KEV "
              "(exploração confirmada) — priorizar.")


if __name__ == "__main__":
    main()
