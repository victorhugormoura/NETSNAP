#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_topologia — topologia da rede a partir dos snapshots do netsnap

Monta um grafo de equipamentos e enlaces em JSON, com duas fontes:

  LLDP/CDP   seção Vizinhança: quem o equipamento vê em cada porta
  L3         seção Configuração: dois equipamentos coletados com endereços
             na mesma sub-rede ponto a ponto (/29 a /31 em IPv4, /112 a
             /127 em IPv6) estão ligados naquela interface. Cobre roteadores
             sem LLDP, caso comum em bordas Juniper.

O que cada enlace informa:
  a, porta_a          equipamento e porta de quem anunciou a vizinhança
  b, porta_b          vizinho e porta remota (no enlace confirmado, a porta
                      como o próprio vizinho a nomeia)
  tipo                "lldp" ou "l3"
  rede                sub-rede do enlace L3
  confirmado          os dois lados foram coletados e se veem mutuamente;
                      todo enlace L3 é confirmado (vem das duas configurações)
  origem              arquivos e comandos de onde o enlace foi lido

O mesmo equipamento coletado por vários endereços (roteador acessado pelo IP
de cada interface) vira um nó só, identificado pelo hostname; nomes de
fábrica ("MikroTik", "HUAWEI") continuam separados por endereço.

Limites:
  - Enlace sem LLDP/CDP e sem endereçamento ponto a ponto entre equipamentos
    coletados não aparece. Ausência no grafo não significa ausência de cabo.
  - Formatos validados em coleta real: Huawei VRP ('display lldp neighbor
    brief' e 'display lldp neighbor') e configuração Junos. Os demais seguem
    a sintaxe documentada de cada plataforma.

Uso direto:
    python3 netsnap_topologia.py [pasta] [--saida arquivo.json]
                                 [--desenho arquivo.pdf|arquivo.svg] [--todos]

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.1.0"

import ipaddress
import json
import os
import re
import sys
from datetime import datetime

import netsnap_md as md

# ---------------------------------------------------------------------------
# Tabelas com colunas alinhadas (Junos 'show lldp neighbors', Huawei
# 'display lldp neighbor brief'). As colunas são localizadas pelos rótulos do
# cabeçalho, inclusive os que não interessam, para delimitar corretamente
# onde cada coluna termina.
# ---------------------------------------------------------------------------
ROTULOS_LOCAL = ["Local Interface", "Local Intf", "Local Port ID",
                 "Local Port"]
ROTULOS_DISPOSITIVO = ["System Name", "Neighbor Device", "Neighbor Dev",
                       "Device ID", "Device-ID", "SysName"]
ROTULOS_REMOTO = ["Neighbor Interface", "Neighbor Intf", "Port info",
                  "Port ID", "Port-ID", "Remote Port"]
ROTULOS_OUTROS = ["Parent Interface", "Chassis Id", "Chassis ID",
                  "Exptime(s)", "Exptime", "Hold-time", "Holdtime",
                  "Hold Time", "Capability", "Platform", "Port Description",
                  "Expire"]


def _posicoes(cabecalho):
    """Mapeia rótulos encontrados no cabeçalho para (inicio, papel)."""
    achados = []
    ocupado = []
    for papel, rotulos in (("local", ROTULOS_LOCAL),
                           ("dispositivo", ROTULOS_DISPOSITIVO),
                           ("remoto", ROTULOS_REMOTO),
                           ("outro", ROTULOS_OUTROS)):
        for r in rotulos:
            for m in re.finditer(re.escape(r), cabecalho, re.I):
                ini, fim = m.start(), m.end()
                if any(a <= ini < b or a < fim <= b for a, b in ocupado):
                    continue
                ocupado.append((ini, fim))
                achados.append((ini, papel))
    return sorted(achados)


def _vizinho(local, dispositivo, remota, ip="", alternativas=()):
    return {
        "porta_local": local,
        "dispositivo": dispositivo,
        "porta_remota": remota,
        "portas_alt": [a for a in alternativas if a and a != remota],
        "ip_gerencia": ip,
    }


def ler_tabela(texto):
    vizinhos = []
    linhas = texto.splitlines()
    for idx, linha in enumerate(linhas):
        pos = _posicoes(linha)
        papeis = {p for _, p in pos}
        if not {"local", "dispositivo"} <= papeis and \
                not {"local", "remoto"} <= papeis:
            continue
        for row in linhas[idx + 1:]:
            if not row.strip() or re.match(r"^[\s\-=+]+$", row):
                continue
            if _posicoes(row) and len({p for _, p in _posicoes(row)}) >= 2:
                break
            campos = {}
            for n, (ini, papel) in enumerate(pos):
                fim = pos[n + 1][0] if n + 1 < len(pos) else None
                valor = row[ini:fim].strip() if fim else row[ini:].strip()
                if papel != "outro":
                    campos[papel] = valor
            if campos.get("local"):
                vizinhos.append(_vizinho(campos.get("local", ""),
                                         campos.get("dispositivo", ""),
                                         campos.get("remoto", "")))
        break
    return vizinhos


# ---------------------------------------------------------------------------
# Saídas em blocos "Campo : valor"
# ---------------------------------------------------------------------------
def _campo(bloco, *padroes):
    for p in padroes:
        m = re.search(p, bloco, re.I | re.M)
        if m:
            return m.group(1).strip()
    return ""


def ler_huawei_detalhe(texto):
    vizinhos = []
    partes = re.split(r"(?m)^(\S+) has (\d+) neighbor\(?s?\)?:?\s*$", texto)
    # partes: [prefixo, porta, qtd, bloco, porta, qtd, bloco, ...]
    for k in range(1, len(partes) - 2, 3):
        porta, qtd, bloco = partes[k], int(partes[k + 1]), partes[k + 2]
        if not qtd:
            continue
        for sub in re.split(r"(?m)^Neighbor index\s*:", bloco)[1:]:
            vizinhos.append(_vizinho(
                porta,
                _campo(sub, r"^System name\s*:\s*(.*)$"),
                _campo(sub, r"^Port ID\s*:\s*(.*)$"),
                # V5 escreve "Management address value :"; outras versões,
                # "Management address :". IPv4 primeiro: é o que se coleta.
                _campo(sub, r"^Management address(?: value)?\s*:\s*"
                            r"(\d+\.\d+\.\d+\.\d+)\s*$",
                       r"^Management address(?: value)?\s*:\s*"
                       r"([0-9a-fA-F:]+:[0-9a-fA-F:]*)\s*$"),
                [_campo(sub, r"^Port description\s*:\s*(.*)$")]))
    return vizinhos


def ler_junos_detalhe(texto):
    """Junos: 'show lldp neighbors detail' (19.1R2+) e
    'show lldp neighbors interface X'. Cada vizinho é um bloco "LLDP Neighbor
    Information" com "Local Information" e "Neighbour Information"."""
    vizinhos = []
    for bloco in re.split(r"(?mi)^\s*LLDP Neighbou?r Information\s*:?\s*$",
                          texto):
        local = _campo(bloco, r"^\s*Local Interface\s*:\s*(\S+)")
        if not local:
            continue
        tipo_porta = _campo(bloco, r"^\s*Port type\s*:\s*(.*)$")
        porta_id = _campo(bloco, r"^\s*Port ID\s*:\s*(.*)$")
        descricao = _campo(bloco, r"^\s*Port description\s*:\s*(.*)$")
        # Vizinho Junos com port-id-subtype padrão (locally-assigned) anuncia
        # o índice SNMP como Port ID; a descrição da porta é o que identifica
        # a interface.
        indice = re.search(r"(?i)locally assigned", tipo_porta) or \
            re.fullmatch(r"\d+", porta_id or "")
        remota = descricao if (indice and descricao) else porta_id
        vizinhos.append(_vizinho(
            local,
            _campo(bloco, r"^\s*System name\s*:\s*(.*)$"),
            remota,
            _campo(bloco, r"^\s*Address\s*:\s*(\d+\.\d+\.\d+\.\d+)",
                   r"^\s*Management address\s*:\s*(\d+\.\d+\.\d+\.\d+)"),
            [porta_id, descricao]))
    return vizinhos


def ler_cdp_detalhe(texto):
    vizinhos = []
    for bloco in re.split(r"(?m)^-{5,}\s*$|(?=^Device ID\s*:)", texto):
        disp = _campo(bloco, r"^Device ID\s*:\s*(.*)$")
        if not disp:
            continue
        vizinhos.append(_vizinho(
            _campo(bloco, r"^Interface\s*:\s*([^,]+),"),
            disp,
            _campo(bloco, r"Port ID \(outgoing port\)\s*:\s*(\S+)"),
            _campo(bloco, r"^\s*(?:IP|IPv4) [Aa]ddress\s*:\s*([0-9.]+)")))
    return vizinhos


def ler_lldp_detalhe_cisco(texto):
    """IOS/IOS-XE, NX-OS e IOS-XR: 'show lldp neighbors detail'."""
    vizinhos = []
    # NX-OS lista "Local Port id" depois de "Port id": o bloco começa em
    # "Chassis id". IOS e IOS-XR começam pela porta local.
    if re.search(r"(?m)^\s*Local Port id\s*:", texto):
        inicio = r"(?m)(?=^\s*Chassis id\s*:)"
    else:
        inicio = r"(?m)(?=^\s*(?:Local Intf|Local Interface)\s*:)"
    for bloco in re.split(inicio, texto):
        local = _campo(bloco, r"^\s*(?:Local Intf|Local Port id|"
                              r"Local Interface)\s*:\s*(\S+)")
        if not local:
            continue
        vizinhos.append(_vizinho(
            local,
            _campo(bloco, r"^\s*System Name\s*:\s*(.*)$"),
            _campo(bloco, r"^\s*Port id\s*:\s*(.*)$"),
            _campo(bloco, r"^\s*(?:IP|IPv4 address|Management Address(?:es)?)"
                          r"\s*:\s*([0-9]+\.[0-9.]+)",
                   r"^\s+IP\s*:\s*([0-9.]+)"),
            [_campo(bloco, r"^\s*Port Description\s*:\s*(.*)$")]))
    return vizinhos


def ler_mikrotik(texto):
    """'/ip neighbor print detail': entradas numeradas com chave=valor."""
    vizinhos = []
    entradas = re.split(r"(?m)^\s*\d+\s+(?=[A-Z ]*\s*\w[\w-]*=)", texto)
    for e in entradas:
        pares = dict(re.findall(r'([\w-]+)=("[^"]*"|\S+)', e))
        pares = {k: v.strip('"') for k, v in pares.items()}
        if not pares.get("interface"):
            continue
        vizinhos.append(_vizinho(
            pares.get("interface", ""),
            pares.get("identity", ""),
            pares.get("interface-name", ""),
            pares.get("address", pares.get("address4", ""))))
    return vizinhos


def ler_lldpd(texto):
    """Linux: 'lldpcli show neighbors detail' / 'lldpctl'."""
    vizinhos = []
    for bloco in re.split(r"(?m)(?=^Interface:\s)", texto):
        local = _campo(bloco, r"^Interface:\s*([^,\s]+)")
        if not local:
            continue
        porta = _campo(bloco, r"^\s*PortID:\s*(?:ifname|local)\s+(.*)$",
                       r"^\s*PortID:\s*\S+\s+(.*)$")
        vizinhos.append(_vizinho(
            local,
            _campo(bloco, r"^\s*SysName:\s*(.*)$"),
            porta,
            _campo(bloco, r"^\s*MgmtIP:\s*([0-9.]+)"),
            [_campo(bloco, r"^\s*PortDescr:\s*(.*)$")]))
    return vizinhos


def _eh_tabela(comando):
    c = comando.lower()
    return "neighbor brief" in c or c.strip() == "show lldp neighbors"


PADRAO_BLOCO_JUNOS = re.compile(
    r"(?mi)^\s*(?:LLDP Neighbou?r Information|Neighbou?r Information)\s*:")


def vizinhos_do_comando(comando, saida):
    c = comando.lower().strip()
    if "neighbor brief" in c or c == "show lldp neighbors":
        return ler_tabela(saida)
    if c.startswith("display lldp neighbor"):
        return ler_huawei_detalhe(saida)
    if "cdp neighbors detail" in c:
        return ler_cdp_detalhe(saida)
    if "lldp neighbors detail" in c or c.startswith("show lldp neighbors interface"):
        # Junos e Cisco usam o mesmo comando; o formato decide.
        if PADRAO_BLOCO_JUNOS.search(saida):
            return ler_junos_detalhe(saida)
        return ler_lldp_detalhe_cisco(saida)
    if c.startswith("/ip neighbor print"):
        return ler_mikrotik(saida)
    if c.startswith("lldpcli") or c.startswith("lldpctl"):
        return ler_lldpd(saida)
    if c.startswith("/") or c.startswith("show configuration") or \
            c in ("show lldp", "show lldp local-information"):
        return []
    # Formato desconhecido (FiberHome): tenta tabela, depois blocos Cisco.
    return ler_tabela(saida) or ler_lldp_detalhe_cisco(saida)


# ---------------------------------------------------------------------------
# Diagnóstico da vizinhança: nenhum vizinho, LLDP desligado, como ativar
# ---------------------------------------------------------------------------
# Comandos conferidos na documentação dos fabricantes (Juniper, Huawei linha
# S, MikroTik, Cisco, lldpd). Onde a sintaxe não pôde ser conferida, o texto
# diz isso em vez de sugerir um comando.
COMO_ATIVAR = {
    "juniper_junos": {
        "comandos": ["set protocols lldp interface all",
                     "set protocols lldp port-id-subtype interface-name",
                     "commit"],
        "nota": "Modo de configuração. O LLDP vem desligado no MX e ligado "
                "de fábrica no EX. O port-id-subtype faz o vizinho ver o nome "
                "da porta em vez do índice SNMP. Para não anunciar em "
                "trânsito ou IX: set protocols lldp interface <porta> disable.",
    },
    "huawei": {
        "comandos": ["system-view", "lldp enable",
                     "interface <porta>", " lldp enable"],
        "nota": "VRP V5 (linha S). O global liga o protocolo; o da interface "
                "só é preciso onde ele tiver sido desligado.",
    },
    "huawei_ce": {
        "comandos": ["system-view", "lldp enable", "commit"],
        "nota": "Mesma sintaxe da linha S; no VRP V8 a alteração só vale "
                "depois do commit. Confira no guia do modelo (CE/NE) se a "
                "interface também exige lldp enable.",
    },
    "huawei_smartax": {
        "comandos": [],
        "nota": "A sintaxe de LLDP do MA5800 não foi conferida; consulte o "
                "guia de configuração da versão instalada.",
    },
    "fiberhome": {
        "comandos": [],
        "nota": "A sintaxe de LLDP da FiberHome não foi conferida; consulte "
                "o manual da versão instalada.",
    },
    "cisco_ios": {
        "comandos": ["configure terminal", "lldp run", "cdp run"],
        "nota": "No IOS/IOS-XE o LLDP vem desligado; o CDP costuma vir "
                "ligado. Por interface: lldp transmit / lldp receive.",
    },
    "cisco_nxos": {
        "comandos": ["configure terminal", "feature lldp"],
        "nota": "Depois do feature lldp, transmissão e recepção ficam ligadas "
                "nas interfaces.",
    },
    "cisco_xr": {
        "comandos": ["configure", "lldp", "commit"],
        "nota": "O lldp global liga transmissão e recepção nas interfaces "
                "suportadas. CDP no XR exige 'cdp' global e em cada "
                "interface.",
    },
    "mikrotik_routeros": {
        "comandos": ["/ip neighbor discovery-settings set "
                     "discover-interface-list=all protocol=cdp,lldp,mndp"],
        "nota": "O parâmetro protocol existe a partir do RouterOS 6.48; em "
                "versões anteriores, omita-o. Em vez de all, prefira uma "
                "interface list só com as portas de backbone.",
    },
    "linux": {
        "comandos": ["apt install lldpd", "systemctl enable --now lldpd"],
        "nota": "No RHEL/Fedora, dnf install lldpd. Os vizinhos precisam "
                "anunciar LLDP para aparecerem.",
    },
}

PADRAO_LLDP_DESLIGADO = re.compile(
    r"(?i)(?:\bLLDP\s*:\s*Disabled\b|global lldp is (?:not enabled|disabled)|"
    r"lldp is not enabled|lldp (?:is )?disabled|% lldp is not enabled|"
    r"lldp(?:cli|ctl)?: (?:command )?not found|lldpcli: comando não encontrado|"
    r"unable to connect to socket|discover-interface-list:\s*none\b)")


def diagnosticar_vizinhanca(tipo, saidas):
    """Analisa as saídas da seção Vizinhança de um equipamento.

    saidas: [(comando, saida)]. Devolve dict com vizinhos (quantidade),
    estado ("ok", "desligado", "sem_vizinhos"), motivo (texto) e como_ativar
    (comandos e nota da plataforma)."""
    detalhadas, resumidas, desligado = [], [], False
    for cmd, saida in saidas:
        if not saida:
            continue
        if PADRAO_LLDP_DESLIGADO.search(saida):
            desligado = True
        recusado = saida.startswith("[ERRO") or re.search(
            r"(?i)syntax error|unknown command|unrecognized command", saida)
        if tipo == "juniper_junos" and not recusado:
            c = cmd.strip()
            if c == "show configuration protocols lldp" and \
                    "interface" not in saida:
                desligado = True
            # LLDP também pode vir de um grupo de configuração.
            if c.startswith("show configuration |") and not re.search(
                    r"(?m)^set (?:groups \S+ )?protocols lldp interface",
                    saida):
                desligado = True
        if saida.startswith("[ERRO ao executar comando"):
            continue
        vs = [v for v in vizinhos_do_comando(cmd, saida) if v["porta_local"]]
        (resumidas if _eh_tabela(cmd) else detalhadas).extend(vs)
    n = max(len(detalhadas), len(resumidas))
    ativar = COMO_ATIVAR.get(tipo, {"comandos": [], "nota": ""})
    if n:
        return {"vizinhos": n, "estado": "ok", "motivo": "",
                "como_ativar": ativar}
    if desligado:
        motivo = "LLDP desligado ou não configurado neste equipamento"
    else:
        motivo = ("nenhum vizinho LLDP/CDP anunciado (o protocolo também "
                  "precisa estar ativo nos vizinhos)")
    return {"vizinhos": 0, "estado": "desligado" if desligado
            else "sem_vizinhos", "motivo": motivo, "como_ativar": ativar}


def texto_como_ativar(tipo):
    a = COMO_ATIVAR.get(tipo)
    if not a:
        return ""
    if a["comandos"]:
        return "para ativar: " + " ; ".join(c.strip() for c in a["comandos"]) \
            + (f" — {a['nota']}" if a["nota"] else "")
    return a["nota"]


# ---------------------------------------------------------------------------
# Nomes de porta: o mesmo enlace visto pelos dois lados chega com nomes em
# formas diferentes (XGE0/0/3 x XGigabitEthernet0/0/3, Gi0/1 x
# GigabitEthernet0/1, xe-0/0/0.0 x xe-0/0/0).
# ---------------------------------------------------------------------------
_PREFIXOS_PORTA = sorted([
    ("hundredgigabitethernet", "100ge"), ("hundredgige", "100ge"),
    ("100gigabitethernet", "100ge"), ("fortygigabitethernet", "40ge"),
    ("fortygige", "40ge"), ("40gigabitethernet", "40ge"),
    ("twentyfivegigabitethernet", "25ge"), ("twentyfivegige", "25ge"),
    ("25gigabitethernet", "25ge"), ("tengigabitethernet", "10ge"),
    ("tengige", "10ge"), ("10gigabitethernet", "10ge"),
    ("xgigabitethernet", "10ge"), ("xge", "10ge"), ("te", "10ge"),
    ("gigabitethernet", "ge"), ("gige", "ge"), ("gi", "ge"),
    ("fastethernet", "fe"), ("fa", "fe"),
    ("eth-trunk", "eth-trunk"), ("ethernet", "eth"),
    ("port-channel", "po"), ("bundle-ether", "be"),
], key=lambda p: -len(p[0]))


def porta_canonica(nome):
    s = re.sub(r"\s+", "", (nome or "").lower())
    for longo, curto in _PREFIXOS_PORTA:
        # Só prefixo seguido de número: "te" não pode capturar "team0".
        if s.startswith(longo) and re.match(r"\d", s[len(longo):] or "x"):
            s = curto + s[len(longo):]
            break
    return re.sub(r"\.0$", "", s)


def _variantes_porta(nome):
    """Formas de um nome de porta anunciado pelo vizinho."""
    v = {porta_canonica(nome)}
    # MikroTik anuncia "bridge1/sfp-sfpplus1" como descrição da porta.
    m = re.fullmatch(r"[A-Za-z][\w.-]*/([A-Za-z][\w.-]*)", (nome or "").strip())
    if m:
        v.add(porta_canonica(m.group(1)))
    v.discard("")
    return v


# ---------------------------------------------------------------------------
# Identidade do equipamento coletado: nomes pelos quais os vizinhos o veem
# ---------------------------------------------------------------------------
# Só na configuração e nas informações LLDP locais: a mesma forma "System
# name :" aparece na lista de vizinhos do Huawei e designa o vizinho.
PADROES_NOME_CONFIG = [
    r"(?m)^set system host-name\s+(\S+)",
    r"(?m)^\s*sysname\s+(\S+)",
    r"(?m)^hostname\s+(\S+)",
    r"(?m)^/system identity\s*\n\s*set name=(\"[^\"]+\"|\S+)",
]
PADRAO_NOME_LLDP_LOCAL = r"(?m)^System name\s*:\s*(\S+)"

# Nomes que não identificam um equipamento: dois MikroTik de fábrica não são
# o mesmo roteador.
NOMES_GENERICOS = {"", "mikrotik", "huawei", "router", "switch", "localhost",
                   "juniper", "cisco", "fiberhome", "olt", "ubuntu", "debian"}


def nomes_do_host(snap):
    nomes = set()
    host = snap["meta"].get("host")
    if host:
        nomes.add(host)
    for s in snap["secoes"]:
        if s["modulo"]:
            continue
        for c in s["comandos"]:
            if not c["saida"]:
                continue
            if s["chave"] == "config":
                padroes = PADROES_NOME_CONFIG
            elif s["chave"] == "vizinhanca" and "local-information" in c["comando"]:
                padroes = [PADRAO_NOME_LLDP_LOCAL]
            else:
                continue
            for p in padroes:
                for m in re.finditer(p, c["saida"]):
                    nome = m.group(1).strip('"')
                    nomes.add(nome)
                    # Junos anuncia o FQDN quando o host-name o contém
                    # ("BRAS-CLEMENTINA.migonet.com.br"); vizinhos podem
                    # usar só a primeira parte.
                    if "." in nome and not re.fullmatch(r"[\d.]+", nome):
                        nomes.add(nome.split(".", 1)[0])
    return nomes


def _norm(nome):
    return re.sub(r"\s+", "", (nome or "").lower())


def _identidade(meta):
    """Chave que agrupa snapshots do mesmo equipamento."""
    host = _norm(meta.get("host"))
    if host in NOMES_GENERICOS or re.fullmatch(r"[\d.:_]+", host) or \
            host == _norm(meta.get("ip")):
        return ("ip", host, meta.get("ip", ""))
    return ("host", meta.get("platform_key", ""), host)


# ---------------------------------------------------------------------------
# Endereçamento por interface (enlaces L3)
# ---------------------------------------------------------------------------
def _interface_ip(endereco, mascara=None):
    try:
        if mascara is None:
            return ipaddress.ip_interface(endereco)
        if re.fullmatch(r"\d+", mascara):
            return ipaddress.ip_interface(f"{endereco}/{mascara}")
        return ipaddress.ip_interface(f"{endereco}/{mascara}")
    except ValueError:
        return None


def enderecos_junos(texto):
    for m in re.finditer(r"(?m)^set interfaces (\S+) unit (\S+) family "
                         r"inet6? address ([0-9a-fA-F.:]+/\d+)", texto):
        ip = _interface_ip(m.group(3))
        if ip:
            yield f"{m.group(1)}.{m.group(2)}", ip


def enderecos_em_blocos(texto):
    """Huawei VRP e Cisco: 'interface X' seguido de linhas indentadas com
    ip/ipv4/ipv6 address em qualquer das formas (A M, A len, A/len)."""
    atual = None
    for linha in texto.splitlines():
        m = re.match(r"^interface\s+(\S+)", linha)
        if m:
            atual = m.group(1)
            continue
        if not linha.startswith((" ", "\t")):
            atual = None
            continue
        if not atual:
            continue
        m = re.match(r"^\s+(?:ip|ipv4|ipv6) address\s+([0-9a-fA-F.:]+)"
                     r"(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+|\d+))?\b", linha)
        if not m:
            continue
        mascara = m.group(2) or m.group(3)
        if not mascara:
            continue
        ip = _interface_ip(m.group(1), mascara)
        if ip:
            yield atual, ip


def enderecos_mikrotik(texto):
    texto = re.sub(r"\\\r?\n\s*", "", texto)
    secao = ""
    for linha in texto.splitlines():
        if linha.startswith("/"):
            secao = linha.strip()
            continue
        if secao not in ("/ip address", "/ipv6 address") or \
                not linha.startswith("add "):
            continue
        pares = dict(re.findall(r'([\w-]+)=("[^"]*"|\S+)', linha))
        if pares.get("disabled") == "yes":
            continue
        ip = _interface_ip(pares.get("address", "").strip('"'))
        if ip and pares.get("interface"):
            yield pares["interface"].strip('"'), ip


def enderecos_do_snapshot(snap):
    plataforma = snap["meta"].get("platform_key", "")
    saida = []
    for _, c in md.comandos_da_secao(snap, "config"):
        texto = c["saida"] or ""
        if plataforma == "juniper_junos":
            saida.extend(enderecos_junos(texto))
        elif plataforma == "mikrotik_routeros":
            saida.extend(enderecos_mikrotik(texto))
        elif plataforma.startswith(("huawei", "cisco")):
            saida.extend(enderecos_em_blocos(texto))
    return saida


def _ponto_a_ponto(rede):
    if rede.version == 4:
        return 29 <= rede.prefixlen <= 31
    return 112 <= rede.prefixlen <= 127


def _descricoes(snap):
    """Descrição de interface -> nome, para resolver a porta remota que o
    vizinho anuncia pela descrição (Junos com port-id-subtype padrão)."""
    mapa = {}
    for _, c in md.comandos_da_secao(snap, "optica"):
        if "description" not in c["comando"].lower() or not c["saida"]:
            continue
        linhas = c["saida"].splitlines()
        for i, linha in enumerate(linhas):
            if re.search(r"(?i)\bdescription\b", linha) and \
                    re.match(r"(?i)\s*interface", linha):
                for row in linhas[i + 1:]:
                    m = re.match(r"^(\S+)\s+\S+\s+\S+\s+(.+?)\s*$", row)
                    if m and not re.match(r"[-=]+$", m.group(1)):
                        mapa.setdefault(_norm(m.group(2)), m.group(1))
                break
    return mapa


# ---------------------------------------------------------------------------
# Grafo
# ---------------------------------------------------------------------------
def _novo_no(no_id, rotulo, coletado=False):
    return {
        "id": no_id, "rotulo": rotulo, "coletado": coletado,
        "ip": "", "ips": [], "plataforma": "", "plataforma_nome": "",
        "fabricante": "", "coletado_em": "", "arquivo": "",
        "ips_gerencia": [],
    }


def construir(pasta, caminhos=None):
    """Monta o grafo a partir do snapshot mais recente de cada equipamento."""
    caminhos = caminhos if caminhos is not None else md.listar_snapshots(pasta)
    escolhidos = md.mais_recentes(caminhos)

    # Mesmo equipamento coletado por vários endereços: fica o mais recente,
    # e os endereços vão para a lista do nó.
    grupos = {}
    for caminho, meta in escolhidos:
        grupos.setdefault(_identidade(meta), []).append((caminho, meta))
    unicos = []
    for itens in grupos.values():
        itens.sort(key=lambda cm: cm[1].get("collected_at") or "")
        caminho, meta = itens[-1]
        ips = sorted({m.get("ip", "") for _, m in itens if m.get("ip")})
        unicos.append((caminho, meta, ips))
    unicos.sort(key=lambda x: (x[1].get("host") or "", x[1].get("ip") or ""))

    nos, apelidos, leituras, sem_vizinhanca = {}, {}, [], []
    descricoes, enderecos = {}, []
    for caminho, meta, ips in unicos:
        snap = md.ler_snapshot(caminho)
        nome = meta.get("host") or meta.get("ip") or os.path.basename(caminho)
        no_id = _norm(nome)
        if no_id in nos:
            # Nome de fábrica repetido (MikroTik, HUAWEI): equipamentos
            # distintos não podem virar um nó só.
            no_id = _norm(f"{nome}@{meta.get('ip')}")
        no = _novo_no(no_id, nome, True)
        no.update({
            "ip": meta.get("ip", ""), "ips": ips,
            "plataforma": meta.get("platform_key", ""),
            "plataforma_nome": meta.get("platform_name", ""),
            "fabricante": meta.get("vendor", ""),
            "coletado_em": meta.get("collected_at", ""),
            "arquivo": os.path.basename(caminho),
        })
        nos[no_id] = no
        for n in nomes_do_host(snap):
            # Nome de fábrica não identifica: um vizinho que anuncie
            # "MikroTik" não é, por isso, este equipamento.
            if _norm(n) not in NOMES_GENERICOS:
                apelidos[_norm(n)] = no_id
        for ip in ips:
            apelidos[_norm(ip)] = no_id
        descricoes[no_id] = _descricoes(snap)
        enderecos.extend((no_id, iface, ip, no["arquivo"])
                         for iface, ip in enderecos_do_snapshot(snap))

        comandos = list(md.comandos_da_secao(snap, "vizinhanca"))
        # A configuração diz se o LLDP está configurado (Junos), mesmo em
        # snapshots sem a seção Vizinhança ou de versões que não coletavam
        # 'show lldp'.
        config = [(c["comando"], c["saida"])
                  for _, c in md.comandos_da_secao(snap, "config")
                  if c["saida"]]
        if not comandos:
            motivo = ("seção Vizinhança não coletada (use o modo Vizinhança "
                      "L2, Mapa da rede ou Extração total)")
            ativar = {"comandos": [], "nota": ""}
            if config and diagnosticar_vizinhanca(
                    no["plataforma"], config)["estado"] == "desligado":
                motivo += "; a configuração não tem LLDP"
                ativar = COMO_ATIVAR.get(no["plataforma"], ativar)
            sem_vizinhanca.append({
                "host": nome, "id": no_id, "plataforma": no["plataforma"],
                "estado": "nao_coletada", "motivo": motivo,
                "como_ativar": ativar})
            continue
        # A forma detalhada traz nome completo e endereço de gerência; a tabela
        # resumida trunca nomes ("Roteador-Borda-Ce...") e abrevia portas.
        # Havendo as duas, vale a detalhada.
        detalhadas, resumidas = [], []
        for _, c in comandos:
            if not c["saida"]:
                continue
            vs = vizinhos_do_comando(c["comando"], c["saida"])
            fonte = f"{no['arquivo']} · {c['comando']}"
            destino = resumidas if _eh_tabela(c["comando"]) else detalhadas
            destino.extend((no_id, v, fonte) for v in vs)
        escolhidas = detalhadas or resumidas
        leituras.extend(escolhidas)
        if not escolhidas:
            diag = diagnosticar_vizinhanca(
                no["plataforma"],
                [(c["comando"], c["saida"] or c["retorno"]) for _, c in comandos]
                + config)
            sem_vizinhanca.append({
                "host": nome, "id": no_id, "plataforma": no["plataforma"],
                "estado": diag["estado"], "motivo": diag["motivo"],
                "como_ativar": diag["como_ativar"]})

    diretos = {}
    for origem_id, v, fonte in leituras:
        if v["dispositivo"].strip() in ("-", "--", "N/A"):
            v["dispositivo"] = ""
        rotulo = v["dispositivo"] or (f"sem nome ({v['porta_remota']})"
                                      if v["porta_remota"] else "sem nome")
        destino_id = apelidos.get(_norm(v["dispositivo"])) or \
            apelidos.get(_norm(v["dispositivo"]).split(".", 1)[0]) or \
            apelidos.get(_norm(v["ip_gerencia"])) or _norm(rotulo)
        if destino_id not in nos:
            nos[destino_id] = _novo_no(destino_id, rotulo)
        if v["ip_gerencia"] and \
                v["ip_gerencia"] not in nos[destino_id]["ips_gerencia"]:
            nos[destino_id]["ips_gerencia"].append(v["ip_gerencia"])

        # Um mesmo vizinho visto por várias interfaces lógicas na mesma porta
        # física (MikroTik anuncia LLDP também pelas VLANs) é um enlace só.
        chave = (origem_id, porta_canonica(v["porta_local"]), destino_id)
        if chave not in diretos:
            diretos[chave] = {
                "a": origem_id, "porta_a": v["porta_local"],
                "b": destino_id, "porta_b": v["porta_remota"],
                "portas_b": [], "tipo": "lldp", "rede": "",
                "confirmado": False, "origem": [],
            }
        e = diretos[chave]
        for p in [v["porta_remota"]] + v.get("portas_alt", []):
            if p and p not in e["portas_b"]:
                e["portas_b"].append(p)
        if fonte not in e["origem"]:
            e["origem"].append(fonte)

    enlaces = _confirmar(diretos, descricoes)
    enlaces.extend(_enlaces_l3(enderecos))

    return {
        "documento": "netsnap_topologia",
        "versao": __version__,
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "pasta": os.path.abspath(pasta),
        "nos": sorted(nos.values(), key=lambda n: (not n["coletado"],
                                                    n["rotulo"].lower())),
        "enlaces": enlaces,
        "sem_vizinhanca": sem_vizinhanca,
    }


def _confirmar(diretos, descricoes):
    """Funde os dois sentidos de um enlace quando ambos foram coletados.

    A porta remota anunciada pode vir abreviada, pela descrição da interface
    ou pelo índice SNMP. Confirma-se por nome (normalizado), pela descrição
    resolvida no snapshot do vizinho, ou — quando o par tem um único enlace
    em cada sentido — pelo próprio par."""
    def conhecidas(no_id, anunciadas):
        v = set()
        for p in anunciadas:
            v |= _variantes_porta(p)
            real = descricoes.get(no_id, {}).get(_norm(p))
            if real:
                v.add(porta_canonica(real))
        return v

    por_par = {}
    for chave, e in diretos.items():
        por_par.setdefault((e["a"], e["b"]), []).append(chave)

    enlaces, usados = [], set()
    for chave, e in diretos.items():
        if chave in usados:
            continue
        usados.add(chave)
        reversos = [k for k in por_par.get((e["b"], e["a"]), [])
                    if k not in usados]
        par = None
        for k in reversos:
            r = diretos[k]
            if porta_canonica(e["porta_a"]) in conhecidas(e["a"], r["portas_b"]) \
                    and porta_canonica(r["porta_a"]) in \
                    conhecidas(e["b"], e["portas_b"]):
                par = k
                break
        if par is None and len(reversos) == 1 and \
                len(por_par.get((e["a"], e["b"]), [])) == 1:
            par = reversos[0]
        if par is not None:
            r = diretos[par]
            usados.add(par)
            e["confirmado"] = True
            e["porta_b"] = r["porta_a"]
            e["origem"] += [o for o in r["origem"] if o not in e["origem"]]
        enlaces.append(e)
    return enlaces


def _enlaces_l3(enderecos):
    """Sub-redes ponto a ponto com endereço em dois equipamentos coletados."""
    por_rede = {}
    for no_id, iface, ip, arquivo in enderecos:
        if not _ponto_a_ponto(ip.network) or \
                iface.lower().startswith(("lo", "loopback")):
            continue
        por_rede.setdefault(ip.network, []).append((no_id, iface, ip, arquivo))
    agrupados = {}
    for rede, membros in por_rede.items():
        por_no = {}
        for m in membros:
            por_no.setdefault(m[0], m)
        if len(por_no) != 2:
            continue
        (a, ia, _, fa), (b, ib, _, fb) = sorted(por_no.values())
        # IPv4 e IPv6 na mesma interface são o mesmo enlace.
        chave = (a, ia, b, ib)
        if chave not in agrupados:
            agrupados[chave] = {
                "a": a, "porta_a": ia, "b": b, "porta_b": ib,
                "portas_b": [ib], "tipo": "l3", "rede": str(rede),
                "confirmado": True,
                "origem": [f"{fa} · configuração", f"{fb} · configuração"],
            }
        elif rede.version == 4:
            agrupados[chave]["rede"] = str(rede)
    return list(agrupados.values())


def salvar(grafo, pasta):
    caminho = os.path.join(
        pasta, f"_topologia_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(grafo, f, ensure_ascii=False, indent=2)
    return caminho


def main():
    args = sys.argv[1:]
    opcoes_com_valor = {"--saida", "--desenho"}
    posicionais, i = [], 0
    while i < len(args):
        if args[i] in opcoes_com_valor:
            i += 2
            continue
        if not args[i].startswith("--"):
            posicionais.append(args[i])
        i += 1
    pasta = posicionais[0] if posicionais else "snapshots"
    if not os.path.isdir(pasta):
        alt = os.path.join(os.path.expanduser("~"), "netsnap_snapshots")
        pasta = alt if os.path.isdir(alt) else pasta
    grafo = construir(pasta)

    def valor(opcao):
        if opcao in args and args.index(opcao) + 1 < len(args):
            return args[args.index(opcao) + 1]
        return None

    destino = valor("--saida")
    if destino:
        with open(destino, "w", encoding="utf-8") as f:
            json.dump(grafo, f, ensure_ascii=False, indent=2)
    else:
        destino = salvar(grafo, pasta)
    coletados = sum(1 for n in grafo["nos"] if n["coletado"])
    confirmados = sum(1 for e in grafo["enlaces"] if e["confirmado"])
    print(f"{coletados} equipamento(s) coletado(s), "
          f"{len(grafo['nos']) - coletados} vizinho(s) não coletado(s), "
          f"{len(grafo['enlaces'])} enlace(s), {confirmados} confirmado(s)")
    print(f"Topologia: {destino}")
    for s in grafo["sem_vizinhanca"]:
        print(f"  sem vizinhança: {s['host']} — {s['motivo']}")
        dica = texto_como_ativar(s["plataforma"]) \
            if s["como_ativar"]["comandos"] or s["como_ativar"]["nota"] else ""
        if dica:
            print(f"    {dica}")

    desenho = valor("--desenho")
    if desenho:
        import netsnap_desenho as nd
        cena = nd.montar_cena(grafo, incluir_um_lado="--todos" in args)
        if desenho.lower().endswith(".svg"):
            with open(desenho, "w", encoding="utf-8") as f:
                f.write(nd.para_svg(cena))
        else:
            with open(desenho, "wb") as f:
                f.write(nd.para_pdf(cena))
        print(f"Desenho: {desenho}")


if __name__ == "__main__":
    main()
