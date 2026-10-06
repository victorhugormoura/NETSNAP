#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_topologia — topologia L2 a partir dos snapshots do netsnap

Lê a seção Vizinhança (LLDP/CDP) de cada snapshot e monta um grafo de
equipamentos e enlaces em JSON. É a base do futuro módulo de desenho de
rede: o desenho consome este JSON, não os snapshots.

O que cada enlace informa:
  a, porta_a          equipamento e porta de quem anunciou a vizinhança
  b, porta_b          vizinho e porta remota, como o vizinho se identificou
  confirmado          os dois lados foram coletados e se veem mutuamente
  origem              arquivo e comando de onde o enlace foi lido

Limites:
  - Enlace sem LLDP/CDP habilitado não aparece. Ausência no grafo não
    significa ausência de cabo.
  - Nomes de porta não são normalizados entre fabricantes (Gi0/1 x
    GigabitEthernet0/1); o mesmo enlace visto pelos dois lados pode
    aparecer duas vezes quando as abreviações divergem.
  - Formato validado em coleta real: Huawei VRP ('display lldp neighbor
    brief' e 'display lldp neighbor'). Os demais seguem a sintaxe
    documentada de cada plataforma e ainda não rodaram contra saída real.

Uso direto:
    python3 netsnap_topologia.py [pasta_de_snapshots] [--saida arquivo.json]

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.0.0"

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
                vizinhos.append({
                    "porta_local": campos.get("local", ""),
                    "dispositivo": campos.get("dispositivo", ""),
                    "porta_remota": campos.get("remoto", ""),
                    "ip_gerencia": "",
                })
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
            vizinhos.append({
                "porta_local": porta,
                "dispositivo": _campo(sub, r"^System name\s*:\s*(.*)$"),
                "porta_remota": _campo(sub, r"^Port ID\s*:\s*(.*)$"),
                "ip_gerencia": _campo(sub, r"^Management address\s*:\s*"
                                           r"([0-9a-fA-F.:]+)\s*$"),
            })
    return vizinhos


def ler_cdp_detalhe(texto):
    vizinhos = []
    for bloco in re.split(r"(?m)^-{5,}\s*$|(?=^Device ID\s*:)", texto):
        disp = _campo(bloco, r"^Device ID\s*:\s*(.*)$")
        if not disp:
            continue
        vizinhos.append({
            "porta_local": _campo(bloco, r"^Interface\s*:\s*([^,]+),"),
            "dispositivo": disp,
            "porta_remota": _campo(
                bloco, r"Port ID \(outgoing port\)\s*:\s*(\S+)"),
            "ip_gerencia": _campo(
                bloco, r"^\s*(?:IP|IPv4) [Aa]ddress\s*:\s*([0-9.]+)"),
        })
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
        vizinhos.append({
            "porta_local": local,
            "dispositivo": _campo(bloco, r"^\s*System Name\s*:\s*(.*)$"),
            "porta_remota": _campo(bloco, r"^\s*Port id\s*:\s*(.*)$"),
            "ip_gerencia": _campo(
                bloco, r"^\s*(?:IP|IPv4 address|Management Address(?:es)?)"
                       r"\s*:\s*([0-9]+\.[0-9.]+)",
                r"^\s+IP\s*:\s*([0-9.]+)"),
        })
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
        vizinhos.append({
            "porta_local": pares.get("interface", ""),
            "dispositivo": pares.get("identity", ""),
            "porta_remota": pares.get("interface-name", ""),
            "ip_gerencia": pares.get("address", pares.get("address4", "")),
        })
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
        vizinhos.append({
            "porta_local": local,
            "dispositivo": _campo(bloco, r"^\s*SysName:\s*(.*)$"),
            "porta_remota": porta,
            "ip_gerencia": _campo(bloco, r"^\s*MgmtIP:\s*([0-9.]+)"),
        })
    return vizinhos


def _eh_tabela(comando):
    c = comando.lower()
    return "neighbor brief" in c or c.strip() == "show lldp neighbors"


def vizinhos_do_comando(comando, saida):
    c = comando.lower()
    if "neighbor brief" in c or c.strip() == "show lldp neighbors":
        return ler_tabela(saida)
    if c.startswith("display lldp neighbor"):
        return ler_huawei_detalhe(saida)
    if "cdp neighbors detail" in c:
        return ler_cdp_detalhe(saida)
    if "lldp neighbors detail" in c:
        return ler_lldp_detalhe_cisco(saida)
    if c.startswith("/ip neighbor"):
        return ler_mikrotik(saida)
    if c.startswith("lldpcli") or c.startswith("lldpctl"):
        return ler_lldpd(saida)
    # Formato desconhecido (FiberHome): tenta tabela, depois blocos Cisco.
    return ler_tabela(saida) or ler_lldp_detalhe_cisco(saida)


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
                    nomes.add(m.group(1).strip('"'))
    return nomes


def _norm(nome):
    return re.sub(r"\s+", "", (nome or "").lower())


def construir(pasta, caminhos=None):
    """Monta o grafo a partir do snapshot mais recente de cada host."""
    caminhos = caminhos if caminhos is not None else md.listar_snapshots(pasta)
    escolhidos = md.mais_recentes(caminhos)

    nos, apelidos, leituras, sem_vizinhanca = {}, {}, [], []
    for caminho, meta in escolhidos:
        snap = md.ler_snapshot(caminho)
        nome = meta.get("host") or meta.get("ip") or os.path.basename(caminho)
        no_id = _norm(nome)
        if no_id in nos:
            # Nome de fábrica repetido (MikroTik, HUAWEI): equipamentos
            # distintos não podem virar um nó só.
            no_id = _norm(f"{nome}@{meta.get('ip')}")
        nos[no_id] = {
            "id": no_id, "rotulo": nome, "coletado": True,
            "ip": meta.get("ip", ""),
            "plataforma": meta.get("platform_key", ""),
            "plataforma_nome": meta.get("platform_name", ""),
            "fabricante": meta.get("vendor", ""),
            "coletado_em": meta.get("collected_at", ""),
            "arquivo": os.path.basename(caminho),
            "ips_gerencia": [],
        }
        for n in nomes_do_host(snap):
            apelidos[_norm(n)] = no_id
        if meta.get("ip"):
            apelidos[_norm(meta["ip"])] = no_id

        comandos = list(md.comandos_da_secao(snap, "vizinhanca"))
        if not comandos:
            sem_vizinhanca.append({"host": nome, "motivo":
                                   "seção Vizinhança não coletada"})
            continue
        # A forma detalhada traz nome completo e endereço de gerência; a tabela
        # resumida trunca nomes ("Roteador-Borda-Ce...") e abrevia portas.
        # Havendo as duas, vale a detalhada.
        detalhadas, resumidas = [], []
        for _, c in comandos:
            if not c["saida"]:
                continue
            vs = vizinhos_do_comando(c["comando"], c["saida"])
            fonte = f"{nos[no_id]['arquivo']} · {c['comando']}"
            destino = resumidas if _eh_tabela(c["comando"]) else detalhadas
            destino.extend((no_id, v, fonte) for v in vs)
        escolhidas = detalhadas or resumidas
        leituras.extend(escolhidas)
        if not escolhidas:
            sem_vizinhanca.append({"host": nome, "motivo":
                                   "nenhum vizinho LLDP/CDP anunciado"})

    diretos = {}
    for origem_id, v, fonte in leituras:
        if v["dispositivo"].strip() in ("-", "--", "N/A"):
            v["dispositivo"] = ""
        rotulo = v["dispositivo"] or (f"sem nome ({v['porta_remota']})"
                                      if v["porta_remota"] else "sem nome")
        destino_id = apelidos.get(_norm(v["dispositivo"])) or \
            apelidos.get(_norm(v["ip_gerencia"])) or _norm(rotulo)
        if destino_id not in nos:
            nos[destino_id] = {
                "id": destino_id, "rotulo": rotulo, "coletado": False,
                "ip": "", "plataforma": "", "plataforma_nome": "",
                "fabricante": "", "coletado_em": "", "arquivo": "",
                "ips_gerencia": [],
            }
        if v["ip_gerencia"] and \
                v["ip_gerencia"] not in nos[destino_id]["ips_gerencia"]:
            nos[destino_id]["ips_gerencia"].append(v["ip_gerencia"])

        # Um mesmo vizinho visto por várias interfaces lógicas na mesma porta
        # física (MikroTik anuncia LLDP também pelas VLANs) é um enlace só.
        chave = (origem_id, _norm(v["porta_local"]), destino_id)
        if chave not in diretos:
            diretos[chave] = {
                "a": origem_id, "porta_a": v["porta_local"],
                "b": destino_id, "porta_b": v["porta_remota"],
                "portas_b": [], "confirmado": False, "origem": [],
            }
        e = diretos[chave]
        if v["porta_remota"] and v["porta_remota"] not in e["portas_b"]:
            e["portas_b"].append(v["porta_remota"])
        if fonte not in e["origem"]:
            e["origem"].append(fonte)

    # Os dois lados coletados e se vendo: funde num enlace confirmado.
    enlaces, usados = [], set()
    for chave, e in diretos.items():
        if chave in usados:
            continue
        for chave_r, r in diretos.items():
            if chave_r in usados or chave_r == chave:
                continue
            if r["a"] == e["b"] and r["b"] == e["a"] and \
                    _norm(e["porta_a"]) in [_norm(p) for p in r["portas_b"]] \
                    and _norm(r["porta_a"]) in [_norm(p) for p in e["portas_b"]]:
                e["confirmado"] = True
                e["origem"] += r["origem"]
                usados.add(chave_r)
                break
        usados.add(chave)
        enlaces.append(e)

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


def salvar(grafo, pasta):
    caminho = os.path.join(
        pasta, f"_topologia_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(grafo, f, ensure_ascii=False, indent=2)
    return caminho


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    pasta = args[0] if args else "snapshots"
    if not os.path.isdir(pasta):
        alt = os.path.join(os.path.expanduser("~"), "netsnap_snapshots")
        pasta = alt if os.path.isdir(alt) else pasta
    grafo = construir(pasta)
    if "--saida" in sys.argv:
        destino = sys.argv[sys.argv.index("--saida") + 1]
        with open(destino, "w", encoding="utf-8") as f:
            json.dump(grafo, f, ensure_ascii=False, indent=2)
    else:
        destino = salvar(grafo, pasta)
    coletados = sum(1 for n in grafo["nos"] if n["coletado"])
    print(f"{coletados} equipamento(s) coletado(s), "
          f"{len(grafo['nos']) - coletados} vizinho(s) não coletado(s), "
          f"{len(grafo['enlaces'])} enlace(s)")
    print(f"Topologia: {destino}")


if __name__ == "__main__":
    main()
