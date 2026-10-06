#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_md — leitura dos snapshots Markdown gerados pelo netsnap

Converte um snapshot em estrutura de dados (metadados, seções, comandos e
saídas), sem depender do netsnap nem do Netmiko. Usado pelo painel web e pelo
módulo de topologia.

A leitura percorre o arquivo linha a linha e ignora cabeçalhos que apareçam
dentro de blocos de código: a saída dos comandos não é escapada, e uma linha
de saída começando com "## " não pode ser tomada como nova seção.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.0.0"

import json
import os
import re

# Títulos de seção do netsnap -> chave interna. Módulos de aplicação usam
# "<Nome do módulo> — <Título>", e a chave é obtida da segunda parte.
TITULO_PARA_CHAVE = [
    ("Configuração", "config"),
    ("Logs", "logs"),
    ("Estado do equipamento", "basico"),
    ("Interfaces e ópticas", "optica"),
    ("Vizinhança L2", "vizinhanca"),
    ("Inventário", "inventario"),
]

PADRAO_COMANDO = re.compile(r"^### `(.*)`\s*$")
PADRAO_SEM_SAIDA = re.compile(r"^_\(sem saída útil — retorno: `(.*)`\)_\s*$")


def chave_da_secao(titulo: str):
    """Devolve (chave, modulo) para um título de seção, ou (None, None)."""
    modulo = None
    base = titulo
    if " — " in titulo:
        modulo, base = titulo.split(" — ", 1)
    for prefixo, chave in TITULO_PARA_CHAVE:
        if base.startswith(prefixo):
            return chave, modulo
    return None, None


def _valor(bruto):
    """Valor do front-matter: JSON, com escalares normalizados para texto."""
    try:
        v = json.loads(bruto)
    except ValueError:
        return bruto.strip('"')
    if v is None:
        return ""
    if isinstance(v, (list, bool)):
        return v
    return str(v) if not isinstance(v, str) else v


def ler_metadados(caminho: str) -> dict:
    """Lê apenas o front-matter YAML (cada valor é JSON válido)."""
    meta = {}
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        primeira = f.readline()
        if primeira.strip() != "---":
            return meta
        for linha in f:
            if linha.strip() == "---":
                break
            chave, sep, valor = linha.partition(":")
            if not sep:
                continue
            meta[chave.strip()] = _valor(valor.strip())
    return meta


def ler_snapshot(caminho: str) -> dict:
    """Lê o snapshot inteiro.

    Retorno:
      meta     dicionário do front-matter
      avisos   notas em destaque do cabeçalho (coleta incompleta, Telnet...)
      secoes   [{titulo, chave, modulo, comandos: [{comando, saida, vazio,
               retorno}]}] — saida é None quando o comando não teve saída útil
    """
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        linhas = f.read().split("\n")

    meta, i = {}, 0
    if linhas and linhas[0].strip() == "---":
        i = 1
        while i < len(linhas) and linhas[i].strip() != "---":
            chave, sep, valor = linhas[i].partition(":")
            if sep:
                meta[chave.strip()] = _valor(valor.strip())
            i += 1
        i += 1

    avisos, secoes = [], []
    atual, comando, dentro, buffer = None, None, False, []
    for linha in linhas[i:]:
        if dentro:
            if linha == "```":
                dentro = False
                if comando is not None:
                    comando["saida"] = "\n".join(buffer)
                continue
            buffer.append(linha)
            continue
        if linha.startswith("```") and comando is not None:
            dentro, buffer = True, []
            continue
        if linha.startswith("## "):
            titulo = linha[3:].strip()
            chave, modulo = chave_da_secao(titulo)
            atual = {"titulo": titulo, "chave": chave, "modulo": modulo,
                     "comandos": []}
            secoes.append(atual)
            comando = None
            continue
        m = PADRAO_COMANDO.match(linha)
        if m and atual is not None and atual["chave"]:
            comando = {"comando": m.group(1), "saida": None, "vazio": False,
                       "retorno": ""}
            atual["comandos"].append(comando)
            continue
        m = PADRAO_SEM_SAIDA.match(linha)
        if m and comando is not None:
            comando["vazio"] = True
            comando["retorno"] = m.group(1)
            continue
        if linha.startswith("> **") and (atual is None or not atual["chave"]):
            avisos.append(linha[2:].strip())

    return {
        "meta": meta,
        "avisos": avisos,
        "secoes": [s for s in secoes if s["chave"]],
    }


def comandos_da_secao(snapshot: dict, chave: str, incluir_modulos=False):
    """Itera (titulo_da_secao, comando) de uma seção."""
    for s in snapshot["secoes"]:
        if s["chave"] != chave:
            continue
        if s["modulo"] and not incluir_modulos:
            continue
        for c in s["comandos"]:
            yield s["titulo"], c


def listar_snapshots(pasta: str):
    """Snapshots de host da pasta (arquivos que não começam com '_')."""
    if not os.path.isdir(pasta):
        return []
    return sorted(
        os.path.join(pasta, n) for n in os.listdir(pasta)
        if n.endswith(".md") and not n.startswith("_"))


def mais_recentes(caminhos):
    """Mantém o snapshot mais recente de cada (host, ip)."""
    escolhidos = {}
    for c in caminhos:
        meta = ler_metadados(c)
        chave = (meta.get("host"), meta.get("ip"))
        data = meta.get("collected_at") or ""
        if chave not in escolhidos or data >= escolhidos[chave][0]:
            escolhidos[chave] = (data, c, meta)
    return [(c, meta) for _, c, meta in escolhidos.values()]
