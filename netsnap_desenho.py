#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_desenho — desenho da topologia em SVG e PDF, sem dependências

Recebe o grafo do netsnap_topologia e produz uma "cena": caixas, linhas e
textos já posicionados. A mesma cena vira SVG (tela do painel e, no
navegador, PNG) ou PDF vetorial, então os dois arquivos mostram exatamente o
mesmo desenho.

O que entra no desenho:
  - por padrão, só enlaces confirmados: LLDP/CDP visto pelos dois lados e
    enlaces L3 (sub-rede ponto a ponto presente nas duas configurações);
  - com incluir_um_lado=True, também enlaces vistos por um lado só, em
    pontilhado, e os vizinhos não coletados que eles alcançam.
Vários enlaces entre o mesmo par (membros de LAG, VLANs L3) viram uma linha,
com as portas listadas nas pontas.

Layout: cada componente conectado é posicionado por majorização de tensão
(cada par de equipamentos busca a distância do menor caminho entre eles,
com o comprimento de cada ligação medido para caber os rótulos), a partir
de anéis em torno do equipamento com mais ligações. Não há sorteio: a mesma
topologia gera sempre o mesmo desenho. Depois as caixas são afastadas até
não se sobreporem e os componentes são arrumados em linhas.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.0.0"

import math
import re
import zlib
from datetime import datetime

# Larguras da Helvetica (AFM da Adobe, por 1000 unidades de corpo), códigos
# 32 a 126. Medem o texto para dimensionar caixas e centralizar no PDF; no
# SVG o navegador usa Helvetica ou Arial, de métricas equivalentes.
_LARGURAS = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333,
    278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278,
    584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
    500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944,
    667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
    278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
    278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]

# Cores de capa de fibra (TIA-598), as mesmas do painel.
COR_PLATAFORMA = {
    "juniper_junos": "#2563c9", "huawei": "#e07b1f", "huawei_ce": "#2e9a4e",
    "huawei_smartax": "#8a5a2b", "fiberhome": "#6f7c88",
    "cisco_nxos": "#f4f4f2", "cisco_ios": "#c8372d", "cisco_xr": "#23262a",
    "mikrotik_routeros": "#e2b714", "linux": "#7b4fc4",
}
TINTA = "#17212b"
SUAVE = "#5a6878"
LINHA = "#b6c0ca"
ENLACE = "#24415a"
UM_LADO = "#8d99a5"
FUNDO = "#ffffff"

ESPACO = 250          # raio entre anéis na posição inicial (px)
MARGEM = 36


def medir(texto, tamanho, negrito=False):
    total = 0
    for ch in texto:
        c = ord(ch)
        total += _LARGURAS[c - 32] if 32 <= c <= 126 else 556
    return total * tamanho / 1000 * (1.07 if negrito else 1.0)


def _curto(nome):
    """'Huawei VRP V5 (S6730/S5700/S9700)' -> 'Huawei VRP V5'."""
    return (nome or "").split(" (")[0]


def _truncar(texto, tamanho, maximo, negrito=False):
    if medir(texto, tamanho, negrito) <= maximo:
        return texto
    while texto and medir(texto + "…", tamanho, negrito) > maximo:
        texto = texto[:-1]
    return texto + "…"


# ---------------------------------------------------------------------------
# Seleção: nós e ligações (pares) que entram no desenho
# ---------------------------------------------------------------------------
def _ligacoes(grafo, incluir_um_lado):
    nos = {n["id"]: n for n in grafo["nos"]}
    pares = {}
    for e in grafo["enlaces"]:
        if not e["confirmado"] and not incluir_um_lado:
            continue
        if e["a"] not in nos or e["b"] not in nos or e["a"] == e["b"]:
            continue
        a, b = sorted((e["a"], e["b"]))
        pa, pb = (e["porta_a"], e["porta_b"]) if a == e["a"] else \
            (e["porta_b"], e["porta_a"])
        p = pares.setdefault((a, b), {"a": a, "b": b, "tipos": set(),
                                      "redes": [], "confirmado": False,
                                      "por_tipo": {}})
        tipo = e.get("tipo", "lldp")
        p["tipos"].add(tipo)
        p["confirmado"] = p["confirmado"] or e["confirmado"]
        if e.get("rede"):
            p["redes"].append(e["rede"])
        lado = p["por_tipo"].setdefault(tipo, {"a": [], "b": [], "n": 0})
        lado["n"] += 1
        for lista, porta in ((lado["a"], pa), (lado["b"], pb)):
            if porta and porta not in lista:
                lista.append(porta)
    # Par com LLDP e também L3: as portas físicas do LLDP contam a história;
    # as interfaces lógicas do L3 ficam fora das pontas.
    for p in pares.values():
        lado = p["por_tipo"].get("lldp") or p["por_tipo"].get("l3") or \
            next(iter(p["por_tipo"].values()))
        p["portas_a"], p["portas_b"], p["enlaces"] = lado["a"], lado["b"], \
            lado["n"]
    return nos, list(pares.values())


# ---------------------------------------------------------------------------
# Caixas dos equipamentos
# ---------------------------------------------------------------------------
def _caixa(no):
    if no["coletado"]:
        linhas = [(_truncar(no["rotulo"], 12.5, 230, True), 12.5, True, TINTA)]
        plat = _curto(no.get("plataforma_nome")) or "plataforma não informada"
        linhas.append((_truncar(plat, 10, 230), 10, False, SUAVE))
        ips = no.get("ips") or ([no["ip"]] if no.get("ip") else [])
        if ips:
            # Mesmo equipamento coletado por vários endereços.
            extra = f"  +{len(ips) - 1}" if len(ips) > 1 else ""
            linhas.append(((no.get("ip") or ips[0]) + extra, 10, False,
                           SUAVE))
    else:
        linhas = [(_truncar(no["rotulo"], 12, 230, True), 12, True, SUAVE),
                  ("não coletado", 10, False, SUAVE)]
        if no.get("ips_gerencia"):
            linhas.append((no["ips_gerencia"][0], 10, False, SUAVE))
    largura = max(150, max(medir(t, s, n) for t, s, n, _ in linhas) + 34)
    altura = 16 + sum(s * 1.45 for _, s, _, _ in linhas)
    return {"linhas": linhas, "w": largura, "h": altura}


# ---------------------------------------------------------------------------
# Layout por forças
# ---------------------------------------------------------------------------
def _componentes(ids, adj):
    vistos, comps = set(), []
    for i in sorted(ids):
        if i in vistos:
            continue
        pilha, comp = [i], []
        vistos.add(i)
        while pilha:
            x = pilha.pop()
            comp.append(x)
            for y in sorted(adj[x]):
                if y not in vistos:
                    vistos.add(y)
                    pilha.append(y)
        comps.append(comp)
    return comps


def _posicoes_iniciais(comp, adj):
    """Anéis por distância (BFS) a partir do nó com mais ligações; cada nó
    perto do ângulo do seu pai, o que evita cruzamentos logo de início."""
    centro = sorted(comp, key=lambda i: (-len(adj[i]), i))[0]
    nivel, pai, ordem = {centro: 0}, {centro: None}, [centro]
    for x in ordem:
        for y in sorted(adj[x], key=lambda i: (-len(adj[i]), i)):
            if y not in nivel:
                nivel[y] = nivel[x] + 1
                pai[y] = x
                ordem.append(y)
    pos, angulo = {centro: (0.0, 0.0)}, {centro: 0.0}
    maximo = max(nivel.values())
    for n in range(1, maximo + 1):
        anel = [i for i in ordem if nivel[i] == n]
        anel.sort(key=lambda i: (angulo[pai[i]], i))
        for k, i in enumerate(anel):
            a = 2 * math.pi * k / len(anel) + (0.35 * n)
            angulo[i] = a
            raio = ESPACO * n
            pos[i] = (raio * math.cos(a), raio * math.sin(a))
    return pos


def _texto_da_ligacao(p):
    """Espaço que os rótulos de uma ligação pedem ao longo da linha."""
    rotulos = [r for r in (_resumir_portas(p["portas_a"]),
                           _resumir_portas(p["portas_b"])) if r]
    if p["tipos"] == {"l3"} and p["redes"]:
        rotulos.append(p["redes"][0] + " +0")
    return max(80.0, sum(medir(r, 9) for r in rotulos) + 24 * len(rotulos))


def _comprimento_ideal(p, caixas):
    """Distância inicial entre centros: meia caixa de cada lado, na média das
    direções, mais o texto. O layout corrige depois as ligações que ficarem
    curtas na direção em que de fato saíram."""
    ca, cb = caixas[p["a"]], caixas[p["b"]]
    return (ca["w"] + cb["w"]) / 4 + (ca["h"] + cb["h"]) / 4 + \
        _texto_da_ligacao(p)


def _visivel(p, pos, caixas):
    """Comprimento da linha entre as bordas das duas caixas."""
    (ax, ay), (bx, by) = pos[p["a"]], pos[p["b"]]
    ca, cb = caixas[p["a"]], caixas[p["b"]]
    x1, y1 = _borda(ax, ay, ca["w"], ca["h"], bx, by)
    x2, y2 = _borda(bx, by, cb["w"], cb["h"], ax, ay)
    return math.hypot(x2 - x1, y2 - y1), math.hypot(bx - ax, by - ay)


def _distancias(comp, comprimento):
    """Menor caminho entre todos os pares do componente (Dijkstra)."""
    import heapq
    vizinhos = {i: [] for i in comp}
    for (a, b), c in comprimento.items():
        if a in vizinhos and b in vizinhos:
            vizinhos[a].append((b, c))
            vizinhos[b].append((a, c))
    dist = {}
    for origem in comp:
        d = {origem: 0.0}
        fila = [(0.0, origem)]
        while fila:
            du, u = heapq.heappop(fila)
            if du > d.get(u, float("inf")):
                continue
            for v, c in vizinhos[u]:
                if du + c < d.get(v, float("inf")):
                    d[v] = du + c
                    heapq.heappush(fila, (d[v], v))
        dist[origem] = d
    return dist


def _layout(comp, pares, pos, caixas):
    """Tensão, depois correção das ligações curtas para os rótulos: cada uma
    ganha o que faltou na direção em que saiu, e o layout é refeito a partir
    das posições atuais."""
    proprios = [p for p in pares if p["a"] in pos and p["b"] in pos
                and p["a"] in comp]
    comprimento = {(p["a"], p["b"]): _comprimento_ideal(p, caixas)
                   for p in proprios}
    # Em redes muito grandes, cada rodada custa segundos: duas bastam.
    for rodada in range(4 if len(comp) <= 150 else 2):
        pos = _tensao(comp, comprimento, pos, caixas,
                      200 if rodada == 0 else 60)
        faltou = False
        for p in proprios:
            visivel, centros = _visivel(p, pos, caixas)
            necessario = _texto_da_ligacao(p)
            if visivel < necessario * 0.95:
                faltou = True
                chave = (p["a"], p["b"])
                comprimento[chave] = max(comprimento[chave],
                                         centros + (necessario - visivel))
        if not faltou:
            break
    return pos


def _tensao(comp, comprimento, pos, caixas, iteracoes=200):
    """Majorização de tensão (stress majorization): cada par de equipamentos
    busca a distância do menor caminho entre eles no grafo, ponderada pelo
    inverso do quadrado. Com o comprimento de cada ligação sob medida para
    os rótulos, o desenho fica compacto sem linhas curtas demais. Depois,
    as caixas que ainda se sobrepõem são afastadas."""
    n = len(comp)
    if n > 1:
        dist = _distancias(comp, comprimento)
        if n > 60:
            iteracoes = max(30, iteracoes // (2 if n <= 150 else 3))
        for _ in range(iteracoes):
            for i in comp:
                xi, yi = pos[i]
                soma_w = soma_x = soma_y = 0.0
                for j in comp:
                    if j == i:
                        continue
                    dij = dist[i].get(j)
                    if not dij:
                        continue
                    w = 1.0 / (dij * dij)
                    xj, yj = pos[j]
                    dx, dy = xi - xj, yi - yj
                    norma = math.hypot(dx, dy) or 1e-3
                    soma_w += w
                    soma_x += w * (xj + dij * dx / norma)
                    soma_y += w * (yj + dij * dy / norma)
                if soma_w:
                    pos[i] = (soma_x / soma_w, soma_y / soma_w)
    # Caixas sobrepostas: afasta pelo eixo de menor sobreposição.
    folga_x, folga_y = 40, 34
    for _ in range(200):
        mexeu = False
        for x in range(n):
            for y in range(x + 1, n):
                a, b = comp[x], comp[y]
                dx = pos[b][0] - pos[a][0]
                dy = pos[b][1] - pos[a][1]
                ox = (caixas[a]["w"] + caixas[b]["w"]) / 2 + folga_x - abs(dx)
                oy = (caixas[a]["h"] + caixas[b]["h"]) / 2 + folga_y - abs(dy)
                if ox > 0 and oy > 0:
                    mexeu = True
                    if ox < oy:
                        s = 1 if dx >= 0 else -1
                        pos[a] = (pos[a][0] - s * ox / 2, pos[a][1])
                        pos[b] = (pos[b][0] + s * ox / 2, pos[b][1])
                    else:
                        s = 1 if dy >= 0 else -1
                        pos[a] = (pos[a][0], pos[a][1] - s * oy / 2)
                        pos[b] = (pos[b][0], pos[b][1] + s * oy / 2)
        if not mexeu:
            break
    return pos


def _arrumar(comps, pos, caixas):
    """Componentes em linhas, do maior para o menor."""
    blocos = []
    for comp in comps:
        x0 = min(pos[i][0] - caixas[i]["w"] / 2 for i in comp)
        y0 = min(pos[i][1] - caixas[i]["h"] / 2 for i in comp)
        x1 = max(pos[i][0] + caixas[i]["w"] / 2 for i in comp)
        y1 = max(pos[i][1] + caixas[i]["h"] / 2 for i in comp)
        blocos.append((comp, x0, y0, x1 - x0, y1 - y0))
    blocos.sort(key=lambda b: (-len(b[0]), -b[3] * b[4]))
    area = sum((b[3] + 80) * (b[4] + 80) for b in blocos)
    limite = max(1100.0, max(b[3] for b in blocos), math.sqrt(area) * 1.5)
    x, y, alt_linha, final = 0.0, 0.0, 0.0, {}
    for comp, x0, y0, w, h in blocos:
        if x > 0 and x + w > limite:
            x, y, alt_linha = 0.0, y + alt_linha + 70, 0.0
        for i in comp:
            final[i] = (pos[i][0] - x0 + x, pos[i][1] - y0 + y)
        x += w + 90
        alt_linha = max(alt_linha, h)
    return final


def _borda(cx, cy, w, h, tx, ty):
    """Ponto onde o segmento do centro (cx,cy) até (tx,ty) sai da caixa."""
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    fatores = []
    if dx:
        fatores.append((w / 2) / abs(dx))
    if dy:
        fatores.append((h / 2) / abs(dy))
    f = min(fatores)
    return cx + dx * f, cy + dy * f


# Formas curtas dos nomes de porta, só para o rótulo do desenho.
_CURTAS = [("XGigabitEthernet", "XGE"), ("GigabitEthernet", "GE"),
           ("TenGigabitEthernet", "Te"), ("TwentyFiveGigE", "Twe"),
           ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"),
           ("FastEthernet", "Fa"), ("Bundle-Ether", "BE"),
           ("Port-channel", "Po")]


def _porta_curta(nome):
    for longo, curto in _CURTAS:
        if nome.startswith(longo):
            return curto + nome[len(longo):]
    return nome


def _resumir_portas(portas, maximo=2):
    portas = [_porta_curta(p) for p in portas]
    if len(portas) <= maximo:
        return ", ".join(portas)
    return ", ".join(portas[:maximo]) + f" +{len(portas) - maximo}"


# ---------------------------------------------------------------------------
# Cena
# ---------------------------------------------------------------------------
def montar_cena(grafo, incluir_um_lado=False, titulo="Topologia da rede"):
    nos, pares = _ligacoes(grafo, incluir_um_lado)
    usados = sorted({p["a"] for p in pares} | {p["b"] for p in pares})
    caixas = {i: _caixa(nos[i]) for i in usados}
    adj = {i: set() for i in usados}
    for p in pares:
        adj[p["a"]].add(p["b"])
        adj[p["b"]].add(p["a"])

    itens = []
    topo = 76
    agora = datetime.now()
    confirmadas = sum(1 for p in pares if p["confirmado"])
    resumo = (f"{len(usados)} equipamentos, {confirmadas} ligações "
              f"confirmadas" + (f", {len(pares) - confirmadas} vistas por "
                                f"um lado só" if incluir_um_lado else "")
              + f" — gerado em {agora:%d/%m/%Y %H:%M}")

    if not usados:
        largura, altura = 900, 260
        itens.append(_texto(MARGEM, 44, titulo, 20, True, TINTA))
        itens.append(_texto(MARGEM, 66, f"gerado em {agora:%d/%m/%Y %H:%M}",
                            10.5, False, SUAVE))
        mensagem = ("Nenhum enlace confirmado nos snapshots." if not
                    incluir_um_lado else "Nenhum enlace nos snapshots.")
        itens.append(_texto(MARGEM, 130, mensagem, 13, True, TINTA))
        itens.append(_texto(MARGEM, 154, "Colete os equipamentos com a seção "
                            "Vizinhança L2 (LLDP/CDP) ou Configuração "
                            "(enlaces L3 ponto a ponto).", 11, False, SUAVE))
        return {"largura": largura, "altura": altura, "itens": itens,
                "titulo": titulo, "resumo": mensagem}

    pos = {}
    comps = _componentes(usados, adj)
    for comp in comps:
        p0 = _posicoes_iniciais(comp, adj)
        pos.update(_layout(comp, pares, p0, caixas))
    pos = _arrumar(comps, pos, caixas)
    # Margem para os rótulos das pontas que escapam das caixas.
    folga = 60
    ox, oy = MARGEM + folga, topo + folga
    pos = {i: (x + ox, y + oy) for i, (x, y) in pos.items()}
    largura = max(max(x + caixas[i]["w"] / 2 for i, (x, _) in pos.items())
                  + MARGEM + folga, 760)
    altura = max(y + caixas[i]["h"] / 2 for i, (_, y) in pos.items()) \
        + MARGEM + folga + 40

    itens.append(_texto(MARGEM, 40, titulo, 20, True, TINTA))
    itens.append(_texto(MARGEM, 62, resumo, 10.5, False, SUAVE))

    rotulos = []
    for p in sorted(pares, key=lambda p: (p["confirmado"], p["a"], p["b"])):
        (ax, ay), (bx, by) = pos[p["a"]], pos[p["b"]]
        ca, cb = caixas[p["a"]], caixas[p["b"]]
        x1, y1 = _borda(ax, ay, ca["w"], ca["h"], bx, by)
        x2, y2 = _borda(bx, by, cb["w"], cb["h"], ax, ay)
        so_l3 = p["tipos"] == {"l3"}
        if not p["confirmado"]:
            cor, traco, espessura = UM_LADO, [2, 3], 1.4
        else:
            cor = ENLACE
            traco = [7, 4] if so_l3 else []
            espessura = 1.6 + 0.7 * min(p["enlaces"] - 1, 4)
        itens.append({"t": "linha", "x1": x1, "y1": y1, "x2": x2, "y2": y2,
                      "cor": cor, "largura": espessura, "traco": traco})
        d = math.hypot(x2 - x1, y2 - y1) or 1
        ux, uy = (x2 - x1) / d, (y2 - y1) / d
        for (px, py), portas, sentido, no_id in (
                ((x1, y1), p["portas_a"], 1, p["a"]),
                ((x2, y2), p["portas_b"], -1, p["b"])):
            texto = _resumir_portas(portas)
            if not texto:
                continue
            # O rótulo fica inteiro fora da caixa: o centro avança, além da
            # folga, meia largura projetada na direção da linha. Em nós com
            # muitas ligações a folga cresce, para os rótulos não se
            # amontoarem junto da caixa.
            tam = 9
            meia = abs(ux) * medir(texto, tam) / 2 + abs(uy) * tam * 0.75
            folga_no = 8 + 5 * min(max(len(adj[no_id]) - 3, 0), 10)
            avanco = min(folga_no + meia, d * 0.45)
            rotulos.append((px + ux * sentido * avanco,
                            py + uy * sentido * avanco, texto, tam, SUAVE,
                            ux * sentido, uy * sentido,
                            d * 0.45 - avanco))
        if p["redes"] and (so_l3 or "lldp" not in p["tipos"]):
            redes = p["redes"][0] + (f" +{len(p['redes']) - 1}"
                                     if len(p["redes"]) > 1 else "")
            rotulos.append(((x1 + x2) / 2, (y1 + y2) / 2, redes, 8.5, SUAVE,
                            ux, uy, d * 0.1))

    for i in usados:
        x, y = pos[i]
        c, no = caixas[i], nos[i]
        x0, y0 = x - c["w"] / 2, y - c["h"] / 2
        itens.append({"t": "ret", "x": x0, "y": y0, "w": c["w"], "h": c["h"],
                      "raio": 6, "fundo": FUNDO,
                      "borda": LINHA if no["coletado"] else UM_LADO,
                      "largura": 1.2, "traco": [] if no["coletado"] else [4, 3]})
        cor = COR_PLATAFORMA.get(no.get("plataforma"))
        if cor:
            itens.append({"t": "ret", "x": x0 + 1, "y": y0 + 1, "w": 7,
                          "h": c["h"] - 2, "raio": 4, "fundo": cor,
                          "borda": LINHA if cor == "#f4f4f2" else None,
                          "largura": 0.8, "traco": []})
        ty = y0 + 8
        for texto, tam, negrito, cor_t in c["linhas"]:
            ty += tam * 1.3
            itens.append(_texto(x0 + 18, ty, texto, tam, negrito, cor_t))
            ty += tam * 0.15

    # Rótulos por cima de tudo, com fundo para não se perderem nas linhas.
    # Rótulo que cairia sobre outro desliza ao longo da própria linha, até
    # o limite de não passar do meio dela.
    ocupados, ajustados = [], []
    for x, y, texto, tam, cor, dx, dy, margem in rotulos:
        w, h = medir(texto, tam) + 6, tam * 1.45
        andado = 0.0
        while andado <= margem:
            r = (x - w / 2, y - h / 2, x + w / 2, y + h / 2)
            if not any(r[0] < o[2] and o[0] < r[2] and r[1] < o[3] and
                       o[1] < r[3] for o in ocupados):
                break
            x, y, andado = x + dx * 6, y + dy * 6, andado + 6
        ocupados.append((x - w / 2, y - h / 2, x + w / 2, y + h / 2))
        ajustados.append((x, y, texto, tam, cor))

    for x, y, texto, tam, cor in ajustados:
        w = medir(texto, tam)
        itens.append({"t": "ret", "x": x - w / 2 - 3, "y": y - tam * 0.75,
                      "w": w + 6, "h": tam * 1.45, "raio": 2, "fundo": FUNDO,
                      "borda": None, "largura": 0, "traco": [],
                      "opacidade": 0.92})
        itens.append(_texto(x, y + tam * 0.35, texto, tam, False, cor,
                            "meio"))

    # Legenda
    ly = altura - 26
    lx = MARGEM
    for rotulo, cor, traco in (("LLDP/CDP confirmado", ENLACE, []),
                               ("L3 ponto a ponto (configuração)", ENLACE,
                                [7, 4])) + ((("visto por um lado só", UM_LADO,
                                             [2, 3]),) if incluir_um_lado
                                           else ()):
        itens.append({"t": "linha", "x1": lx, "y1": ly - 3, "x2": lx + 28,
                      "y2": ly - 3, "cor": cor, "largura": 1.8,
                      "traco": traco})
        itens.append(_texto(lx + 36, ly, rotulo, 9.5, False, SUAVE))
        lx += 36 + medir(rotulo, 9.5) + 28

    return {"largura": math.ceil(largura), "altura": math.ceil(altura),
            "itens": itens, "titulo": titulo, "resumo": resumo}


def _texto(x, y, texto, tamanho, negrito, cor, ancora="inicio"):
    return {"t": "texto", "x": x, "y": y, "texto": texto, "tamanho": tamanho,
            "negrito": negrito, "cor": cor, "ancora": ancora}


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------
# Caracteres de controle não são permitidos em XML 1.0; chegam pelo LLDP
# (nome de sistema e descrição de porta são texto livre do vizinho).
_CONTROLE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _esc(t):
    t = _CONTROLE.sub("\ufffd", str(t))
    return (t.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def para_svg(cena):
    w, h = cena["largura"], cena["altura"]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
           f'viewBox="0 0 {w} {h}" font-family="Helvetica, Arial, sans-serif">',
           f"<title>{_esc(cena['titulo'])}</title>",
           f'<rect x="0" y="0" width="{w}" height="{h}" fill="{FUNDO}"/>']
    for it in cena["itens"]:
        if it["t"] == "linha":
            traco = (f' stroke-dasharray="{" ".join(map(str, it["traco"]))}"'
                     if it["traco"] else "")
            out.append(f'<line x1="{it["x1"]:.1f}" y1="{it["y1"]:.1f}" '
                       f'x2="{it["x2"]:.1f}" y2="{it["y2"]:.1f}" '
                       f'stroke="{it["cor"]}" stroke-width="{it["largura"]:.2f}"'
                       f' stroke-linecap="round"{traco}/>')
        elif it["t"] == "ret":
            borda = (f' stroke="{it["borda"]}" stroke-width="{it["largura"]}"'
                     if it.get("borda") else "")
            traco = (f' stroke-dasharray="{" ".join(map(str, it["traco"]))}"'
                     if it.get("traco") else "")
            opac = (f' fill-opacity="{it["opacidade"]}"'
                    if it.get("opacidade") else "")
            out.append(f'<rect x="{it["x"]:.1f}" y="{it["y"]:.1f}" '
                       f'width="{it["w"]:.1f}" height="{it["h"]:.1f}" '
                       f'rx="{it["raio"]}" fill="{it["fundo"]}"{opac}'
                       f'{borda}{traco}/>')
        elif it["t"] == "texto":
            ancora = {"inicio": "start", "meio": "middle",
                      "fim": "end"}[it["ancora"]]
            peso = ' font-weight="bold"' if it["negrito"] else ""
            out.append(f'<text x="{it["x"]:.1f}" y="{it["y"]:.1f}" '
                       f'font-size="{it["tamanho"]}" fill="{it["cor"]}"'
                       f'{peso} text-anchor="{ancora}">{_esc(it["texto"])}'
                       f'</text>')
    out.append("</svg>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# PDF (1.4, uma página, Helvetica padrão, conteúdo comprimido)
# ---------------------------------------------------------------------------
PT_PADRAO = 0.75   # 1 px da cena = 0,75 pt (mesma relação do CSS)
PAGINA_MAXIMA = 14400   # pt: limite de página do Acrobat (200 polegadas)


def _rgb(cor):
    cor = cor.lstrip("#")
    return " ".join(f"{int(cor[i:i + 2], 16) / 255:.3f}" for i in (0, 2, 4))


def _escapar_pdf(dados):
    return dados.replace(b"\\", b"\\\\").replace(b"(", b"\\(") \
        .replace(b")", b"\\)")


def _pdf_str(texto):
    """Texto do conteúdo da página (fontes padrão com WinAnsiEncoding)."""
    return b"(" + _escapar_pdf(texto.encode("cp1252", "replace")) + b")"


def _pdf_info(texto):
    """Texto do dicionário Info: UTF-16BE com BOM, que os leitores exibem
    corretamente nas propriedades do documento."""
    return b"(" + _escapar_pdf(b"\xfe\xff" + texto.encode("utf-16-be")) + b")"


def _ret_arredondado(x, y, w, h, r):
    """Caminho de retângulo com cantos arredondados (y para cima)."""
    r = min(r, w / 2, h / 2)
    k = 0.5523 * r
    return (f"{x + r:.2f} {y:.2f} m "
            f"{x + w - r:.2f} {y:.2f} l "
            f"{x + w - r + k:.2f} {y:.2f} {x + w:.2f} {y + r - k:.2f} "
            f"{x + w:.2f} {y + r:.2f} c "
            f"{x + w:.2f} {y + h - r:.2f} l "
            f"{x + w:.2f} {y + h - r + k:.2f} {x + w - r + k:.2f} {y + h:.2f} "
            f"{x + w - r:.2f} {y + h:.2f} c "
            f"{x + r:.2f} {y + h:.2f} l "
            f"{x + r - k:.2f} {y + h:.2f} {x:.2f} {y + h - r + k:.2f} "
            f"{x:.2f} {y + h - r:.2f} c "
            f"{x:.2f} {y + r:.2f} l "
            f"{x:.2f} {y + r - k:.2f} {x + r - k:.2f} {y:.2f} "
            f"{x + r:.2f} {y:.2f} c h")


def para_pdf(cena):
    # Redes muito grandes: a página é reduzida para caber no limite.
    PT = min(PT_PADRAO, PAGINA_MAXIMA / max(cena["largura"], cena["altura"]))
    W, H = cena["largura"] * PT, cena["altura"] * PT
    c = [f"{_rgb(FUNDO)} rg 0 0 {W:.2f} {H:.2f} re f".encode()]

    def Y(y):
        return H - y * PT

    for it in cena["itens"]:
        if it["t"] == "linha":
            traco = " ".join(f"{v * PT:.2f}" for v in it["traco"])
            c.append(f"q {_rgb(it['cor'])} RG {it['largura'] * PT:.2f} w 1 J "
                     f"[{traco}] 0 d {it['x1'] * PT:.2f} {Y(it['y1']):.2f} m "
                     f"{it['x2'] * PT:.2f} {Y(it['y2']):.2f} l S Q".encode())
        elif it["t"] == "ret":
            x, y = it["x"] * PT, Y(it["y"] + it["h"])
            w, h = it["w"] * PT, it["h"] * PT
            caminho = _ret_arredondado(x, y, w, h, it["raio"] * PT)
            partes = [f"q {_rgb(it['fundo'])} rg"]
            if it.get("opacidade"):
                partes.append("/GS1 gs")
            if it.get("borda"):
                traco = " ".join(f"{v * PT:.2f}" for v in it.get("traco") or [])
                partes.append(f"{_rgb(it['borda'])} RG "
                              f"{it['largura'] * PT:.2f} w [{traco}] 0 d")
                partes.append(f"{caminho} B Q")
            else:
                partes.append(f"{caminho} f Q")
            c.append(" ".join(partes).encode())
        elif it["t"] == "texto":
            tam = it["tamanho"] * PT
            x = it["x"] * PT
            if it["ancora"] != "inicio":
                w = medir(it["texto"], it["tamanho"], it["negrito"]) * PT
                x -= w / 2 if it["ancora"] == "meio" else w
            fonte = "/F2" if it["negrito"] else "/F1"
            c.append(f"BT {_rgb(it['cor'])} rg {fonte} {tam:.2f} Tf "
                     f"{x:.2f} {Y(it['y']):.2f} Td ".encode()
                     + _pdf_str(it["texto"]) + b" Tj ET")
    conteudo = zlib.compress(b"\n".join(c))

    agora = datetime.now().strftime("D:%Y%m%d%H%M%S")
    objetos = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W:.2f} {H:.2f}] "
         f"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> "
         f"/ExtGState << /GS1 8 0 R >> >> /Contents 6 0 R >>").encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
        b"/Encoding /WinAnsiEncoding >>",
        f"<< /Length {len(conteudo)} /Filter /FlateDecode >>\nstream\n"
        .encode() + conteudo + b"\nendstream",
        b"<< /Title " + _pdf_info(cena["titulo"]) + b" /Subject "
        + _pdf_info(cena["resumo"]) + b" /Producer (netsnap) /CreationDate ("
        + agora.encode() + b") >>",
        b"<< /Type /ExtGState /ca 0.92 >>",
    ]
    saida = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, obj in enumerate(objetos, 1):
        offsets.append(len(saida))
        saida += f"{n} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(saida)
    saida += f"xref\n0 {len(objetos) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        saida += f"{off:010d} 00000 n \n".encode()
    saida += (f"trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R "
              f"/Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n").encode()
    return bytes(saida)
