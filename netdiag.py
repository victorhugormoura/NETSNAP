#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netdiag — Diagnóstico da extração do netsnap (somente leitura)

Executa, um a um, todos os comandos que o netsnap usaria em um equipamento e
mede o resultado de cada um: tempo, volume de retorno e classificação
(funcionou, não suportado pela plataforma, vazio, erro, paginação presa).
Gera um relatório Markdown e um JSON destinados a diagnóstico — inclusive
para envio ao mantenedor do projeto, a fim de corrigir ou ampliar os perfis.

Não duplica listas de comandos: importa os perfis diretamente do netsnap.py,
que permanece a única fonte de verdade.

Uso:
    python3 netdiag.py 10.0.0.1
    python3 netdiag.py 10.0.0.1 10.0.0.2 --porta 2222
    python3 netdiag.py 10.0.0.1 --secao optica
    python3 netdiag.py 10.0.0.1 --plataforma fiberhome
    python3 netdiag.py 10.0.0.1 --anonimizar

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.0.1"

import os
import re
import sys
import json
import time
import getpass
import argparse
import platform as plataforma_host
from datetime import datetime

try:
    import netsnap as ns
except ImportError:
    print("[ERRO] netsnap.py não encontrado. Coloque netdiag.py na mesma "
          "pasta do netsnap.py e execute novamente.")
    sys.exit(1)

try:
    from netmiko import ConnectHandler
    from netmiko.ssh_autodetect import SSHDetect
    from netmiko.exceptions import NetmikoAuthenticationException
    import netmiko
except ImportError:
    print("[ERRO] Netmiko não instalado: pip install netmiko")
    sys.exit(1)

PASTA_SAIDA = "diagnosticos"

# Classificação do retorno de cada comando
OK = "OK"
VAZIO = "VAZIO"
NAO_SUPORTADO = "NAO_SUPORTADO"
ERRO = "ERRO"
PAGINACAO = "PAGINACAO"

DESCRICAO_STATUS = {
    OK: "retornou conteúdo utilizável",
    VAZIO: "executou sem erro, porém sem retorno",
    NAO_SUPORTADO: "comando recusado pela plataforma/firmware",
    ERRO: "exceção durante a execução (timeout, sessão perdida)",
    PAGINACAO: "retorno preso em paginação (--More--); ajustar 'prep' do perfil",
}

# Marcadores de paginação não desativada
PADRAO_PAGINACAO = re.compile(
    r"(?i)(---- more ----|--more--|<space>|press any key to continue|"
    r"\bmore:\s*<space>)"
)
LIMITE_LENTO = 30.0        # segundos
LINHAS_AMOSTRA = 12        # linhas de amostra por comando com problema


def preparar_ambiente() -> str:
    """Cria a pasta de saída sem exigir privilégios elevados."""
    global PASTA_SAIDA
    candidatos = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnosticos"),
        os.path.join(os.path.expanduser("~"), "netdiag_diagnosticos"),
    ]
    for pasta in candidatos:
        try:
            os.makedirs(pasta, exist_ok=True)
            teste = os.path.join(pasta, ".wtest")
            with open(teste, "w") as f:
                f.write("ok")
            os.remove(teste)
            PASTA_SAIDA = pasta
            return pasta
        except (PermissionError, OSError):
            continue
    print("[ERRO] Sem permissão de escrita em nenhuma pasta candidata.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Anonimização opcional
#
# Preserva a estrutura do dado (um mesmo IP recebe sempre o mesmo substituto),
# de modo que o relatório continue analisável sem expor a rede real.
# ---------------------------------------------------------------------------
class Anonimizador:
    RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
                        r"|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b")
    RE_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")

    def __init__(self, ativo: bool):
        self.ativo = ativo
        self._ip, self._mac, self._v6, self._host = {}, {}, {}, {}

    def _mapear(self, cache, valor, modelo):
        if valor not in cache:
            cache[valor] = modelo.format(len(cache) + 1)
        return cache[valor]

    def texto(self, txt: str) -> str:
        if not self.ativo or not txt:
            return txt
        txt = self.RE_MAC.sub(
            lambda m: self._mapear(self._mac, m.group(0), "aa:bb:cc:00:00:{:02d}"), txt)
        txt = self.RE_IPV6.sub(
            lambda m: self._mapear(self._v6, m.group(0), "2001:db8::{}"), txt)
        txt = self.RE_IPV4.sub(self._sub_ipv4, txt)
        for real, falso in self._host.items():
            txt = re.sub(re.escape(real), falso, txt, flags=re.I)
        return txt

    def _sub_ipv4(self, m):
        ip = m.group(0)
        # Preserva endereços que não identificam a rede do operador
        if ip.startswith(("127.", "0.0.0.0", "255.255.255")):
            return ip
        return self._mapear(self._ip, ip, "198.51.100.{}")

    def host(self, nome: str) -> str:
        if not self.ativo or not nome:
            return nome
        return self._mapear(self._host, nome, "EQUIPAMENTO-{}")


# ---------------------------------------------------------------------------
# Detecção instrumentada
# ---------------------------------------------------------------------------
def detectar_detalhado(ip, usuario, senha, porta, forcado=None):
    """Reproduz a detecção do netsnap registrando cada etapa."""
    etapas = []
    inicio = time.perf_counter()
    banner = ns.ler_banner(ip, porta)
    etapas.append({
        "etapa": "banner SSH",
        "resultado": banner or "sem resposta TCP",
        "segundos": round(time.perf_counter() - inicio, 2),
    })
    if banner is None:
        return None, etapas

    if forcado:
        etapas.append({"etapa": "plataforma forçada por parâmetro",
                       "resultado": forcado, "segundos": 0.0})
        return forcado, etapas

    # Mesmo caminho do netsnap: o banner sugere candidatos, que são
    # confirmados por um comando antes de recorrer ao SSHDetect.
    candidatos, confianca = ns.plataforma_por_banner(banner)
    if candidatos:
        etapas.append({
            "etapa": "candidatos pelo banner",
            "resultado": f"{', '.join(candidatos)} (confiança {confianca})",
            "segundos": 0.0,
        })
        for cand in candidatos:
            t0 = time.perf_counter()
            if confianca == "alta":
                confirmado = True
            else:
                confirmado = ns.confirmar_plataforma(ip, usuario, senha,
                                                     porta, cand)
            etapas.append({
                "etapa": f"confirmação de {cand}",
                "resultado": "confirmado" if confirmado else "não confere",
                "segundos": round(time.perf_counter() - t0, 2),
            })
            if confirmado:
                if cand == "huawei":
                    t1 = time.perf_counter()
                    cand = ns.classificar_huawei(ip, usuario, senha, porta)
                    etapas.append({
                        "etapa": "sonda de família Huawei",
                        "resultado": f"{cand} — {ns.PERFIS[cand]['nome']}",
                        "segundos": round(time.perf_counter() - t1, 2),
                    })
                return cand, etapas

    bruto, erro = None, None
    t0 = time.perf_counter()
    try:
        guesser = SSHDetect(device_type="autodetect", host=ip, username=usuario,
                            password=senha, port=porta, timeout=20,
                            conn_timeout=15)
        bruto = guesser.autodetect()
    except NetmikoAuthenticationException:
        etapas.append({"etapa": "SSHDetect", "resultado": "falha de autenticação",
                       "segundos": round(time.perf_counter() - t0, 2)})
        raise
    except Exception as e:
        erro = f"{type(e).__name__}: {e}"
    etapas.append({
        "etapa": "SSHDetect (autodetect do Netmiko)",
        "resultado": bruto or erro or "não identificou",
        "segundos": round(time.perf_counter() - t0, 2),
    })

    detectado = bruto if bruto in ns.PERFIS else None
    if bruto and detectado is None:
        alias = {"cisco_xe": "cisco_ios", "huawei_vrpv8": "huawei"}
        detectado = alias.get(bruto)
        etapas.append({
            "etapa": "mapeamento de alias",
            "resultado": f"{bruto} -> {detectado or 'sem equivalente no netsnap'}",
            "segundos": 0.0,
        })

    if detectado == "huawei":
        t0 = time.perf_counter()
        familia = ns.classificar_huawei(ip, usuario, senha, porta)
        etapas.append({
            "etapa": "sonda de família Huawei (display version)",
            "resultado": f"{familia} — {ns.PERFIS[familia]['nome']}",
            "segundos": round(time.perf_counter() - t0, 2),
        })
        detectado = familia

    if detectado is None:
        t0 = time.perf_counter()
        linux = ns.eh_linux(ip, usuario, senha, porta)
        etapas.append({
            "etapa": "sonda Linux (uname -s)",
            "resultado": "é Linux" if linux else "não é Linux",
            "segundos": round(time.perf_counter() - t0, 2),
        })
        if linux:
            detectado = "linux"

    return detectado, etapas


# ---------------------------------------------------------------------------
# Execução instrumentada de comandos
# ---------------------------------------------------------------------------
def classificar(saida, excecao):
    if excecao:
        return ERRO
    texto = ns.PADRAO_ANSI.sub("", saida or "")
    if PADRAO_PAGINACAO.search(texto):
        return PAGINACAO
    if not texto.strip():
        return VAZIO
    if ns.sem_saida_util(texto):
        return NAO_SUPORTADO
    return OK


def executar(conn, cmd, usa_timing, timeout):
    t0 = time.perf_counter()
    saida, excecao = "", None
    try:
        if usa_timing:
            saida = conn.send_command_timing(cmd, read_timeout=timeout, last_read=3)
        else:
            saida = conn.send_command(cmd, read_timeout=timeout)
    except Exception as e:
        excecao = f"{type(e).__name__}: {e}"
    dur = time.perf_counter() - t0
    return {
        "comando": cmd,
        "segundos": round(dur, 2),
        "bytes": len(saida or ""),
        "linhas": len((saida or "").splitlines()),
        "status": classificar(saida, excecao),
        "excecao": excecao,
        "lento": dur > LIMITE_LENTO,
        "_saida": saida or "",
    }


def diagnosticar_host(ip, porta, usuario, senha, secoes, forcado, timeout, anon):
    """Executa o diagnóstico completo de um equipamento."""
    rel = {
        "ip": ip, "porta": porta, "hostname": None, "plataforma": None,
        "plataforma_nome": None, "fabricante": None,
        "deteccao": [], "erro_fatal": None, "aplicacoes": [],
        "sudo": False, "contexto_usado": False,
        "secoes": {}, "modulos": {}, "segundos_total": 0.0,
    }
    t_inicio = time.perf_counter()

    try:
        tipo, etapas = detectar_detalhado(ip, usuario, senha, porta, forcado)
        rel["deteccao"] = etapas
    except NetmikoAuthenticationException:
        rel["erro_fatal"] = "autenticação recusada (usuário/senha)"
        rel["segundos_total"] = round(time.perf_counter() - t_inicio, 2)
        return rel
    except Exception as e:
        rel["erro_fatal"] = f"{type(e).__name__}: {e}"
        rel["segundos_total"] = round(time.perf_counter() - t_inicio, 2)
        return rel

    if tipo is None:
        rel["erro_fatal"] = ("plataforma não identificada — use --plataforma "
                             "para forçar e diagnosticar mesmo assim")
        rel["segundos_total"] = round(time.perf_counter() - t_inicio, 2)
        return rel

    perfil = ns.PERFIS[tipo]
    rel["plataforma"] = tipo
    rel["plataforma_nome"] = perfil["nome"]
    rel["fabricante"] = perfil.get("fabricante", "")
    usa_timing = perfil.get("timing", False)

    dispositivo = {
        "device_type": perfil.get("driver", tipo), "host": ip,
        "username": usuario, "password": senha, "port": porta,
        "timeout": 45, "conn_timeout": 15,
    }

    try:
        with ConnectHandler(**dispositivo) as conn:
            hostname = conn.find_prompt().strip("<>[]#>$ ").replace("/", "_") or ip
            hostname = hostname.split("@")[-1]

            # Comandos preparatórios (paginação/contexto)
            preps = []
            for cmd in perfil.get("prep", []):
                r = executar(conn, cmd, True, 20)
                if r["_saida"] and re.search(r"(?i)password|senha",
                                             r["_saida"][-120:]):
                    r2 = executar(conn, senha, True, 20)
                    r["comando"] = f"{cmd} (+ senha de contexto)"
                    r["_saida"] += r2["_saida"]
                rel["contexto_usado"] = True
                preps.append(r)
            if preps:
                rel["secoes"]["prep (paginação/contexto)"] = preps

            prefixo_sudo = ""
            if tipo == "linux":
                try:
                    h = conn.send_command("hostname", read_timeout=15).strip()
                    if h:
                        hostname = h.splitlines()[-1].strip()
                except Exception:
                    pass
                try:
                    r = conn.send_command(
                        "sudo -n true 2>/dev/null && echo SUDO_OK", read_timeout=20)
                    rel["sudo"] = "SUDO_OK" in (r or "")
                    if rel["sudo"]:
                        prefixo_sudo = "sudo -n "
                except Exception:
                    pass
                for chave, app in ns.APPS_LINUX.items():
                    cmd = app["deteccao"].replace("{S}", prefixo_sudo)
                    try:
                        s = conn.send_command(cmd, read_timeout=25)
                    except Exception:
                        continue
                    if "PRESENTE" in (s or ""):
                        rel["aplicacoes"].append(chave)

            rel["hostname"] = anon.host(ns.nome_seguro(hostname) or ip)

            # Seções da plataforma
            for secao in secoes:
                comandos = [c.replace("{S}", prefixo_sudo)
                            for c in perfil.get(secao, [])]
                if not comandos:
                    continue
                print(f"    [{secao}] {len(comandos)} comando(s) ...")
                rel["secoes"][ns.TITULOS[secao]] = [
                    executar(conn, c, usa_timing, timeout) for c in comandos
                ]

            # Módulos de aplicação (Linux)
            for chave in rel["aplicacoes"]:
                app = ns.APPS_LINUX[chave]
                bloco = {}
                for secao in secoes:
                    comandos = [c.replace("{S}", prefixo_sudo)
                                for c in app.get(secao, [])]
                    if not comandos:
                        continue
                    print(f"    [{chave}/{secao}] {len(comandos)} comando(s) ...")
                    bloco[ns.TITULOS[secao]] = [
                        executar(conn, c, False, timeout) for c in comandos
                    ]
                extra = app.get("extra")
                if extra and set(secoes) & {"config", "basico", "inventario"}:
                    comandos = [c.replace("{S}", prefixo_sudo)
                                for c in extra["comandos"]]
                    print(f"    [{chave}/extra] {len(comandos)} comando(s) ...")
                    bloco[extra["titulo"]] = [
                        executar(conn, c, False, timeout) for c in comandos
                    ]
                rel["modulos"][app["nome"]] = bloco

            for cmd in perfil.get("sair", []):
                try:
                    conn.send_command_timing(cmd, read_timeout=10)
                except Exception:
                    pass

    except Exception as e:
        rel["erro_fatal"] = f"{type(e).__name__}: {e}"

    rel["segundos_total"] = round(time.perf_counter() - t_inicio, 2)
    return rel


# ---------------------------------------------------------------------------
# Extração de versão e licença a partir do que foi coletado
# ---------------------------------------------------------------------------
PADRAO_VERSAO = [
    (r"(?im)^\s*Junos:\s*([0-9][\w.\-]+)", "Junos"),
    (r"(?i)\b(V\d{3}R\d{3}C\d{2}(?:SPC\d+)?)", "Huawei VRP/SmartAX"),
    (r"(?i)Cisco IOS XE Software,? Version\s*([0-9][\w.()\-]*)", "IOS-XE"),
    (r"(?i)Cisco IOS XR Software,?.*?Version\s*([0-9][\w.\-]*)", "IOS-XR"),
    (r"(?im)^\s*(?:system|NXOS):\s*version\s*([0-9][\w.()\-]*)", "NX-OS"),
    (r"(?im)^\s*version:\s*([0-9][\w.\-]*)", "RouterOS"),
    (r"(?i)Linux\s+\S+\s+([0-9]+\.[0-9]+\.[0-9]+)", "Kernel Linux"),
]
PADRAO_VERSAO_LIVRE = re.compile(
    r"(?im)^.*\b(version|versao|versão|firmware|release|software|"
    r"build|patch|image)\b.*$"
)
PADRAO_LICENCA = re.compile(
    r"(?im)^.*(licen[cs]e|entitlement|serial\s*number|esn|udi|activation|"
    r"subscription|expir).*$"
)


def extrair_indicadores(rel):
    """Procura versão e menções de licença no que foi efetivamente coletado."""
    texto = []
    for bloco in list(rel["secoes"].values()):
        for r in bloco:
            texto.append(r["_saida"])
    for mod in rel["modulos"].values():
        for bloco in mod.values():
            for r in bloco:
                texto.append(r["_saida"])
    tudo = "\n".join(texto)

    versoes = []
    for padrao, rotulo in PADRAO_VERSAO:
        m = re.search(padrao, tudo)
        if m:
            versoes.append({"rotulo": rotulo, "versao": m.group(1)})

    # Sem padrão conhecido (plataformas regionais, firmwares novos), as linhas
    # que mencionam versão são justamente o insumo para criar o padrão.
    candidatos = []
    if not versoes:
        vistas = set()
        for m in PADRAO_VERSAO_LIVRE.finditer(tudo):
            linha = " ".join(m.group(0).split())[:140]
            if linha and linha.lower() not in vistas:
                vistas.add(linha.lower())
                candidatos.append(linha)
            if len(candidatos) >= 15:
                break
    licencas = []
    vistos = set()
    for m in PADRAO_LICENCA.finditer(tudo):
        linha = " ".join(m.group(0).split())[:160]
        if linha and linha.lower() not in vistos:
            vistos.add(linha.lower())
            licencas.append(linha)
        if len(licencas) >= 25:
            break
    return versoes, licencas, candidatos


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
def resumir(rel):
    """Contagem por status considerando plataforma e módulos."""
    cont = {OK: 0, VAZIO: 0, NAO_SUPORTADO: 0, ERRO: 0, PAGINACAO: 0}
    lentos, total = [], 0
    blocos = [(t, b) for t, b in rel["secoes"].items()]
    for mod, secs in rel["modulos"].items():
        blocos += [(f"{mod} — {t}", b) for t, b in secs.items()]
    for titulo, bloco in blocos:
        for r in bloco:
            cont[r["status"]] = cont.get(r["status"], 0) + 1
            total += 1
            if r["lento"]:
                lentos.append((titulo, r))
    return cont, total, lentos, blocos


def gerar_relatorio(relatorios, args, anon, pasta):
    agora = datetime.now()
    md = ["---",
          f"netdiag_version: {json.dumps(__version__)}",
          f"netsnap_version: {json.dumps(ns.__version__)}",
          f"document_type: {json.dumps('extraction_diagnostic')}",
          f"generated_at: {json.dumps(agora.isoformat(timespec='seconds'))}",
          f"hosts: {len(relatorios)}",
          f"anonymized: {json.dumps(bool(args.anonimizar))}",
          f"sensitive_data: {json.dumps('included' if args.sensivel else 'redacted')}",
          "---\n",
          f"# Diagnóstico de extração — {agora:%d/%m/%Y %H:%M}\n"]

    md.append("Este documento registra o comportamento de **cada comando** que "
              "o netsnap executaria nos equipamentos testados. Seu propósito é "
              "diagnóstico: identificar comandos não suportados pelo firmware, "
              "retornos vazios, falhas de paginação e lentidão, de modo a "
              "corrigir ou ampliar os perfis.\n")
    md.append("> **Antes de compartilhar este arquivo:** ele contém nomes de "
              "equipamento, endereçamento e trechos de saída real"
              + (", com valores sensíveis mascarados"
                 if not args.sensivel else
                 " **e dados sensíveis não mascarados (--sensivel)**")
              + (". A anonimização de IPs, MACs e hostnames está **ativa**.\n"
                 if args.anonimizar else
                 ". Para trocar IPs, MACs e hostnames por substitutos "
                 "consistentes, execute novamente com `--anonimizar`.\n"))

    md.append("## Ambiente de execução\n")
    md.append("| Item | Valor |")
    md.append("|---|---|")
    md.append(f"| netdiag | {__version__} |")
    md.append(f"| netsnap | {ns.__version__} |")
    md.append(f"| Netmiko | {getattr(netmiko, '__version__', 'desconhecida')} |")
    md.append(f"| Python | {plataforma_host.python_version()} |")
    md.append(f"| Sistema de origem | {plataforma_host.system()} "
              f"{plataforma_host.release()} |")
    md.append(f"| Seções testadas | {', '.join(args.secoes_nomes)} |")
    md.append(f"| Timeout por comando | {args.timeout}s |\n")

    # Visão geral
    md.append("## Visão geral\n")
    md.append("| Host | Plataforma | OK | Não suportado | Vazio | Erro | "
              "Paginação | Cobertura | Tempo |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    for rel in relatorios:
        if rel["erro_fatal"] and not rel["secoes"]:
            md.append(f"| {rel['hostname'] or anon.texto(rel['ip'])} | "
                      f"_{rel['erro_fatal'][:40]}_ | — | — | — | — | — | — | "
                      f"{rel['segundos_total']}s |")
            continue
        cont, total, _, _ = resumir(rel)
        cob = f"{(cont[OK] / total * 100):.0f}%" if total else "—"
        md.append(f"| {rel['hostname']} | {rel['plataforma_nome']} | "
                  f"{cont[OK]} | {cont[NAO_SUPORTADO]} | {cont[VAZIO]} | "
                  f"{cont[ERRO]} | {cont[PAGINACAO]} | {cob} | "
                  f"{rel['segundos_total']}s |")
    md.append("")
    md.append("Legenda: " + " · ".join(
        f"**{k}** = {v}" for k, v in DESCRICAO_STATUS.items()) + "\n")

    # Detalhe por host
    for rel in relatorios:
        alvo = rel["hostname"] or anon.texto(rel["ip"])
        md.append(f"\n---\n\n## {alvo} ({anon.texto(rel['ip'])}:{rel['porta']})\n")

        md.append("### Detecção de plataforma\n")
        md.append("| Etapa | Resultado | Tempo |")
        md.append("|---|---|---|")
        for e in rel["deteccao"]:
            md.append(f"| {e['etapa']} | {anon.texto(str(e['resultado']))} | "
                      f"{e['segundos']}s |")
        md.append("")
        if rel["plataforma"]:
            md.append(f"Perfil aplicado: **{rel['plataforma_nome']}** "
                      f"(`{rel['plataforma']}`)\n")
        if rel["erro_fatal"]:
            md.append(f"> **Falha:** {anon.texto(rel['erro_fatal'])}\n")
            if not rel["secoes"]:
                continue
        if rel["plataforma"] == "linux":
            md.append(f"- sudo não interativo: "
                      f"**{'disponível' if rel['sudo'] else 'indisponível'}**"
                      + ("" if rel["sudo"] else
                         " — comandos que leem arquivos protegidos retornarão "
                         "vazio ou permissão negada") + "\n")
            if rel["aplicacoes"]:
                nomes = ", ".join(ns.APPS_LINUX[a]["nome"]
                                  for a in rel["aplicacoes"])
                md.append(f"- aplicações detectadas: {nomes}\n")
            else:
                md.append("- nenhuma aplicação conhecida detectada "
                          "(WANGuard, Zabbix, Grafana, BIND9)\n")
        if rel["contexto_usado"]:
            md.append("- contexto privilegiado acessado para leitura "
                      "(plataforma exige)\n")

        versoes, licencas, candidatos = extrair_indicadores(rel)
        md.append("### Versão e licença identificadas\n")
        if versoes:
            md.append("| Software | Versão |")
            md.append("|---|---|")
            for v in versoes:
                md.append(f"| {v['rotulo']} | `{v['versao']}` |")
            md.append("")
        else:
            md.append("_Nenhuma versão reconhecida pelos padrões conhecidos._ "
                      "As linhas abaixo foram capturadas da coleta e são o "
                      "insumo para acrescentar o padrão desta plataforma.\n")
            if candidatos:
                md.append("```text")
                for l in candidatos[:12]:
                    md.append(anon.texto(l))
                md.append("```\n")
            else:
                md.append("_Nenhuma linha mencionando versão/firmware foi "
                          "coletada — verifique a seção Inventário acima._\n")
        if licencas:
            md.append("Linhas relacionadas a licença/identificação "
                      f"({len(licencas)} encontradas, amostra):\n")
            md.append("```text")
            for l in licencas[:12]:
                md.append(anon.texto(l))
            md.append("```\n")
        else:
            md.append("_Nenhuma menção a licença encontrada na coleta._\n")

        cont, total, lentos, blocos = resumir(rel)
        md.append("### Resultado por comando\n")
        for titulo, bloco in blocos:
            md.append(f"#### {titulo}\n")
            md.append("| Status | Tempo | Linhas | Comando |")
            md.append("|---|---|---|---|")
            for r in bloco:
                cmd = r["comando"].replace("|", "\\|")
                if len(cmd) > 90:
                    cmd = cmd[:87] + "..."
                marca = " ⏱" if r["lento"] else ""
                md.append(f"| {r['status']}{marca} | {r['segundos']}s | "
                          f"{r['linhas']} | `{cmd}` |")
            md.append("")

        # Amostras apenas dos comandos problemáticos: é o que interessa
        problemas = [(t, r) for t, b in blocos for r in b
                     if r["status"] in (NAO_SUPORTADO, ERRO, PAGINACAO)]
        if problemas:
            md.append("### Amostras dos comandos com problema\n")
            md.append("Retorno bruto (truncado) dos comandos que não "
                      "funcionaram — é a informação necessária para corrigir "
                      "o perfil.\n")
            for titulo, r in problemas:
                md.append(f"**[{r['status']}]** `{r['comando'][:120]}` "
                          f"— seção *{titulo}*\n")
                if r["excecao"]:
                    md.append(f"- exceção: `{anon.texto(r['excecao'])[:200]}`\n")
                amostra = "\n".join(r["_saida"].splitlines()[:LINHAS_AMOSTRA])
                if not args.sensivel:
                    amostra = ns.sanitizar(amostra)
                amostra = anon.texto(amostra).strip()
                md.append("```text")
                md.append(amostra if amostra else "(sem retorno)")
                md.append("```\n")

        if lentos:
            md.append("### Comandos lentos\n")
            md.append(f"Acima de {LIMITE_LENTO:.0f}s. Em equipamento de "
                      "produção com muitas interfaces ou assinantes, são "
                      "candidatos a filtragem ou remoção do perfil.\n")
            md.append("| Tempo | Linhas | Comando | Seção |")
            md.append("|---|---|---|---|")
            for titulo, r in sorted(lentos, key=lambda x: -x[1]["segundos"]):
                md.append(f"| {r['segundos']}s | {r['linhas']} | "
                          f"`{r['comando'][:70]}` | {titulo} |")
            md.append("")

    md.append("\n---\n\n## Como usar este diagnóstico\n")
    md.append(
        "- **NAO_SUPORTADO** em massa numa plataforma indica perfil "
        "incompatível com a família/firmware: a amostra do retorno mostra a "
        "sintaxe que o equipamento espera.\n"
        "- **PAGINACAO** significa que o comando de desativação de paginação "
        "não funcionou nesse firmware; a correção é no campo `prep` do perfil.\n"
        "- **VAZIO** em comando válido costuma ser ausência de recurso "
        "(sem LLDP, sem óptica, sem licença) ou falta de privilégio — em "
        "Linux, verifique a linha de sudo acima.\n"
        "- **ERRO** com timeout aponta comando pesado demais para o "
        "`--timeout` usado, ou sessão derrubada pelo equipamento.\n"
        "- Comandos marcados com ⏱ dominam o tempo total da coleta.\n")

    caminho = os.path.join(pasta, f"_diagnostico_{agora:%Y%m%d_%H%M%S}.md")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return caminho


def gerar_json(relatorios, args, anon, pasta):
    """Versão estruturada, sem as saídas brutas completas."""
    agora = datetime.now()
    dados = {
        "netdiag_version": __version__,
        "netsnap_version": ns.__version__,
        "netmiko_version": getattr(netmiko, "__version__", None),
        "python_version": plataforma_host.python_version(),
        "generated_at": agora.isoformat(timespec="seconds"),
        "anonymized": bool(args.anonimizar),
        "hosts": [],
    }
    for rel in relatorios:
        cont, total, lentos, blocos = resumir(rel)
        h = {
            "host": rel["hostname"],
            "ip": anon.texto(rel["ip"]),
            "porta": rel["porta"],
            "plataforma": rel["plataforma"],
            "plataforma_nome": rel["plataforma_nome"],
            "erro_fatal": anon.texto(rel["erro_fatal"] or "") or None,
            "sudo": rel["sudo"],
            "aplicacoes": rel["aplicacoes"],
            "deteccao": [{**e, "resultado": anon.texto(str(e["resultado"]))}
                         for e in rel["deteccao"]],
            "resumo": cont,
            "total_comandos": total,
            "segundos_total": rel["segundos_total"],
            "comandos": [],
        }
        for titulo, bloco in blocos:
            for r in bloco:
                h["comandos"].append({
                    "secao": titulo,
                    "comando": r["comando"],
                    "status": r["status"],
                    "segundos": r["segundos"],
                    "linhas": r["linhas"],
                    "bytes": r["bytes"],
                    "excecao": anon.texto(r["excecao"] or "") or None,
                    "amostra": anon.texto(ns.sanitizar(
                        "\n".join(r["_saida"].splitlines()[:6])))
                    if r["status"] != OK else None,
                })
        dados["hosts"].append(h)
    caminho = os.path.join(pasta, f"_diagnostico_{agora:%Y%m%d_%H%M%S}.json")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    return caminho


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Diagnóstico da extração do netsnap (somente leitura).")
    ap.add_argument("alvos", nargs="+",
                    help="IP ou IP:porta dos equipamentos a diagnosticar")
    ap.add_argument("--porta", type=int, default=22, help="porta SSH padrão")
    ap.add_argument("--usuario", help="usuário SSH (se omitido, será solicitado)")
    ap.add_argument("--secao", action="append", choices=ns.SECOES,
                    help="testa apenas a(s) seção(ões) indicada(s); "
                         "pode repetir. Padrão: todas")
    ap.add_argument("--plataforma", choices=list(ns.PERFIS),
                    help="força o perfil, ignorando a autodetecção")
    ap.add_argument("--timeout", type=int, default=120,
                    help="timeout por comando em segundos (padrão: 120)")
    ap.add_argument("--anonimizar", action="store_true",
                    help="substitui IPs, MACs e hostnames por valores "
                         "fictícios consistentes, para compartilhamento")
    ap.add_argument("--sensivel", action="store_true",
                    help="NÃO mascara senhas e chaves nas amostras "
                         "(use apenas em diagnóstico local)")
    ap.add_argument("-v", "--version", action="version",
                    version=f"netdiag {__version__} (netsnap {ns.__version__})")
    args = ap.parse_args()

    args.secoes = args.secao or list(ns.SECOES)
    args.secoes_nomes = [ns.TITULOS[s] for s in args.secoes]

    print("=" * 68)
    print(f" netdiag v{__version__} — diagnóstico de extração "
          f"(netsnap {ns.__version__})")
    print("=" * 68)
    pasta = preparar_ambiente()
    print(f"[+] Pasta de saída: {pasta}")
    print(f"[+] Seções: {', '.join(args.secoes)}")
    if args.sensivel:
        print("[!] --sensivel ativo: senhas e chaves NÃO serão mascaradas "
              "nas amostras.")

    usuario = args.usuario or input("\nUsuário SSH: ").strip()
    senha = getpass.getpass("Senha SSH: ")

    anon = Anonimizador(args.anonimizar)
    relatorios = []
    for alvo in args.alvos:
        ip, porta = alvo, args.porta
        if ":" in alvo and alvo.rsplit(":", 1)[1].isdigit():
            ip, p = alvo.rsplit(":", 1)
            porta = int(p)
        print(f"\n[+] Diagnosticando {ip}:{porta} ...")
        rel = diagnosticar_host(ip, porta, usuario, senha, args.secoes,
                                args.plataforma, args.timeout, anon)
        if rel["erro_fatal"] and not rel["secoes"]:
            print(f"    [FALHA] {rel['erro_fatal']}")
        else:
            cont, total, _, _ = resumir(rel)
            print(f"    [OK] {rel['plataforma_nome']} — {total} comando(s): "
                  f"{cont[OK]} ok, {cont[NAO_SUPORTADO]} não suportado(s), "
                  f"{cont[VAZIO]} vazio(s), {cont[ERRO]} erro(s) "
                  f"em {rel['segundos_total']}s")
        relatorios.append(rel)

    rel_md = gerar_relatorio(relatorios, args, anon, pasta)
    rel_json = gerar_json(relatorios, args, anon, pasta)
    print("\n" + "=" * 68)
    print(f"Relatório: {rel_md}")
    print(f"JSON:      {rel_json}")
    if not args.anonimizar:
        print("\nPara compartilhar o diagnóstico, considere executar com "
              "--anonimizar\n(substitui IPs, MACs e hostnames por valores "
              "fictícios consistentes).")


if __name__ == "__main__":
    main()
