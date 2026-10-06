#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_web — painel local do netsnap

Sobe um servidor HTTP apenas em 127.0.0.1 e abre no navegador um painel para
disparar coletas, acompanhar a execução, navegar pelos snapshots, comparar
coletas, montar o inventário do parque, rodar netcve e netdiag, agendar
coletas e gerar a topologia L2.

Garantias:
  - Escuta só em 127.0.0.1; ninguém da rede alcança o painel.
  - Toda chamada à API exige o token gerado a cada execução, que só existe
    no endereço aberto no navegador. Outra página aberta no mesmo PC não
    consegue disparar coletas.
  - Senhas de equipamento ficam apenas em memória: vão ao processo de coleta
    pela entrada padrão e nunca são gravadas. Agendamentos são salvos sem a
    senha; ela precisa ser informada de novo a cada vez que o painel inicia.
  - O painel em si só usa a biblioteca padrão. Coleta e netdiag dependem do
    Netmiko, como na linha de comando; sem ele, o painel abre em modo de
    consulta (snapshots, inventário, comparação, topologia e netcve).

Uso:
    python3 netsnap_web.py [--porta 8765] [--sem-navegador]

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "0.1.0"

import argparse
import difflib
import hmac
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import traceback
import threading
import time
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

import netsnap_md as md            # noqa: E402
import netsnap_topologia as topo   # noqa: E402

PASTA_WEB = os.path.join(AQUI, "web")
TOKEN = secrets.token_urlsafe(24)
PORTA = 8765
LIMITE_CORPO = 1024 * 1024
LIMITE_LINHAS_JOB = 20000
NOME_SEGURO = re.compile(r"[\w.\-]+")


def pasta_gravavel(nome_local, nome_home):
    """Mesma regra do netsnap: ao lado do script ou, sem permissão, na home."""
    for pasta in (os.path.join(AQUI, nome_local),
                  os.path.join(os.path.expanduser("~"), nome_home)):
        try:
            os.makedirs(pasta, exist_ok=True)
            teste = os.path.join(pasta, ".wtest")
            with open(teste, "w") as f:
                f.write("ok")
            os.remove(teste)
            return pasta
        except OSError:
            continue
    raise SystemExit(f"[ERRO] Sem permissão de escrita para {nome_local}")


PASTA_SNAPSHOTS = pasta_gravavel("snapshots", "netsnap_snapshots")
PASTA_DIAG = pasta_gravavel("diagnosticos", "netdiag_diagnosticos")
ARQUIVO_AGENDA = os.path.join(PASTA_SNAPSHOTS, "_agendamentos.json")


def capacidades():
    """O que esta máquina consegue executar."""
    info = {"coleta": False, "motivo": "", "plataformas": [], "modos": [],
            "secoes": [], "netsnap": None}
    try:
        import netsnap as ns
        info.update(
            coleta=True, netsnap=ns.__version__,
            plataformas=[{"chave": k, "nome": p["nome"]}
                         for k, p in ns.PERFIS.items()],
            modos=[{"chave": k, "nome": v[1], "secoes": v[0]}
                   for k, v in ns.MAPA_MODOS.items()],
            secoes=[{"chave": k, "nome": ns.TITULOS[k]} for k in ns.SECOES])
    except ImportError as e:
        info["motivo"] = (f"{e}. Instale com 'pip install netmiko' para "
                          "coletar e diagnosticar; a consulta funciona sem ele.")
    return info


CAPACIDADES = capacidades()


# ---------------------------------------------------------------------------
# Execução em subprocesso
#
# Cada coleta, diagnóstico ou triagem roda num processo próprio: o netsnap
# usa estado global (pasta de saída, depuração), e o processo separado isola
# execuções simultâneas, permite cancelar de fato (encerrando o processo e
# as sessões SSH dele) e mantém o servidor responsivo.
# ---------------------------------------------------------------------------
def emitir(evento):
    sys.stdout.write("@@" + json.dumps(evento, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def fmt_alvo(ip, porta):
    """IP:porta; IPv6 entre colchetes, senão a porta vira parte do endereço."""
    return f"[{ip}]:{porta}" if ":" in ip else f"{ip}:{porta}"


def ip_do_alvo(alvo):
    return alvo.rsplit(":", 1)[0].strip("[]")


def _alvos(ns, texto, porta):
    alvos, vistos = [], set()
    for linha in texto.splitlines():
        if not linha.split("#", 1)[0].strip():
            continue
        for a in ns.expandir_entrada(linha, porta):
            if a not in vistos:
                vistos.add(a)
                alvos.append(a)
    return alvos


def executor_coleta(cfg):
    import netsnap as ns
    from concurrent.futures import ThreadPoolExecutor

    pasta = ns.preparar_ambiente()
    if cfg.get("debug"):
        ns.DEBUG = True
        emitir({"tipo": "debug", "arquivo": os.path.basename(
            ns.iniciar_debug(pasta))})

    original = ns.log

    def log(ip, msg):
        original(ip, msg)
        emitir({"tipo": "host", "ip": ip, "msg": msg})
    ns.log = log

    porta = int(cfg["porta"])
    alvos = _alvos(ns, cfg["alvos"], porta)
    emitir({"tipo": "alvos", "lista": [fmt_alvo(ip, p) for ip, p in alvos]})
    if not alvos:
        emitir({"tipo": "fim", "resultados": [], "pendentes": [],
                "indice": None, "segundos": 0})
        return

    secoes, nome_modo = ns.MAPA_MODOS[cfg["modo"]]
    protocolo = cfg["protocolo"]
    usuario, senha = cfg["usuario"], cfg["senha"]
    sensivel = bool(cfg.get("sensivel"))
    instancias = max(1, min(10, int(cfg.get("instancias", 5))))
    resultados, pendentes = [], []
    t0 = time.perf_counter()

    if cfg.get("tipo"):
        # Plataforma informada pelo operador (resolução de pendentes).
        tipo = cfg["tipo"]
        trava = threading.Lock()

        def coletar(ip, p):
            log(ip, f"plataforma informada: {ns.PERFIS[tipo]['nome']}")
            try:
                arq, host = ns.coletar(ip, p, tipo, usuario, senha, secoes,
                                       nome_modo, sensivel, protocolo)
                log(ip, f"[OK] snapshot salvo: {os.path.basename(arq)}")
                with trava:
                    resultados.append((ip, True, arq, host))
            except Exception as e:
                log(ip, f"[FALHA] {e}")
                with trava:
                    resultados.append((ip, False, str(e), ip))
        with ThreadPoolExecutor(max_workers=instancias) as pool:
            for ip, p in alvos:
                pool.submit(coletar, ip, p)
    else:
        lista = alvos
        if cfg.get("varredura", "fast") == "fast":
            lista, mortos = ns.varrer_icmp(alvos)
            emitir({"tipo": "icmp", "mortos": [ip for ip, _ in mortos]})
            for ip, _ in mortos:
                resultados.append((ip, False, "sem resposta ICMP (modo fast)",
                                   ip))
        if lista:
            pendentes = ns.processar_lote(
                lista, instancias, usuario, senha, secoes, nome_modo,
                sensivel, resultados, protocolo)

    segundos = time.perf_counter() - t0
    indice = ns.escrever_indice(resultados, nome_modo, segundos)
    emitir({
        "tipo": "fim",
        "resultados": [{"ip": ip, "ok": ok,
                        "arquivo": os.path.basename(x) if ok else "",
                        "motivo": "" if ok else str(x), "host": host}
                       for ip, ok, x, host in resultados],
        "pendentes": [fmt_alvo(ip, p) for ip, p in pendentes],
        "indice": os.path.basename(indice) if indice else None,
        "segundos": round(segundos),
    })


def executor_netdiag(cfg):
    import netsnap as ns
    import netdiag as nd
    from types import SimpleNamespace

    nd.SENSIVEL = bool(cfg.get("sensivel"))
    secoes = cfg.get("secoes") or list(ns.SECOES)
    args = SimpleNamespace(
        anonimizar=bool(cfg.get("anonimizar")), sensivel=nd.SENSIVEL,
        secoes=secoes, secoes_nomes=[ns.TITULOS[s] for s in secoes],
        timeout=int(cfg.get("timeout", 120)))
    pasta = nd.preparar_ambiente()
    anon = nd.Anonimizador(args.anonimizar)
    alvos = _alvos(ns, cfg["alvos"], int(cfg["porta"]))[:20]
    emitir({"tipo": "alvos", "lista": [fmt_alvo(ip, p) for ip, p in alvos]})
    relatorios = []
    for ip, porta in alvos:
        emitir({"tipo": "host", "ip": ip, "msg": "diagnosticando ..."})
        print(f"[+] Diagnosticando {ip}:{porta} ...", flush=True)
        rel = nd.diagnosticar_host(ip, porta, cfg["usuario"], cfg["senha"],
                                   secoes, cfg.get("plataforma") or None,
                                   args.timeout, anon)
        if rel["erro_fatal"] and not rel["secoes"]:
            emitir({"tipo": "host", "ip": ip,
                    "msg": f"[FALHA] {rel['erro_fatal']}"})
        else:
            cont, total, _, _ = nd.resumir(rel)
            emitir({"tipo": "host", "ip": ip, "msg":
                    f"[OK] {rel['plataforma_nome']}: {total} comando(s), "
                    f"{cont[nd.OK]} ok, {cont[nd.NAO_SUPORTADO]} não "
                    f"suportado(s), {cont[nd.ERRO]} erro(s)"})
        relatorios.append(rel)
    rel_md = nd.gerar_relatorio(relatorios, args, anon, pasta)
    rel_js = nd.gerar_json(relatorios, args, anon, pasta)
    emitir({"tipo": "fim", "relatorio": os.path.basename(rel_md),
            "json": os.path.basename(rel_js)})


def modo_executor(tipo):
    cfg = json.loads(sys.stdin.readline())
    try:
        {"coleta": executor_coleta, "netdiag": executor_netdiag}[tipo](cfg)
    except Exception as e:
        emitir({"tipo": "erro", "mensagem": f"{type(e).__name__}: {e}"})
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Execuções (jobs)
# ---------------------------------------------------------------------------
class Job:
    def __init__(self, tipo, titulo, origem="manual"):
        self.id = secrets.token_hex(4)
        self.tipo = tipo
        self.titulo = titulo
        self.origem = origem
        self.estado = "executando"
        self.criado = datetime.now().isoformat(timespec="seconds")
        self.terminado = None
        self.linhas = []
        self.hosts = {}
        self.resultado = {}
        self.erro = ""
        self.proc = None
        self.cancelado = False
        self.config = {}
        self.trava = threading.RLock()

    def resumo(self):
        estados = {}
        with self.trava:
            hosts = list(self.hosts.values())
        for h in hosts:
            estados[h["estado"]] = estados.get(h["estado"], 0) + 1
        return {"id": self.id, "tipo": self.tipo, "titulo": self.titulo,
                "origem": self.origem, "estado": self.estado,
                "criado": self.criado, "terminado": self.terminado,
                "hosts": len(hosts), "contagem": estados}

    def detalhe(self, desde=0):
        with self.trava:
            d = self.resumo()
            d.update(config=self.config,
                     linhas=self.linhas[desde:], total_linhas=len(self.linhas),
                     lista_hosts=list(self.hosts.values()),
                     resultado=self.resultado, erro=self.erro)
        return d

    # Estado de cada host a partir das mensagens do netsnap
    def evento_host(self, ip, msg):
        h = self.hosts.setdefault(ip, {"ip": ip, "estado": "na fila",
                                       "plataforma": "", "arquivo": "",
                                       "motivo": "", "ultimo": ""})
        h["ultimo"] = msg
        if msg.startswith("[OK]"):
            h["estado"] = "ok"
            m = re.search(r"snapshot salvo: (\S+)", msg)
            h["arquivo"] = m.group(1) if m else ""
        elif msg.startswith("[FALHA]"):
            h["estado"] = "falha"
            h["motivo"] = msg[7:].strip()
        elif msg.startswith("[PENDENTE]"):
            h["estado"] = "pendente"
            h["ultimo"] = "plataforma não reconhecida; escolha o tipo abaixo"
        elif msg.startswith("identificado:"):
            h["estado"] = "identificado"
            m = re.match(r"identificado:\s*(.*?)\s*\(\d[\d.]*s", msg)
            h["plataforma"] = (m.group(1) if m else
                               msg.split(":", 1)[1]).strip()
        elif msg.startswith("plataforma informada:"):
            h["estado"] = "identificado"
            h["plataforma"] = msg.split(":", 1)[1].strip()
        elif msg.startswith(("conectando", "->")):
            h["estado"] = "coletando"
        elif msg.startswith("[ABORTADO]"):
            h["motivo"] = "sessão encerrada pelo equipamento"
        elif h["estado"] == "na fila":
            h["estado"] = "identificando"


JOBS = {}
JOBS_TRAVA = threading.Lock()


def registrar(job):
    with JOBS_TRAVA:
        JOBS[job.id] = job
        if len(JOBS) > 200:
            antigos = sorted((j for j in JOBS.values()
                              if j.estado != "executando"),
                             key=lambda j: j.criado)
            for j in antigos[:len(JOBS) - 200]:
                del JOBS[j.id]


def iniciar_processo(job, argv, entrada=None, env_extra=None):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    env.update(env_extra or {})
    try:
        job.proc = subprocess.Popen(
            argv, cwd=AQUI, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env)
    except OSError as e:
        with job.trava:
            job.estado, job.erro = "falhou", f"não foi possível iniciar: {e}"
            job.terminado = datetime.now().isoformat(timespec="seconds")
        pos_job(job)
        return

    def ler():
        for bruto in job.proc.stdout:
            linha = bruto.decode("utf-8", "replace").rstrip("\r\n")
            with job.trava:
                if linha.startswith("@@"):
                    try:
                        ev = json.loads(linha[2:])
                    except ValueError:
                        continue
                    tratar_evento(job, ev)
                elif len(job.linhas) < LIMITE_LINHAS_JOB:
                    job.linhas.append(linha)
        codigo = job.proc.wait()
        with job.trava:
            job.terminado = datetime.now().isoformat(timespec="seconds")
            if job.cancelado:
                job.estado = "cancelado"
            elif codigo == 0 and not job.erro:
                job.estado = "concluido"
            else:
                job.estado = "falhou"
                job.erro = job.erro or f"processo terminou com código {codigo}"
        pos_job(job)
    # A leitura começa antes da escrita: se o processo morrer cedo, a
    # escrita falha, mas a execução ainda é encerrada pela thread.
    threading.Thread(target=ler, daemon=True).start()
    try:
        if entrada is not None:
            job.proc.stdin.write((json.dumps(entrada) + "\n").encode("utf-8"))
        job.proc.stdin.close()
    except OSError as e:
        with job.trava:
            job.erro = f"falha ao enviar a configuração ao processo: {e}"


def tratar_evento(job, ev):
    tipo = ev.get("tipo")
    if tipo == "alvos":
        for a in ev["lista"]:
            ip = ip_do_alvo(a)
            job.hosts.setdefault(ip, {"ip": ip, "estado": "na fila",
                                      "plataforma": "", "arquivo": "",
                                      "motivo": "", "ultimo": ""})
    elif tipo == "icmp":
        for ip in ev["mortos"]:
            if ip in job.hosts:
                job.hosts[ip].update(estado="sem icmp",
                                     motivo="sem resposta ICMP (modo fast)")
    elif tipo == "host":
        job.evento_host(ev["ip"], ev["msg"])
    elif tipo == "fim":
        job.resultado.update(ev)
    elif tipo == "debug":
        job.resultado["debug"] = ev["arquivo"]
    elif tipo == "erro":
        job.erro = ev["mensagem"]


def pos_job(job):
    """Pós-processamento ao término (netcve: localizar o relatório)."""
    if job.tipo == "netcve":
        for linha in job.linhas:
            m = re.search(r"Relatório: (.+\.md)\s*$", linha)
            if m:
                job.resultado["relatorio"] = os.path.basename(m.group(1))
            m = re.search(r"CSV: (.+\.csv)\s*$", linha)
            if m:
                job.resultado["csv"] = os.path.basename(m.group(1))
    if job.origem.startswith("agendamento:"):
        AGENDA.registrar_termino(job.origem.split(":", 1)[1], job)


def nova_coleta(cfg, origem="manual"):
    if not CAPACIDADES["coleta"]:
        raise ErroAPI(409, CAPACIDADES["motivo"])
    obrig = ("alvos", "usuario", "senha", "modo", "protocolo")
    faltando = [c for c in obrig if not str(cfg.get(c, "")).strip()]
    if faltando:
        raise ErroAPI(400, "Preencha: " + ", ".join(faltando))
    if cfg["modo"] not in {m["chave"] for m in CAPACIDADES["modos"]}:
        raise ErroAPI(400, "Tipo de extração inválido")
    if cfg["protocolo"] not in ("ssh", "telnet"):
        raise ErroAPI(400, "Protocolo inválido")
    if cfg.get("tipo") and cfg["tipo"] not in {
            p["chave"] for p in CAPACIDADES["plataformas"]}:
        raise ErroAPI(400, "Plataforma inválida")
    cfg.setdefault("porta", 23 if cfg["protocolo"] == "telnet" else 22)
    try:
        cfg["porta"] = int(cfg["porta"])
        if not 1 <= cfg["porta"] <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise ErroAPI(400, "Porta inválida")
    linhas = [l for l in cfg["alvos"].splitlines()
              if l.split("#", 1)[0].strip()]
    nome_modo = next(m["nome"] for m in CAPACIDADES["modos"]
                     if m["chave"] == cfg["modo"])
    titulo = (f"Coleta · {nome_modo} · " +
              (linhas[0].strip() if len(linhas) == 1
               else f"{len(linhas)} entradas"))
    job = Job("coleta", cfg.get("titulo") or titulo, origem)
    # Configuração sem a senha: permite repetir a coleta ou resolver
    # pendentes sem redigitar tudo.
    job.config = {k: v for k, v in cfg.items() if k != "senha"}
    registrar(job)
    iniciar_processo(job, [sys.executable, "-u", os.path.abspath(__file__),
                           "--executor", "coleta"], entrada=cfg)
    return job


def novo_netdiag(cfg):
    if not CAPACIDADES["coleta"]:
        raise ErroAPI(409, CAPACIDADES["motivo"])
    for c in ("alvos", "usuario", "senha"):
        if not str(cfg.get(c, "")).strip():
            raise ErroAPI(400, f"Preencha: {c}")
    cfg["porta"] = int(cfg.get("porta") or 22)
    validas = {s["chave"] for s in CAPACIDADES["secoes"]}
    cfg["secoes"] = [s for s in cfg.get("secoes") or [] if s in validas]
    job = Job("netdiag", "Diagnóstico · " + cfg["alvos"].splitlines()[0][:40])
    job.config = {k: v for k, v in cfg.items() if k != "senha"}
    registrar(job)
    iniciar_processo(job, [sys.executable, "-u", os.path.abspath(__file__),
                           "--executor", "netdiag"], entrada=cfg)
    return job


def novo_netcve(cfg):
    argv = [sys.executable, "-u", os.path.join(AQUI, "netcve.py"),
            PASTA_SNAPSHOTS, "--csv"]
    if cfg.get("sem_rede"):
        argv.append("--sem-rede")
    if cfg.get("todos"):
        argv.append("--todos")
    if cfg.get("inseguro"):
        argv.append("--inseguro")
    try:
        limite = int(cfg.get("limite_cve") or 15)
    except ValueError:
        limite = 15
    argv += ["--limite-cve", str(max(1, min(200, limite)))]
    env = {}
    if cfg.get("api_key"):
        # Por variável de ambiente, não por argumento: argumentos aparecem
        # na lista de processos.
        env["NVD_API_KEY"] = cfg["api_key"]
    job = Job("netcve", "Vulnerabilidades · " +
              ("só configuração" if cfg.get("sem_rede") else "NVD + KEV"))
    job.config = {k: v for k, v in cfg.items() if k != "api_key"}
    registrar(job)
    iniciar_processo(job, argv, env_extra=env)
    return job


# ---------------------------------------------------------------------------
# Agendamentos
# ---------------------------------------------------------------------------
class Agenda:
    CAMPOS = ("nome", "alvos", "modo", "protocolo", "varredura", "instancias",
              "porta", "sensivel", "usuario", "intervalo_tipo",
              "intervalo_valor")

    def __init__(self, arquivo):
        self.arquivo = arquivo
        self.itens = {}
        self.senhas = {}
        self.trava = threading.Lock()
        try:
            with open(arquivo, "r", encoding="utf-8") as f:
                for item in json.load(f):
                    self.itens[item["id"]] = item
        except (OSError, ValueError):
            pass

    def salvar(self):
        tmp = self.arquivo + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(list(self.itens.values()), f, ensure_ascii=False,
                      indent=2)
        os.replace(tmp, self.arquivo)

    @staticmethod
    def proxima(item, base=None):
        agora = base or datetime.now()
        if item["intervalo_tipo"] == "horas":
            return agora + timedelta(hours=float(item["intervalo_valor"]))
        hh, mm = [int(x) for x in str(item["intervalo_valor"]).split(":")]
        alvo = agora.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if alvo <= agora:
            alvo += timedelta(days=1)
        return alvo

    def validar(self, dados):
        item = {c: dados.get(c) for c in self.CAMPOS}
        if not (item["nome"] or "").strip():
            raise ErroAPI(400, "Dê um nome ao agendamento")
        if not (item["alvos"] or "").strip() or not item["usuario"]:
            raise ErroAPI(400, "Informe alvos e usuário")
        if item["intervalo_tipo"] == "horas":
            try:
                h = float(item["intervalo_valor"])
                if not 1 <= h <= 24 * 30:
                    raise ValueError
            except (TypeError, ValueError):
                raise ErroAPI(400, "Intervalo entre 1 hora e 30 dias")
        elif item["intervalo_tipo"] == "diario":
            if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$",
                            str(item["intervalo_valor"])):
                raise ErroAPI(400, "Horário no formato HH:MM")
        else:
            raise ErroAPI(400, "Tipo de intervalo inválido")
        if CAPACIDADES["coleta"] and item["modo"] not in {
                m["chave"] for m in CAPACIDADES["modos"]}:
            raise ErroAPI(400, "Tipo de extração inválido")
        if item["protocolo"] not in ("ssh", "telnet"):
            raise ErroAPI(400, "Protocolo inválido")
        try:
            item["porta"] = int(item["porta"] or (
                23 if item["protocolo"] == "telnet" else 22))
            item["instancias"] = max(1, min(10, int(item["instancias"] or 5)))
            if not 1 <= item["porta"] <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            raise ErroAPI(400, "Porta ou número de simultâneos inválido")
        return item

    def criar(self, dados):
        item = self.validar(dados)
        senha = dados.get("senha") or ""
        with self.trava:
            item.update(id=secrets.token_hex(4), ativo=True,
                        criado=datetime.now().isoformat(timespec="seconds"),
                        proxima=self.proxima(item).isoformat(timespec="seconds"),
                        ultima=None, ultimo_job=None, ultimo_estado=None)
            self.itens[item["id"]] = item
            if senha:
                self.senhas[item["id"]] = senha
            self.salvar()
        return item

    def publico(self, item):
        d = dict(item)
        d["tem_senha"] = item["id"] in self.senhas
        d["situacao"] = ("pausado" if not item["ativo"] else
                         "aguardando senha" if not d["tem_senha"] else
                         "ativo")
        return d

    def listar(self):
        with self.trava:
            return [self.publico(i) for i in
                    sorted(self.itens.values(), key=lambda i: i["nome"])]

    def obter(self, ident):
        item = self.itens.get(ident)
        if not item:
            raise ErroAPI(404, "Agendamento não encontrado")
        return item

    def disparar(self, ident):
        item = self.obter(ident)
        senha = self.senhas.get(ident)
        if not senha:
            raise ErroAPI(409, "Informe a senha deste agendamento")
        cfg = {c: item[c] for c in ("alvos", "modo", "protocolo", "varredura",
                                    "instancias", "porta", "sensivel",
                                    "usuario")}
        cfg["senha"] = senha
        cfg["titulo"] = f"Agendamento · {item['nome']}"
        job = nova_coleta(cfg, origem=f"agendamento:{ident}")
        with self.trava:
            item["ultima"] = datetime.now().isoformat(timespec="seconds")
            item["ultimo_job"] = job.id
            item["ultimo_estado"] = "executando"
            item["proxima"] = self.proxima(item).isoformat(timespec="seconds")
            self.salvar()
        return job

    def registrar_termino(self, ident, job):
        with self.trava:
            item = self.itens.get(ident)
            if item and item.get("ultimo_job") == job.id:
                item["ultimo_estado"] = job.estado
                self.salvar()

    def ciclo(self):
        while True:
            time.sleep(15)
            try:
                self.verificar()
            except Exception:
                # Uma falha num agendamento não pode parar os demais.
                traceback.print_exc()

    def verificar(self):
        """Dispara os agendamentos vencidos que têm senha em memória."""
        agora = datetime.now()
        for ident, item in list(self.itens.items()):
            if not item["ativo"] or ident not in self.senhas:
                continue
            try:
                vencido = datetime.fromisoformat(item["proxima"]) <= agora
            except (TypeError, ValueError):
                vencido = True
            if not vencido:
                continue
            with JOBS_TRAVA:
                rodando = any(j.origem == f"agendamento:{ident}" and
                              j.estado == "executando" for j in JOBS.values())
            if rodando:
                continue
            try:
                self.disparar(ident)
            except ErroAPI as e:
                with self.trava:
                    item["ultima"] = agora.isoformat(timespec="seconds")
                    item["ultimo_estado"] = f"erro: {e.mensagem}"
                    item["proxima"] = self.proxima(item).isoformat(
                        timespec="seconds")
                    self.salvar()


AGENDA = Agenda(ARQUIVO_AGENDA)


# ---------------------------------------------------------------------------
# Snapshots, inventário, comparação e relatórios
# ---------------------------------------------------------------------------
MODELO = [
    (r"(?m)^Model:\s*(\S+)", None),
    (r"HUAWEI\s+([A-Z]{1,3}\d{3,5}[\w-]*)\s+(?:Routing Switch\s+)?uptime", None),
    (r"\b(MA5[68]\d\d[\w-]*)", None),
    (r"(?m)^\s*cisco\s+(Nexus\s*\S+.*?)\s+[Cc]hassis", None),
    (r"(?m)^[Cc]isco\s+(\S+)\s+\(.*\)\s+processor", None),
    (r"(?m)^\s*(?:board-name|model):\s*(.+)$", None),
    (r"\b(AN\d{4}[\w-]*)", None),
    (r'PRETTY_NAME="([^"]+)"', None),
]


def modelo_do_snapshot(snap):
    texto = "\n".join(c["saida"] or "" for _, c in
                      md.comandos_da_secao(snap, "inventario"))
    for padrao, _ in MODELO:
        m = re.search(padrao, texto)
        if m:
            return m.group(1).strip()[:60]
    return ""


def resumo_snapshot(caminho):
    meta = md.ler_metadados(caminho)
    nome = os.path.basename(caminho)
    return {
        "arquivo": nome,
        "host": meta.get("host") or "",
        "ip": meta.get("ip") or "",
        "plataforma": meta.get("platform_key") or "",
        "plataforma_nome": meta.get("platform_name") or "",
        "coletado_em": meta.get("collected_at") or "",
        "modo": meta.get("extraction_mode") or "",
        "secoes": meta.get("sections") or [],
        "aplicacoes": meta.get("applications") or [],
        "transporte": meta.get("transport") or "ssh",
        "sessao_perdida": bool(meta.get("session_lost")),
        "sensivel": meta.get("sensitive_data") or "",
        "tamanho": os.path.getsize(caminho),
    }


def caminho_seguro(pasta, nome):
    if not nome or not NOME_SEGURO.fullmatch(nome):
        raise ErroAPI(400, "Nome de arquivo inválido")
    caminho = os.path.join(pasta, nome)
    if not os.path.isfile(caminho):
        raise ErroAPI(404, "Arquivo não encontrado")
    return caminho


def cves_por_host():
    """Contagem de CVEs da triagem netcve mais recente, por (host, ip)."""
    triagens = sorted(n for n in os.listdir(PASTA_SNAPSHOTS)
                      if n.startswith("_cve_triagem_") and n.endswith(".md"))
    if not triagens:
        return {}, None
    contagem = {}
    texto = open(os.path.join(PASTA_SNAPSHOTS, triagens[-1]),
                 encoding="utf-8", errors="replace").read()
    bloco = texto.split("## Inventário de versões identificadas", 1)
    if len(bloco) < 2:
        return {}, triagens[-1]
    for linha in bloco[1].split("\n## ", 1)[0].splitlines():
        cel = [c.strip() for c in linha.strip().strip("|").split("|")]
        if len(cel) != 6 or cel[0] in ("Host", "---"):
            continue
        chave = (cel[0], cel[1])
        atual = contagem.setdefault(chave, {"cves": 0, "consultado": False})
        if cel[5].isdigit():
            atual["cves"] += int(cel[5])
            atual["consultado"] = True
    return contagem, triagens[-1]


def falhas_recentes():
    indices = sorted(n for n in os.listdir(PASTA_SNAPSHOTS)
                     if n.startswith("_indice_") and n.endswith(".md"))
    falhas = []
    for nome in indices[-5:]:
        texto = open(os.path.join(PASTA_SNAPSHOTS, nome), encoding="utf-8",
                     errors="replace").read()
        if "## Hosts não coletados" not in texto:
            continue
        data = re.search(r"_indice_(\d{8})_(\d{6})", nome)
        quando = (datetime.strptime("".join(data.groups()), "%Y%m%d%H%M%S")
                  .isoformat(timespec="seconds") if data else "")
        for linha in texto.split("## Hosts não coletados", 1)[1].splitlines():
            cel = [c.strip() for c in linha.strip().strip("|").split("|")]
            if len(cel) == 2 and cel[0] not in ("IP", "---"):
                falhas.append({"ip": cel[0], "motivo": cel[1],
                               "quando": quando, "indice": nome})
    return falhas


def inventario():
    try:
        import netcve
    except ImportError:
        netcve = None
    caminhos = md.listar_snapshots(PASTA_SNAPSHOTS)
    contagem_arquivos = {}
    for c in caminhos:
        m = md.ler_metadados(c)
        chave = (m.get("host"), m.get("ip"))
        contagem_arquivos[chave] = contagem_arquivos.get(chave, 0) + 1
    cves, triagem = cves_por_host()
    linhas = []
    for caminho, meta in md.mais_recentes(caminhos):
        snap = md.ler_snapshot(caminho)
        versoes = []
        if netcve:
            texto = open(caminho, encoding="utf-8", errors="replace").read()
            versoes = [f"{v['rotulo']} {v['versao']}" for v in
                       netcve.extrair_versoes(meta, texto)]
        chave = (meta.get("host"), meta.get("ip"))
        info_cve = cves.get((str(meta.get("host")), str(meta.get("ip"))))
        linha = resumo_snapshot(caminho)
        linha.update(
            modelo=modelo_do_snapshot(snap), versoes=versoes,
            coletas=contagem_arquivos.get(chave, 1),
            cves=info_cve["cves"] if info_cve and info_cve["consultado"]
            else None)
        linhas.append(linha)
    linhas.sort(key=lambda l: (l["host"] or "").lower())
    coletados = {l["ip"] for l in linhas}
    falhas = [f for f in falhas_recentes() if f["ip"] not in coletados]
    return {"hosts": linhas, "falhas": falhas, "triagem": triagem}


def comparar(nome_a, nome_b, so_estaveis=False):
    a = md.ler_snapshot(caminho_seguro(PASTA_SNAPSHOTS, nome_a))
    b = md.ler_snapshot(caminho_seguro(PASTA_SNAPSHOTS, nome_b))

    def itens(snap):
        d = {}
        for s in snap["secoes"]:
            for c in s["comandos"]:
                d[(s["titulo"], c["comando"])] = (s["chave"], c["saida"] or "")
        return d
    ia, ib = itens(a), itens(b)
    chaves = list(ia) + [k for k in ib if k not in ia]
    resultado = []
    for k in chaves:
        secao = (ia.get(k) or ib.get(k))[0]
        if so_estaveis and secao not in ("config", "inventario"):
            continue
        sa = ia.get(k, (None, None))[1]
        sb = ib.get(k, (None, None))[1]
        if sa is None:
            estado = "só na segunda"
        elif sb is None:
            estado = "só na primeira"
        elif sa == sb:
            estado = "igual"
        else:
            estado = "alterado"
        diff, mais, menos = [], 0, 0
        if estado == "alterado":
            for linha in difflib.unified_diff(sa.splitlines(), sb.splitlines(),
                                              lineterm="", n=3):
                if linha.startswith(("---", "+++")):
                    continue
                if linha.startswith("+"):
                    mais += 1
                elif linha.startswith("-"):
                    menos += 1
                if len(diff) < 3000:
                    diff.append(linha)
        resultado.append({"secao": k[0], "chave": secao, "comando": k[1],
                          "estado": estado, "mais": mais, "menos": menos,
                          "diff": diff})
    return {"a": a["meta"], "b": b["meta"], "arquivo_a": nome_a,
            "arquivo_b": nome_b,
            "mesmo_host": a["meta"].get("ip") == b["meta"].get("ip"),
            "itens": resultado}


TIPOS_RELATORIO = {
    "indice": (lambda: PASTA_SNAPSHOTS, "_indice_", ".md"),
    "triagem": (lambda: PASTA_SNAPSHOTS, "_cve_triagem_", ".md"),
    "triagem_csv": (lambda: PASTA_SNAPSHOTS, "_cve_triagem_", ".csv"),
    "diagnostico": (lambda: PASTA_DIAG, "_diagnostico_", ".md"),
    "topologia": (lambda: PASTA_SNAPSHOTS, "_topologia_", ".json"),
    "debug": (lambda: PASTA_SNAPSHOTS, "_debug_", ".log"),
}


def listar_relatorios():
    saida = {}
    for tipo, (pasta, prefixo, ext) in TIPOS_RELATORIO.items():
        nomes = sorted((n for n in os.listdir(pasta())
                        if n.startswith(prefixo) and n.endswith(ext)),
                       reverse=True)
        saida[tipo] = [{"arquivo": n, "tamanho": os.path.getsize(
            os.path.join(pasta(), n))} for n in nomes[:100]]
    return saida


def caminho_relatorio(tipo, nome):
    if tipo == "snapshot":
        return caminho_seguro(PASTA_SNAPSHOTS, nome)
    if tipo not in TIPOS_RELATORIO:
        raise ErroAPI(404, "Tipo desconhecido")
    pasta, prefixo, ext = TIPOS_RELATORIO[tipo]
    if not (nome.startswith(prefixo) and nome.endswith(ext)):
        raise ErroAPI(400, "Arquivo não pertence a este tipo")
    return caminho_seguro(pasta(), nome)


def painel():
    snaps = [resumo_snapshot(c) for c in md.listar_snapshots(PASTA_SNAPSHOTS)]
    snaps.sort(key=lambda s: s["coletado_em"], reverse=True)
    hosts = {(s["host"], s["ip"]) for s in snaps}
    with JOBS_TRAVA:
        jobs = sorted((j.resumo() for j in JOBS.values()),
                      key=lambda j: j["criado"], reverse=True)
    return {
        "snapshots": len(snaps), "hosts": len(hosts),
        "ultimas": snaps[:8], "jobs": jobs[:10],
        "executando": sum(1 for j in jobs if j["estado"] == "executando"),
        "agendamentos": AGENDA.listar(),
        "falhas": falhas_recentes()[-10:],
        "pastas": {"snapshots": PASTA_SNAPSHOTS, "diagnosticos": PASTA_DIAG},
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class ErroAPI(Exception):
    def __init__(self, status, mensagem):
        super().__init__(mensagem)
        self.status = status
        self.mensagem = mensagem


ESTATICOS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'none'")


class Manipulador(BaseHTTPRequestHandler):
    server_version = "netsnap-web"
    sys_version = ""

    def log_message(self, formato, *args):
        pass

    # -- segurança --------------------------------------------------------
    def _host_valido(self):
        # Contra DNS rebinding: um site externo que resolva para 127.0.0.1
        # chegaria aqui com o próprio nome no cabeçalho Host.
        host = (self.headers.get("Host") or "").lower()
        return host in (f"127.0.0.1:{PORTA}", f"localhost:{PORTA}")

    def _token_valido(self):
        recebido = self.headers.get("X-Netsnap-Token") or ""
        return hmac.compare_digest(recebido.encode("utf-8", "replace"),
                                   TOKEN.encode("ascii"))

    # -- respostas --------------------------------------------------------
    def _cabecalhos_comuns(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _json(self, status, dados):
        corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self._cabecalhos_comuns()
        self.end_headers()
        self.wfile.write(corpo)

    def _arquivo(self, caminho, tipo, baixar=False):
        with open(caminho, "rb") as f:
            corpo = f.read()
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        if baixar:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{os.path.basename(caminho)}"')
        self._cabecalhos_comuns()
        if tipo.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(corpo)

    def _corpo(self):
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho > LIMITE_CORPO:
            raise ErroAPI(413, "Requisição grande demais")
        if not (self.headers.get("Content-Type") or "").startswith(
                "application/json"):
            raise ErroAPI(415, "Envie JSON")
        bruto = self.rfile.read(tamanho) if tamanho else b"{}"
        try:
            dados = json.loads(bruto.decode("utf-8"))
        except ValueError:
            raise ErroAPI(400, "JSON inválido")
        if not isinstance(dados, dict):
            raise ErroAPI(400, "JSON inválido")
        return dados

    # -- despacho ---------------------------------------------------------
    def do_GET(self):
        self._despachar("GET")

    def do_POST(self):
        self._despachar("POST")

    def do_DELETE(self):
        self._despachar("DELETE")

    def _despachar(self, metodo):
        if not self._host_valido():
            self._json(403, {"erro": "Host não permitido"})
            return
        url = urlparse(self.path)
        caminho = url.path
        if metodo == "GET" and caminho in ESTATICOS:
            nome, tipo = ESTATICOS[caminho]
            self._arquivo(os.path.join(PASTA_WEB, nome), tipo)
            return
        if not caminho.startswith("/api/"):
            self._json(404, {"erro": "Não encontrado"})
            return
        if not self._token_valido():
            self._json(401, {"erro": "Token ausente ou inválido. Abra o "
                                     "painel pelo endereço mostrado no "
                                     "terminal."})
            return
        consulta = {k: v[0] for k, v in parse_qs(url.query).items()}
        partes = [unquote(p) for p in caminho[5:].strip("/").split("/")]
        try:
            resposta = self._rota(metodo, partes, consulta)
            if resposta is not None:
                self._json(200, resposta)
        except ErroAPI as e:
            self._json(e.status, {"erro": e.mensagem})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._json(500, {"erro": f"{type(e).__name__}: {e}"})

    def _rota(self, metodo, p, q):
        rota = (metodo, p[0] if p else "")
        n = len(p)

        if rota == ("GET", "info"):
            return {"versao": __version__, "capacidades": CAPACIDADES,
                    "pastas": {"snapshots": PASTA_SNAPSHOTS,
                               "diagnosticos": PASTA_DIAG}}
        if rota == ("GET", "painel"):
            return painel()

        if rota == ("POST", "coletas"):
            return nova_coleta(self._corpo()).resumo()
        if rota == ("POST", "netdiag"):
            return novo_netdiag(self._corpo()).resumo()
        if rota == ("POST", "netcve"):
            return novo_netcve(self._corpo()).resumo()

        if rota == ("GET", "jobs") and n == 1:
            with JOBS_TRAVA:
                return sorted((j.resumo() for j in JOBS.values()),
                              key=lambda j: j["criado"], reverse=True)
        if p[0] == "jobs" and n >= 2:
            job = JOBS.get(p[1])
            if not job:
                raise ErroAPI(404, "Execução não encontrada")
            if metodo == "GET" and n == 2:
                return job.detalhe(int(q.get("desde", 0) or 0))
            if metodo == "POST" and n == 3 and p[2] == "cancelar":
                with job.trava:
                    if job.estado == "executando" and job.proc:
                        job.cancelado = True
                        job.proc.terminate()
                return job.resumo()

        if rota == ("GET", "snapshots"):
            if n == 1:
                lista = [resumo_snapshot(c) for c in
                         md.listar_snapshots(PASTA_SNAPSHOTS)]
                lista.sort(key=lambda s: s["coletado_em"], reverse=True)
                return lista
            snap = md.ler_snapshot(caminho_seguro(PASTA_SNAPSHOTS, p[1]))
            snap["arquivo"] = p[1]
            return snap

        if rota == ("GET", "arquivo") and n == 3:
            caminho = caminho_relatorio(p[1], p[2])
            tipo = ("application/json" if caminho.endswith(".json") else
                    "text/csv; charset=utf-8" if caminho.endswith(".csv")
                    else "text/plain; charset=utf-8")
            self._arquivo(caminho, tipo, baixar=q.get("baixar") == "1")
            return None

        if rota == ("GET", "relatorios"):
            return listar_relatorios()
        if rota == ("GET", "inventario"):
            return inventario()
        if rota == ("GET", "comparar"):
            return comparar(q.get("a", ""), q.get("b", ""),
                            q.get("estaveis") == "1")
        if rota == ("GET", "topologia"):
            return topo.construir(PASTA_SNAPSHOTS)
        if rota == ("POST", "topologia") and n == 2 and p[1] == "salvar":
            grafo = topo.construir(PASTA_SNAPSHOTS)
            return {"arquivo": os.path.basename(
                topo.salvar(grafo, PASTA_SNAPSHOTS))}

        if p[0] == "agendamentos":
            if metodo == "GET" and n == 1:
                return AGENDA.listar()
            if metodo == "POST" and n == 1:
                return AGENDA.publico(AGENDA.criar(self._corpo()))
            if n >= 2:
                item = AGENDA.obter(p[1])
                if metodo == "DELETE" and n == 2:
                    with AGENDA.trava:
                        AGENDA.itens.pop(item["id"], None)
                        AGENDA.senhas.pop(item["id"], None)
                        AGENDA.salvar()
                    return {"removido": item["id"]}
                if metodo == "POST" and n == 3:
                    acao = p[2]
                    if acao == "senha":
                        senha = self._corpo().get("senha") or ""
                        if not senha:
                            raise ErroAPI(400, "Informe a senha")
                        AGENDA.senhas[item["id"]] = senha
                        # Depois de um reinício a próxima execução pode
                        # estar no passado; informar a senha não deve
                        # disparar a coleta na hora (para isso há
                        # "Executar agora").
                        try:
                            atrasado = datetime.fromisoformat(
                                item["proxima"]) <= datetime.now()
                        except (TypeError, ValueError):
                            atrasado = True
                        if atrasado:
                            with AGENDA.trava:
                                item["proxima"] = AGENDA.proxima(
                                    item).isoformat(timespec="seconds")
                                AGENDA.salvar()
                    elif acao in ("ativar", "pausar"):
                        with AGENDA.trava:
                            item["ativo"] = acao == "ativar"
                            if item["ativo"]:
                                item["proxima"] = AGENDA.proxima(item).isoformat(
                                    timespec="seconds")
                            AGENDA.salvar()
                    elif acao == "executar":
                        return AGENDA.disparar(item["id"]).resumo()
                    else:
                        raise ErroAPI(404, "Ação desconhecida")
                    return AGENDA.publico(item)

        raise ErroAPI(404, "Rota não encontrada")


def abrir_navegador(url):
    """Abre o painel sem pôr o token na linha de comando do navegador.

    A linha de comando de um processo é visível para outros usuários da
    máquina. O navegador recebe o caminho de um arquivo legível só pelo
    dono, que redireciona para o endereço com o token."""
    try:
        fd, caminho = tempfile.mkstemp(prefix="netsnap_", suffix=".html")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f'<!doctype html><meta charset="utf-8">'
                    f'<meta http-equiv="refresh" content="0;url={url}">'
                    f'<title>netsnap</title><a href="{url}">Abrir o painel</a>')
        webbrowser.open(pathlib.Path(caminho).as_uri())
        threading.Timer(60, lambda: os.path.exists(caminho) and
                        os.remove(caminho)).start()
    except OSError:
        webbrowser.open(url)


def main():
    global PORTA
    ap = argparse.ArgumentParser(description="Painel local do netsnap")
    ap.add_argument("--porta", type=int, default=8765)
    ap.add_argument("--sem-navegador", action="store_true",
                    help="não abre o navegador automaticamente")
    ap.add_argument("--executor", help=argparse.SUPPRESS)
    ap.add_argument("-v", "--version", action="version",
                    version=f"netsnap_web {__version__}")
    args = ap.parse_args()
    if args.executor:
        modo_executor(args.executor)
        return

    if os.name == "posix":
        # Snapshots e logs criados pelo painel e pelas coletas ficam
        # legíveis só pelo dono.
        os.umask(0o077)
    servidor = None
    for tentativa in range(10):
        try:
            PORTA = args.porta + tentativa
            servidor = ThreadingHTTPServer(("127.0.0.1", PORTA), Manipulador)
            break
        except OSError:
            continue
    if servidor is None:
        raise SystemExit("[ERRO] Nenhuma porta livre a partir de "
                         f"{args.porta}")
    servidor.daemon_threads = True
    threading.Thread(target=AGENDA.ciclo, daemon=True).start()

    url = f"http://127.0.0.1:{PORTA}/#t={TOKEN}"
    print("=" * 68)
    print(f" netsnap painel v{__version__}")
    print("=" * 68)
    print(f" Endereço : {url}")
    print(f" Snapshots: {PASTA_SNAPSHOTS}")
    if not CAPACIDADES["coleta"]:
        print(f" [!] Modo consulta: {CAPACIDADES['motivo']}")
    print(" O endereço contém o token desta execução; não o compartilhe.")
    print(" Ctrl+C encerra o painel e interrompe coletas em andamento.")
    if not args.sem_navegador:
        threading.Timer(0.8, abrir_navegador, args=(url,)).start()
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando ...")
    finally:
        for job in list(JOBS.values()):
            if job.estado == "executando" and job.proc:
                job.cancelado = True
                job.proc.terminate()
        servidor.server_close()


if __name__ == "__main__":
    main()
