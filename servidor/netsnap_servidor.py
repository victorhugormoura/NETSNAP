#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_servidor — o painel do netsnap como serviço multiusuário

Roda em um servidor Linux atrás do Nginx ou do Apache (que cuidam do HTTPS) e
deixa os técnicos coletarem pelo navegador, sem instalar nada no próprio PC.
Aproveita todo o painel local (netsnap_web) e acrescenta:

  - Login com usuário, senha e TOTP; papéis admin, técnico e leitura;
    bloqueio progressivo por tentativas; sessões com expiração por ociosidade
    e por duração máxima.
  - Cofre de credenciais de equipamento cifrado (AES-256-GCM, chave-mestra
    entregue pelo systemd). A senha guardada nunca volta para o navegador:
    o técnico escolhe a credencial, e o servidor a entrega só ao processo de
    coleta.
  - Agendador persistente (todo dia, dias da semana, a cada N dias ou a cada
    N horas) que roda sem ninguém logado e, ao fim, monta o pacote de análise
    para o NETANALYTIC.
  - Histórico de execuções, retenção automática e trilha de auditoria
    encadeada por HMAC.

Escuta num socket Unix entregue pelo systemd, acessível só ao grupo do
Nginx/Apache: o acesso de fora passa obrigatoriamente pelo proxy com TLS.

Uso:
    netsnap_servidor.py --config /etc/netsnap/servidor.conf

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.0.2"

import argparse
import configparser
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from datetime import date, datetime, timedelta
from datetime import time as dtime
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

import netsnap_cofre as cofre_mod   # noqa: E402
import netsnap_banco as banco_mod   # noqa: E402

# Preenchidos em iniciar(): o netsnap_web lê NETSNAP_DADOS ao ser importado.
web = None
analise = None
CONF = None
COFRE = None
BANCO = None
AGENDA = None

NIVEL = {"leitura": 1, "tecnico": 2, "admin": 3}
COOKIE_SEGURO = "__Host-netsnap"
COOKIE_LOCAL = "netsnap"
VALIDADE_COOKIE_DISPOSITIVO = 180 * 86400
CONTROLE = re.compile(r"[\x00-\x1f\x7f]")


def limpo(texto, tamanho=120):
    """Texto vindo do cliente, seguro para uma linha de log (sem quebra de
    linha nem caractere de controle que forje outra entrada)."""
    return CONTROLE.sub("?", str(texto))[:tamanho]


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
PADRAO = {
    "servidor": {
        "endereco": "127.0.0.1",
        "porta": "8765",
        "nomes": "localhost",
        "porta_publica": "443",
        "dados": "/var/lib/netsnap",
        "banco": "",
        "arquivo_chave": "",
        "proxy_confiavel": "127.0.0.1, ::1",
        "cookie_seguro": "sim",
        "tcp_para_testes": "nao",
    },
    "sessao": {
        "ociosidade_minutos": "30",
        "duracao_maxima_horas": "12",
        "exigir_totp": "sim",
        "emissor_totp": "netsnap",
    },
    "coleta": {
        "max_execucoes_simultaneas": "3",
        "permitir_dados_sensiveis": "nao",
        "permitir_telnet": "sim",
        # Laboratório com equipamento simulado em 127.x: 'sim' libera alvos
        # locais e link-local, que em produção nunca são equipamento.
        "permitir_alvos_locais": "nao",
    },
    "retencao": {
        "snapshots_dias": "180",
        "analises_dias": "365",
        "execucoes_dias": "365",
    },
}


class Config:
    def __init__(self, caminho):
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        cp.BOOLEAN_STATES = dict(cp.BOOLEAN_STATES, sim=True, nao=False,
                                 não=False)
        cp.read_dict(PADRAO)
        try:
            self._ler(cp, caminho)
        except ValueError as e:
            raise SystemExit(f"[ERRO] {caminho}: {e}")

    def _ler(self, cp, caminho):
        if caminho:
            if not cp.read(caminho, encoding="utf-8"):
                raise SystemExit(f"[ERRO] não foi possível ler {caminho}")
        s = cp["servidor"]
        self.endereco = s.get("endereco")
        self.porta = s.getint("porta")
        self.nomes = [n.strip().lower() for n in s.get("nomes").split(",")
                      if n.strip()]
        self.porta_publica = s.getint("porta_publica")
        self.dados = s.get("dados")
        self.banco = s.get("banco") or os.path.join(self.dados, "netsnap.db")
        self.arquivo_chave = s.get("arquivo_chave") or None
        self.proxies = {p.strip() for p in s.get("proxy_confiavel").split(",")
                        if p.strip()}
        self.cookie_seguro = s.getboolean("cookie_seguro")
        self.tcp_para_testes = s.getboolean("tcp_para_testes")
        ss = cp["sessao"]
        self.ociosidade = timedelta(minutes=ss.getint("ociosidade_minutos"))
        self.duracao = timedelta(hours=ss.getint("duracao_maxima_horas"))
        self.exigir_totp = ss.getboolean("exigir_totp")
        self.emissor = ss.get("emissor_totp")
        c = cp["coleta"]
        self.max_execucoes = max(1, c.getint("max_execucoes_simultaneas"))
        self.permitir_sensivel = c.getboolean("permitir_dados_sensiveis")
        self.permitir_telnet = c.getboolean("permitir_telnet")
        self.permitir_locais = c.getboolean("permitir_alvos_locais")
        r = cp["retencao"]
        self.ret_snapshots = r.getint("snapshots_dias")
        self.ret_analises = r.getint("analises_dias")
        self.ret_execucoes = r.getint("execucoes_dias")
        porta = "" if self.porta_publica == 443 else f":{self.porta_publica}"
        self.origens = {f"https://{n}{porta}" for n in self.nomes}
        if not self.cookie_seguro:
            # Só para testes locais sem TLS.
            self.origens |= {f"http://{n}:{self.porta}" for n in self.nomes}
        if self.endereco not in ("127.0.0.1", "::1", "localhost"):
            raise SystemExit("[ERRO] o servidor escuta só em 127.0.0.1/::1; "
                             "o acesso externo passa pelo Nginx/Apache")

    @property
    def cookie(self):
        return COOKIE_SEGURO if self.cookie_seguro else COOKIE_LOCAL

    @property
    def cookie_dispositivo(self):
        return self.cookie + "-disp"


# ---------------------------------------------------------------------------
# Limite de tentativas por IP (em memória)
# ---------------------------------------------------------------------------
def chave_ip(ip):
    """IPv6 por /64: trocar de endereço dentro da mesma rede não renova o
    limite de tentativas."""
    try:
        end = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if end.version == 6:
        return str(ipaddress.ip_network(f"{end}/64", strict=False))
    return str(end)


class Limitador:
    def __init__(self, maximo, janela_s):
        self.maximo, self.janela = maximo, janela_s
        self.eventos = {}
        self.trava = threading.Lock()
        self.ultima_limpeza = time.monotonic()

    def permitido(self, chave):
        t = time.monotonic()
        with self.trava:
            fila = self.eventos.setdefault(chave, deque())
            while fila and fila[0] <= t - self.janela:
                fila.popleft()
            if len(fila) >= self.maximo:
                return False
            fila.append(t)
            if t - self.ultima_limpeza > 60:
                # Chaves cujo último evento saiu da janela não voltam a
                # esvaziar sozinhas: limpa uma vez por minuto.
                self.ultima_limpeza = t
                for k in [k for k, f in self.eventos.items()
                          if not f or f[-1] <= t - self.janela]:
                    del self.eventos[k]
            return True


class BloqueioPorOrigem:
    """Bloqueio rápido por conta + origem: 5 erros seguidos do mesmo IP (ou
    /64) bloqueiam aquela conta para aquela origem, com tempo dobrando a cada
    novo bloqueio (até 24 h). Quem erra de outro lugar não tranca o dono da
    conta; o bloqueio da conta inteira (netsnap_banco) só vem com muitos
    erros vindos de vários lugares."""
    LIMITE = 5

    def __init__(self):
        self.itens = {}
        self.trava = threading.Lock()
        self.ultima_limpeza = time.monotonic()

    def bloqueado(self, uid, ip):
        with self.trava:
            d = self.itens.get((uid, chave_ip(ip)))
            return bool(d and d["ate"] > time.monotonic())

    def falhou(self, uid, ip):
        agora = time.monotonic()
        with self.trava:
            if agora - self.ultima_limpeza > 60:
                # Uma vez por minuto: some o que não está bloqueado e não
                # erra há mais de uma hora.
                self.ultima_limpeza = agora
                for k in [k for k, v in self.itens.items()
                          if v["ate"] <= agora and v["visto"] < agora - 3600]:
                    del self.itens[k]
            d = self.itens.setdefault((uid, chave_ip(ip)),
                                      {"falhas": 0, "vezes": 0, "ate": 0,
                                       "visto": agora})
            d["visto"] = agora
            d["falhas"] += 1
            if d["falhas"] >= self.LIMITE:
                d["ate"] = agora + min(900 * 2 ** d["vezes"], 86400)
                d["vezes"] += 1
                d["falhas"] = 0
                return True
        return False

    def limpar(self, uid, ip=None):
        with self.trava:
            for k in [k for k in self.itens
                      if k[0] == uid and (ip is None or k[1] == chave_ip(ip))]:
                del self.itens[k]


LIMITE_LOGIN_IP = Limitador(60, 300)
BLOQUEIOS = BloqueioPorOrigem()
TRAVA_EXECUCOES = threading.Lock()


# ---------------------------------------------------------------------------
# Login em etapas: senha -> (cadastro do) TOTP -> troca de senha -> sessão
# ---------------------------------------------------------------------------
class Desafios:
    """Estado entre as etapas do login, só em memória e por 5 minutos."""
    VALIDADE = 300
    TENTATIVAS = 5

    def __init__(self):
        self.itens = {}
        self.trava = threading.Lock()

    def criar(self, uid, etapa, **extra):
        token = secrets.token_urlsafe(32)
        with self.trava:
            agora = time.monotonic()
            for k in [k for k, v in self.itens.items()
                      if v["expira"] <= agora]:
                del self.itens[k]
            self.itens[token] = dict(uid=uid, etapa=etapa, tentativas=0,
                                     expira=agora + self.VALIDADE, **extra)
        return token

    def consumir(self, token):
        """Gasta uma tentativa antes de verificar o código: pedidos paralelos
        no mesmo desafio não passam do limite. None se esgotado/expirado."""
        with self.trava:
            d = self.itens.get(token or "")
            if not d or d["expira"] <= time.monotonic():
                self.itens.pop(token or "", None)
                return None
            d["tentativas"] += 1
            if d["tentativas"] > self.TENTATIVAS:
                del self.itens[token]
                return None
            return d

    def descartar(self, token):
        with self.trava:
            self.itens.pop(token, None)


DESAFIOS = Desafios()
MSG_LOGIN = ("Usuário, senha ou código inválidos, ou conta temporariamente "
             "bloqueada.")


def qr_svg(texto):
    """QR code em SVG pelo qrencode (entrada pela stdin, fora da lista de
    processos). Sem o programa, o painel mostra o segredo em texto."""
    exe = shutil.which("qrencode")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-t", "SVG", "-m", "2", "-s", "6", "-o", "-"],
                           input=texto.encode(), capture_output=True,
                           timeout=10)
        return r.stdout.decode("utf-8") if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Agendador persistente
# ---------------------------------------------------------------------------
DIAS_SEMANA = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"]
HORA = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def proxima_execucao(freq, base):
    tipo = freq["tipo"]
    if tipo == "horas":
        return (base + timedelta(hours=freq["a_cada"])).replace(microsecond=0)
    hh, mm = (int(x) for x in freq["hora"].split(":"))
    if tipo == "diario":
        alvo = base.replace(hour=hh, minute=mm, second=0, microsecond=0)
        return alvo if alvo > base else alvo + timedelta(days=1)
    if tipo == "semanal":
        for i in range(8):
            alvo = (base + timedelta(days=i)).replace(
                hour=hh, minute=mm, second=0, microsecond=0)
            if alvo.weekday() in freq["dias_semana"] and alvo > base:
                return alvo
        raise ValueError("nenhum dia da semana marcado")
    if tipo == "dias":
        inicio = date.fromisoformat(freq["inicio"])
        n = freq["a_cada"]
        d = max(base.date(), inicio)
        resto = (d - inicio).days % n
        if resto:
            d += timedelta(days=n - resto)
        alvo = datetime.combine(d, dtime(hh, mm))
        return alvo if alvo > base else alvo + timedelta(days=n)
    raise ValueError("tipo de frequência inválido")


def texto_frequencia(freq):
    tipo = freq.get("tipo")
    if tipo == "horas":
        return f"a cada {freq['a_cada']} h"
    if tipo == "diario":
        return f"todo dia às {freq['hora']}"
    if tipo == "semanal":
        dias = ", ".join(DIAS_SEMANA[d] for d in sorted(freq["dias_semana"]))
        return f"{dias} às {freq['hora']}"
    if tipo == "dias":
        return f"a cada {freq['a_cada']} dias às {freq['hora']}"
    return "?"


def validar_frequencia(f):
    if not isinstance(f, dict):
        raise web.ErroAPI(400, "Frequência inválida")
    tipo = f.get("tipo")
    saida = {"tipo": tipo}
    try:
        if tipo == "horas":
            saida["a_cada"] = int(f.get("a_cada"))
            if not 1 <= saida["a_cada"] <= 24 * 30:
                raise ValueError
            return saida
        if not HORA.match(str(f.get("hora", ""))):
            raise web.ErroAPI(400, "Horário no formato HH:MM")
        saida["hora"] = f["hora"]
        if tipo == "diario":
            return saida
        if tipo == "semanal":
            dias = sorted({int(d) for d in f.get("dias_semana") or []})
            if not dias or any(not 0 <= d <= 6 for d in dias):
                raise web.ErroAPI(400, "Marque pelo menos um dia da semana")
            saida["dias_semana"] = dias
            return saida
        if tipo == "dias":
            saida["a_cada"] = int(f.get("a_cada"))
            if not 1 <= saida["a_cada"] <= 365:
                raise ValueError
            inicio = f.get("inicio") or date.today().isoformat()
            date.fromisoformat(inicio)
            saida["inicio"] = inicio
            return saida
    except web.ErroAPI:
        raise
    except (TypeError, ValueError):
        raise web.ErroAPI(400, "Intervalo inválido (horas: 1 a 720; "
                               "dias: 1 a 365)")
    raise web.ErroAPI(400, "Tipo de frequência inválido")


LIMITE_NETDIAG = 20


def resolver_alvos(texto, porta_padrao, redes, nome_credencial, limite):
    """Expande as entradas e confere cada endereço contra as redes da
    credencial do cofre.

    Devolve as entradas reescritas como IP:porta: um nome DNS é resolvido
    uma vez, aqui, e o coletor conecta exatamente ao endereço conferido (sem
    nova consulta DNS que poderia apontar para outro lugar)."""
    import netsnap as ns
    linhas = [l for l in str(texto).splitlines() if l.split("#", 1)[0].strip()]
    total = web.contar_alvos(linhas)
    if total > limite:
        raise web.ErroAPI(400, f"As entradas somam {total} endereços; o limite "
                               f"é {limite}")
    redes_obj = [ipaddress.ip_network(r) for r in redes] if redes else None
    saida, fora, proibidos = [], [], []
    for linha in linhas:
        for alvo, porta in ns.expandir_entrada(linha, porta_padrao):
            try:
                ip = ipaddress.ip_address(alvo)
            except ValueError:
                try:
                    infos = socket.getaddrinfo(alvo, porta,
                                               type=socket.SOCK_STREAM)
                except (socket.gaierror, UnicodeError):
                    raise web.ErroAPI(400, f"Não foi possível resolver {alvo}")
                enderecos = sorted({ipaddress.ip_address(i[4][0].split("%")[0])
                                    for i in infos},
                                   key=lambda e: (e.version, int(e)))
                ip = enderecos[0]
            # Loopback, link-local (metadados de nuvem em 169.254.169.254),
            # multicast e reservados nunca são equipamento do parque: com
            # Telnet, usuário e senha iriam em texto para o serviço local.
            if not CONF.permitir_locais and (
                    ip.is_loopback or ip.is_link_local or ip.is_multicast or
                    ip.is_unspecified or ip.is_reserved):
                proibidos.append(f"{alvo}" + (f" ({ip})" if str(ip) != alvo else ""))
                continue
            if redes_obj is not None and \
                    not any(ip.version == r.version and ip in r for r in redes_obj):
                fora.append(f"{alvo}" + (f" ({ip})" if str(ip) != alvo else ""))
                continue
            saida.append(f"[{ip}]:{porta}" if ip.version == 6 else
                         f"{ip}:{porta}")
    if proibidos:
        raise web.ErroAPI(403, "Endereço local, link-local, multicast ou "
                               "reservado não é alvo de coleta: "
                               + ", ".join(proibidos[:5]))
    if fora:
        mostrar = ", ".join(fora[:5]) + (f" e mais {len(fora) - 5}"
                                         if len(fora) > 5 else "")
        raise web.ErroAPI(403, f"A credencial \"{nome_credencial}\" só pode ser "
                               f"usada nas redes {', '.join(redes)}. Fora "
                               f"delas: {mostrar}")
    if not saida:
        raise web.ErroAPI(400, "Nenhum alvo válido nas entradas")
    return "\n".join(saida)


def preparar_credencial(cfg, cid, limite):
    """Aplica a credencial do cofre a uma execução, com as regras dela."""
    try:
        segredo = BANCO.segredo_credencial(int(cid), marcar_uso=True)
        cred = BANCO.credencial(int(cid))
    except (ValueError, TypeError, banco_mod.ErroBanco):
        raise web.ErroAPI(400, "Credencial não encontrada")
    except cofre_mod.ErroCofre:
        raise web.ErroAPI(409, "Credencial ilegível (chave diferente?)")
    if cfg.get("protocolo") == "telnet" and not segredo["telnet"]:
        raise web.ErroAPI(403, f"A credencial \"{cred['nome']}\" não permite "
                               "Telnet (o Telnet manda a senha em texto claro). "
                               "Um administrador pode liberar no cofre.")
    porta = web.porta_valida(cfg.get("porta"),
                             23 if cfg.get("protocolo") == "telnet" else 22)
    cfg["alvos"] = resolver_alvos(cfg.get("alvos", ""), porta, segredo["redes"],
                                  cred["nome"], limite)
    cfg["usuario"], cfg["senha"] = segredo["usuario"], segredo["senha"]
    cfg["credencial"] = int(cid)
    return cfg


def execucoes_ativas():
    with web.JOBS_TRAVA:
        return sum(1 for j in web.JOBS.values() if j.estado == "executando")


class AgendaServidor:
    CAMPOS = ("nome", "alvos", "modo", "protocolo", "varredura", "instancias",
              "porta", "credencial", "frequencia", "analise")

    def __init__(self):
        self.trava = threading.RLock()

    def itens(self):
        return {i["id"]: i for i in BANCO.listar_agendamentos()}

    def validar(self, dados):
        item = {c: dados.get(c) for c in self.CAMPOS}
        # Sem caractere de controle: o nome vai para o journal e uma quebra
        # de linha forjaria outra entrada.
        item["nome"] = limpo((item["nome"] or "").strip(), 80).strip()
        if not item["nome"]:
            raise web.ErroAPI(400, "Dê um nome ao agendamento")
        alvos = str(item["alvos"] or "")
        linhas = [l for l in alvos.splitlines() if l.split("#", 1)[0].strip()]
        if not linhas:
            raise web.ErroAPI(400, "Informe os alvos")
        total = web.contar_alvos(linhas)
        if total > web.LIMITE_ALVOS:
            raise web.ErroAPI(400, f"As entradas somam {total} endereços; o "
                                   f"limite é {web.LIMITE_ALVOS}")
        item["alvos"] = alvos[:200000]
        if item["modo"] not in {m["chave"] for m in web.CAPACIDADES["modos"]}:
            raise web.ErroAPI(400, "Tipo de extração inválido")
        if item["protocolo"] not in ("ssh", "telnet"):
            raise web.ErroAPI(400, "Protocolo inválido")
        if item["protocolo"] == "telnet" and not CONF.permitir_telnet:
            raise web.ErroAPI(403, "Telnet desativado neste servidor")
        if item["varredura"] not in ("fast", "deep"):
            item["varredura"] = "fast"
        try:
            item["porta"] = int(item["porta"] or (
                23 if item["protocolo"] == "telnet" else 22))
            item["instancias"] = max(1, min(10, int(item["instancias"] or 5)))
            if not 1 <= item["porta"] <= 65535:
                raise ValueError
            item["credencial"] = int(item["credencial"])
        except (TypeError, ValueError):
            raise web.ErroAPI(400, "Porta, simultâneos ou credencial inválidos")
        if not BANCO.credencial(item["credencial"]):
            raise web.ErroAPI(400, "Credencial não encontrada no cofre")
        item["frequencia"] = validar_frequencia(item["frequencia"])
        item["analise"] = bool(item["analise"])
        # Confere já na criação (alvos dentro das redes da credencial,
        # Telnet permitido); a conferência se repete a cada disparo.
        preparar_credencial({"alvos": item["alvos"], "porta": item["porta"],
                             "protocolo": item["protocolo"]},
                            item["credencial"], web.LIMITE_ALVOS)
        return item

    def criar(self, dados, usuario):
        item = self.validar(dados)
        item.update(id=secrets.token_hex(8), ativo=True, criado_por=usuario,
                    criado=banco_mod.iso(banco_mod.agora()), ultima=None,
                    ultimo_job=None, ultimo_estado=None)
        item["proxima"] = banco_mod.iso(proxima_execucao(
            item["frequencia"], banco_mod.agora()))
        with self.trava:
            BANCO.salvar_agendamento(item)
        return item

    def atualizar(self, ident, dados):
        with self.trava:
            item = self.obter(ident)
            novo = self.validar(dados)
            item.update(novo)
            if item["ativo"]:
                item["proxima"] = banco_mod.iso(proxima_execucao(
                    item["frequencia"], banco_mod.agora()))
            BANCO.salvar_agendamento(item)
        return item

    def obter(self, ident):
        item = self.itens().get(ident)
        if not item:
            raise web.ErroAPI(404, "Agendamento não encontrado")
        return item

    def publico(self, item):
        d = dict(item)
        cred = BANCO.credencial(item.get("credencial"))
        d["credencial_nome"] = cred["nome"] if cred else None
        d["frequencia_texto"] = texto_frequencia(item["frequencia"])
        d["tem_senha"] = bool(cred)
        d["situacao"] = ("pausado" if not item["ativo"] else
                         "sem credencial" if not cred else "ativo")
        return d

    def listar(self):
        return [self.publico(i) for i in self.itens().values()]

    def alternar(self, ident, ativo):
        with self.trava:
            item = self.obter(ident)
            item["ativo"] = ativo
            if ativo:
                item["proxima"] = banco_mod.iso(proxima_execucao(
                    item["frequencia"], banco_mod.agora()))
            BANCO.salvar_agendamento(item)
        return item

    def remover(self, ident):
        with self.trava:
            BANCO.remover_agendamento(self.obter(ident)["id"])

    def disparar(self, ident, usuario):
        with self.trava, TRAVA_EXECUCOES:
            item = self.obter(ident)
            if execucoes_ativas() >= CONF.max_execucoes:
                raise web.ErroAPI(429, "Limite de execuções simultâneas "
                                       "atingido; tente em alguns minutos")
            cfg = {c: item[c] for c in ("alvos", "modo", "protocolo",
                                        "varredura", "instancias", "porta")}
            preparar_credencial(cfg, item["credencial"], web.LIMITE_ALVOS)
            cfg.update(sensivel=False, titulo=f"Agendamento · {item['nome']}")
            job = web.nova_coleta(cfg, origem=f"agendamento:{ident}")
            job.usuario = usuario
            job.config["iniciado_por"] = usuario
            item["ultima"] = banco_mod.iso(banco_mod.agora())
            item["ultimo_job"] = job.id
            item["ultimo_estado"] = "executando"
            item["proxima"] = banco_mod.iso(proxima_execucao(
                item["frequencia"], banco_mod.agora()))
            BANCO.salvar_agendamento(item)
        BANCO.auditar(usuario, "", "agendamento_executado", item["nome"],
                      f"execução {job.id}")
        return job

    def registrar_termino(self, ident, job):
        with self.trava:
            item = self.itens().get(ident)
            if not item or item.get("ultimo_job") != job.id:
                return
            item["ultimo_estado"] = job.estado
            BANCO.salvar_agendamento(item)
        if item.get("analise") and job.estado == "concluido":
            threading.Thread(target=gerar_analise, args=(job, item),
                             daemon=True).start()

    def ciclo(self):
        while True:
            time.sleep(15)
            try:
                self.verificar()
            except Exception:
                # Um agendamento com problema não pode parar os demais.
                traceback.print_exc()

    def verificar(self):
        agora = banco_mod.agora()
        for ident, item in self.itens().items():
            if not item["ativo"]:
                continue
            try:
                vencido = datetime.fromisoformat(item["proxima"]) <= agora
            except (TypeError, ValueError):
                vencido = True
            if not vencido:
                continue
            with web.JOBS_TRAVA:
                rodando = any(j.origem == f"agendamento:{ident}" and
                              j.estado == "executando"
                              for j in web.JOBS.values())
            if rodando:
                continue
            if execucoes_ativas() >= CONF.max_execucoes:
                return  # tenta de novo no próximo ciclo, sem perder a vez
            try:
                self.disparar(ident, "agendador")
                log(f"agendamento '{item['nome']}' disparado")
            except web.ErroAPI as e:
                with self.trava:
                    # Relido: uma pausa ou edição feita no meio não se perde.
                    atual = self.itens().get(ident)
                    if atual:
                        atual["ultima"] = banco_mod.iso(agora)
                        atual["ultimo_estado"] = f"erro: {e.mensagem}"[:300]
                        atual["proxima"] = banco_mod.iso(proxima_execucao(
                            atual["frequencia"], agora))
                        BANCO.salvar_agendamento(atual)
                log(f"agendamento '{item['nome']}' não disparou: {e.mensagem}")


def gerar_analise(job, item):
    try:
        ident, arquivo, resumo = analise.gerar(
            job.detalhe(), item, web.PASTA_SNAPSHOTS,
            os.path.join(CONF.dados, "analises"))
        BANCO.salvar_analise(ident, item["id"], job.id,
                             os.path.basename(arquivo), resumo)
        BANCO.auditar("agendador", "", "analise_gerada", item["nome"],
                      os.path.basename(arquivo))
        log(f"pacote de análise gerado: {os.path.basename(arquivo)}")
    except Exception:
        log("falha ao gerar o pacote de análise:")
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Execuções: autoria e histórico persistente
# ---------------------------------------------------------------------------
_pos_job_original = None


def pos_job_servidor(job):
    _pos_job_original(job)
    try:
        detalhe = job.detalhe()
        detalhe["linhas"] = detalhe["linhas"][-3000:]
        detalhe["total_linhas"] = len(detalhe["linhas"])
        BANCO.salvar_execucao(job.resumo(), detalhe,
                              getattr(job, "usuario", ""))
    except Exception:
        traceback.print_exc()


def lista_execucoes():
    with web.JOBS_TRAVA:
        memoria = {j.id: j.resumo() for j in web.JOBS.values()}
    for r in BANCO.listar_execucoes(300):
        memoria.setdefault(r["id"], r)
    return sorted(memoria.values(), key=lambda j: j["criado"], reverse=True)


# ---------------------------------------------------------------------------
# Manutenção: retenção e limpeza
# ---------------------------------------------------------------------------
def aplicar_retencao():
    import netsnap_md as md
    if CONF.ret_snapshots > 0:
        limite = time.time() - CONF.ret_snapshots * 86400
        caminhos = md.listar_snapshots(web.PASTA_SNAPSHOTS)
        # O snapshot mais recente de cada equipamento nunca é apagado, por
        # mais antigo que seja: é a última configuração conhecida.
        manter = {c for c, _ in md.mais_recentes(caminhos)}
        for c in caminhos:
            try:
                if c not in manter and os.path.getmtime(c) < limite:
                    os.remove(c)
            except OSError:
                pass
        for nome in os.listdir(web.PASTA_SNAPSHOTS):
            if nome.startswith(("_indice_", "_debug_", "_cve_triagem_",
                                "_topologia_")):
                c = os.path.join(web.PASTA_SNAPSHOTS, nome)
                try:
                    if os.path.getmtime(c) < limite:
                        os.remove(c)
                except OSError:
                    pass
    if CONF.ret_analises > 0:
        limite = banco_mod.agora() - timedelta(days=CONF.ret_analises)
        for a in BANCO.listar_analises(100000):
            if datetime.fromisoformat(a["criado"]) < limite:
                try:
                    os.remove(os.path.join(CONF.dados, "analises", a["arquivo"]))
                except OSError:
                    pass
                BANCO.remover_analise(a["id"])
    if CONF.ret_execucoes > 0:
        BANCO.limpar_execucoes(CONF.ret_execucoes)


def ciclo_manutencao():
    while True:
        try:
            BANCO.limpar_sessoes(CONF.ociosidade)
            aplicar_retencao()
        except Exception:
            traceback.print_exc()
        time.sleep(3600)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
ESTATICOS_SERVIDOR = {
    "/": ("servidor.html", "text/html; charset=utf-8"),
    "/index.html": ("servidor.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/tema.js": ("tema.js", "text/javascript; charset=utf-8"),
    "/servidor.js": ("servidor.js", "text/javascript; charset=utf-8"),
    "/servidor.css": ("servidor.css", "text/css; charset=utf-8"),
}
ROTAS_PUBLICAS = {("POST", "sessao"), ("GET", "sessao"), ("GET", "saude")}


def criar_manipulador():
    class Manipulador(web.Manipulador):
        server_version = "netsnap"

        def finish(self):
            # Uma thread por conexão: a conexão SQLite dela fecha junto, em vez
            # de esperar o coletor de lixo.
            try:
                super().finish()
            finally:
                BANCO.fechar_da_thread()

        # -- identidade da requisição -------------------------------------
        def _par(self):
            """Origem da conexão; "unix" quando chega pelo socket Unix, que só
            o Nginx/Apache (grupo www-data) e o root alcançam."""
            if isinstance(self.client_address, tuple) and self.client_address:
                return self.client_address[0]
            return "unix"

        def _ip(self):
            par = self._par()
            if par == "unix" or par in CONF.proxies:
                real = (self.headers.get("X-Real-IP") or "").strip()
                try:
                    return str(ipaddress.ip_address(real))
                except ValueError:
                    pass
            return par

        @staticmethod
        def _caminho_ca():
            return os.path.join(CONF.dados, "publico", "netsnap-ca.crt")

        def _host_valido(self):
            host = (self.headers.get("Host") or "").strip().lower()
            if host.startswith("["):
                nome = host.split("]")[0] + "]"
                nome = nome.strip("[]")
            else:
                nome = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            return nome in CONF.nomes or nome in ("127.0.0.1", "localhost",
                                                  "::1")

        def _origem_valida(self):
            origem = self.headers.get("Origin")
            return origem is None or origem in CONF.origens

        def _cookie(self, procurado):
            for parte in (self.headers.get("Cookie") or "").split(";"):
                nome, _, valor = parte.strip().partition("=")
                if nome == procurado:
                    return valor
            return ""

        def _token_cookie(self):
            return self._cookie(CONF.cookie)

        def _dispositivo_conhecido(self, u):
            return BANCO.dispositivo_valido(
                u["id"], self._cookie(CONF.cookie_dispositivo))

        def _cookie_sessao(self, token, apagar=False):
            atributos = "Path=/; HttpOnly; SameSite=Strict"
            if CONF.cookie_seguro:
                atributos += "; Secure"
            if apagar:
                return f"{CONF.cookie}=; {atributos}; Max-Age=0"
            return f"{CONF.cookie}={token}; {atributos}"

        def send_response(self, code, message=None):
            self._status = code
            super().send_response(code, message)

        def log_message(self, formato, *args):
            pass

        def _json(self, status, dados, cookie=None):
            corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            for c in ([cookie] if isinstance(cookie, str) else cookie or []):
                self.send_header("Set-Cookie", c)
            self._cabecalhos_comuns()
            self.end_headers()
            self.wfile.write(corpo)

        def do_PUT(self):
            self._despachar("PUT")

        def auditar(self, acao, alvo="", detalhe=""):
            BANCO.auditar(self.sessao["nome"] if self.sessao else "",
                          self._ip(), acao, alvo, detalhe)

        # -- despacho -------------------------------------------------------
        def _despachar(self, metodo):
            self.sessao = None
            self._status = 0
            inicio = time.monotonic()
            try:
                self._despachar_seguro(metodo)
            finally:
                caminho = urlparse(self.path).path
                if caminho.startswith("/api/") and caminho != "/api/saude":
                    log(f"{self._ip()} {self.sessao['nome'] if self.sessao else '-'}"
                        f" {metodo} {limpo(caminho)} {self._status} "
                        f"{(time.monotonic() - inicio) * 1000:.0f}ms")

        def _despachar_seguro(self, metodo):
            if not self._host_valido():
                self._json(421, {"erro": "Host não permitido"})
                return
            url = urlparse(self.path)
            caminho = url.path
            if metodo == "GET" and caminho in ESTATICOS_SERVIDOR:
                nome, tipo = ESTATICOS_SERVIDOR[caminho]
                try:
                    self._arquivo(os.path.join(web.PASTA_WEB, nome), tipo)
                except OSError:
                    self._json(404, {"erro": "Arquivo da interface ausente"})
                return
            if metodo == "GET" and caminho == "/ca.crt":
                ca = self._caminho_ca()
                if os.path.isfile(ca):
                    self._arquivo(ca, "application/x-x509-ca-cert", baixar=True)
                else:
                    self._json(404, {"erro": "Este servidor não usa CA interna"})
                return
            if not caminho.startswith("/api/"):
                self._json(404, {"erro": "Não encontrado"})
                return
            consulta = {k: v[0] for k, v in parse_qs(url.query).items()}
            partes = [unquote(p) for p in caminho[5:].strip("/").split("/")]
            rota = (metodo, partes[0] if partes else "")
            try:
                if metodo != "GET" and not self._origem_valida():
                    raise web.ErroAPI(403, "Origem não permitida")
                if rota in ROTAS_PUBLICAS and len(partes) <= 2:
                    resposta = self._rota_publica(metodo, partes)
                else:
                    self._autenticar(metodo, partes)
                    resposta = self._rota_servidor(metodo, partes, consulta)
                if resposta is not None:
                    self._json(200, resposta)
            except web.ErroAPI as e:
                self._json(e.status, {"erro": e.mensagem})
            except cofre_mod.Ocupado as e:
                self._json(503, {"erro": str(e)})
            except (banco_mod.ErroBanco, cofre_mod.ErroCofre) as e:
                self._json(400, {"erro": str(e)})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                ref = secrets.token_hex(4)
                log(f"erro interno {ref}:\n{traceback.format_exc()}")
                self._json(500, {"erro": f"Erro interno (referência {ref} "
                                         f"no log do serviço)"})

        def _autenticar(self, metodo, partes):
            self.sessao = BANCO.sessao(self._token_cookie(), CONF.ociosidade)
            if not self.sessao:
                raise web.ErroAPI(401, "Sessão expirada; entre novamente")
            if metodo != "GET":
                recebido = self.headers.get("X-Netsnap-CSRF") or ""
                if not hmac.compare_digest(recebido.encode("utf-8", "replace"),
                                           self.sessao["csrf"].encode()):
                    raise web.ErroAPI(403, "Requisição sem o token da sessão")

        def exigir(self, papel):
            if NIVEL[self.sessao["papel"]] < NIVEL[papel]:
                raise web.ErroAPI(403, "Seu perfil não permite esta ação")

        # -- login --------------------------------------------------------
        def _rota_publica(self, metodo, p):
            if p == ["saude"]:
                # Só para quem está na própria máquina, direto na porta
                # interna: pelo proxy toda conexão também vem de 127.0.0.1,
                # mas chega com o X-Real-IP que o Nginx/Apache acrescenta.
                if self._par() not in ("127.0.0.1", "::1", "unix") or \
                        self.headers.get("X-Real-IP"):
                    raise web.ErroAPI(404, "Não encontrado")
                return {"ok": True, "versao": __version__}
            if metodo == "GET" and p == ["sessao"]:
                s = BANCO.sessao(self._token_cookie(), CONF.ociosidade)
                if not s:
                    # Sem sessão não é erro aqui: é a pergunta da tela inicial.
                    # A tela de login oferece a CA interna para download.
                    return {"autenticado": False,
                            "ca_interna": os.path.isfile(self._caminho_ca())}
                return dict(self._dados_sessao(s), autenticado=True)
            if p == ["sessao"]:
                return self._login(self._corpo())
            if p == ["sessao", "etapa"]:
                return self._etapa(self._corpo())
            raise web.ErroAPI(404, "Rota não encontrada")

        def _dados_sessao(self, s):
            return {"usuario": s["nome"], "nome": s["nome_completo"],
                    "papel": s["papel"], "csrf": s["csrf"],
                    "totp": bool(s["totp_ativo"]),
                    "ociosidade_min": int(CONF.ociosidade.total_seconds() // 60)}

        def _limite_ip(self):
            ip = self._ip()
            if not LIMITE_LOGIN_IP.permitido(chave_ip(ip)):
                BANCO.auditar("", ip, "login_limite_ip")
                raise web.ErroAPI(429, "Muitas tentativas deste endereço; "
                                       "aguarde alguns minutos")
            return ip

        def _registrar_erro(self, u, ip, motivo):
            par = BLOQUEIOS.falhou(u["id"], ip)
            _, conta = BANCO.registrar_falha(u["id"])
            BANCO.auditar(u["nome"], ip, "login_falha", "", motivo +
                          (", origem bloqueada" if par else "") +
                          (f", conta bloqueada até {conta}" if conta else ""))

        def _login(self, dados):
            ip = self._limite_ip()
            nome = str(dados.get("usuario") or "")[:64]
            senha = str(dados.get("senha") or "")[:256]
            u = BANCO.usuario(nome=nome)
            try:
                if not u or not u["ativo"]:
                    cofre_mod.gastar_tempo_como_login(senha)
                    BANCO.auditar(nome.lower(), ip, "login_falha", "",
                                  "usuário inexistente ou desativado")
                    raise web.ErroAPI(401, MSG_LOGIN)
                conta_bloqueada = banco_mod.Banco.bloqueado(u) and \
                    not self._dispositivo_conhecido(u)
                if conta_bloqueada or BLOQUEIOS.bloqueado(u["id"], ip):
                    cofre_mod.gastar_tempo_como_login(senha)
                    BANCO.auditar(u["nome"], ip, "login_falha", "",
                                  "conta ou origem bloqueada")
                    raise web.ErroAPI(401, MSG_LOGIN)
                if not BANCO.conferir_senha(u, senha):
                    self._registrar_erro(u, ip, "senha incorreta")
                    raise web.ErroAPI(401, MSG_LOGIN)
            except cofre_mod.Ocupado as e:
                raise web.ErroAPI(503, str(e))
            return self._proxima_etapa(u, senha_ok=True)

        def _proxima_etapa(self, u, extra=None, senha_ok=False, totp_ok=False,
                           totp_cadastrado=False, senha_trocada=False):
            """Decide o que falta para abrir a sessão.

            `extra` (códigos de recuperação, avisos) segue na resposta da
            próxima etapa, qualquer que seja ela, para aparecer uma vez só."""
            estado = dict(senha_ok=senha_ok, totp_ok=totp_ok,
                          totp_cadastrado=totp_cadastrado,
                          senha_trocada=senha_trocada)
            extra = extra or {}
            if u["totp_ativo"] and not totp_ok:
                return dict(extra, etapa="totp",
                            desafio=DESAFIOS.criar(u["id"], "totp", **estado))
            if not u["totp_ativo"] and CONF.exigir_totp and not totp_cadastrado:
                segredo = cofre_mod.novo_segredo_totp()
                uri = cofre_mod.uri_totp(segredo, u["nome"], CONF.emissor)
                return dict(extra, etapa="cadastrar_totp", segredo=segredo,
                            uri=uri, qr_svg=qr_svg(uri),
                            desafio=DESAFIOS.criar(u["id"], "cadastrar_totp",
                                                   segredo=segredo, **estado))
            if u["trocar_senha"] and not senha_trocada:
                return dict(extra, etapa="trocar_senha",
                            desafio=DESAFIOS.criar(u["id"], "trocar_senha",
                                                   **estado))
            return self._abrir_sessao(u, extra)

        def _abrir_sessao(self, u, extra):
            BANCO.registrar_login(u["id"])
            BLOQUEIOS.limpar(u["id"], self._ip())
            token, _ = BANCO.criar_sessao(
                u["id"], self._ip(), self.headers.get("User-Agent", ""),
                CONF.duracao)
            BANCO.auditar(u["nome"], self._ip(), "login_ok")
            s = BANCO.sessao(token, CONF.ociosidade)
            cookies = [self._cookie_sessao(token)]
            if not self._dispositivo_conhecido(u):
                atributos = "Path=/; HttpOnly; SameSite=Strict" + \
                    ("; Secure" if CONF.cookie_seguro else "")
                cookies.append(f"{CONF.cookie_dispositivo}="
                               f"{BANCO.criar_dispositivo(u['id'])}; {atributos}; "
                               f"Max-Age={VALIDADE_COOKIE_DISPOSITIVO}")
            self._json(200, dict(extra, etapa="ok", **self._dados_sessao(s)),
                       cookie=cookies)
            return None

        def _etapa(self, dados):
            ip = self._limite_ip()
            token = str(dados.get("desafio") or "")
            d = DESAFIOS.consumir(token)
            if not d:
                raise web.ErroAPI(401, "Etapa expirada ou tentativas "
                                       "esgotadas; entre novamente")
            u = BANCO.usuario(d["uid"])
            if not u or not u["ativo"] or BLOQUEIOS.bloqueado(u["id"], ip) or \
                    (banco_mod.Banco.bloqueado(u) and
                     not self._dispositivo_conhecido(u)):
                DESAFIOS.descartar(token)
                raise web.ErroAPI(401, MSG_LOGIN)
            estado = {k: d[k] for k in ("senha_ok", "totp_ok",
                                        "totp_cadastrado", "senha_trocada")}
            etapa = d["etapa"]

            if etapa == "totp":
                codigo = str(dados.get("codigo") or "").strip()
                contador = cofre_mod.conferir_totp(
                    BANCO.segredo_totp(u), codigo, u["totp_ultimo"])
                if contador is not None and BANCO.avancar_totp(u["id"],
                                                               contador):
                    DESAFIOS.descartar(token)
                    estado["totp_ok"] = True
                    return self._proxima_etapa(BANCO.usuario(u["id"]),
                                               **estado)
                restantes = BANCO.usar_codigo_recuperacao(u["id"], codigo) \
                    if len(cofre_mod.normalizar_codigo_recuperacao(codigo)) \
                    == 12 else None
                if restantes is not None:
                    DESAFIOS.descartar(token)
                    BANCO.auditar(u["nome"], ip, "recuperacao_usada", "",
                                  f"restam {restantes}")
                    estado["totp_ok"] = True
                    return self._proxima_etapa(
                        BANCO.usuario(u["id"]),
                        {"aviso": f"Código de recuperação usado; restam "
                                  f"{restantes}. Gere novos em Minha conta."},
                        **estado)
                self._falha_etapa(token, u, ip, "código TOTP inválido")

            if etapa == "cadastrar_totp":
                if u["totp_ativo"]:
                    # Desafio antigo depois de outro cadastro concluído.
                    DESAFIOS.descartar(token)
                    raise web.ErroAPI(401, "Etapa expirada; entre novamente")
                codigo = str(dados.get("codigo") or "")
                contador = cofre_mod.conferir_totp(d["segredo"], codigo, 0)
                if contador is None:
                    self._falha_etapa(token, u, ip, "código do cadastro TOTP "
                                                    "inválido")
                DESAFIOS.descartar(token)
                codigos = BANCO.ativar_totp(u["id"], d["segredo"], contador)
                BANCO.auditar(u["nome"], ip, "totp_cadastrado")
                estado.update(totp_ok=True, totp_cadastrado=True)
                return self._proxima_etapa(BANCO.usuario(u["id"]),
                                           {"codigos_recuperacao": codigos},
                                           **estado)

            if etapa == "trocar_senha":
                nova = str(dados.get("nova_senha") or "")
                if BANCO.conferir_senha(u, nova):
                    raise web.ErroAPI(400, "A nova senha deve ser diferente "
                                           "da atual")
                BANCO.trocar_senha(u["id"], nova)
                DESAFIOS.descartar(token)
                BANCO.encerrar_sessoes_do_usuario(u["id"])
                BANCO.auditar(u["nome"], ip, "senha_trocada", "",
                              "troca obrigatória no login")
                estado["senha_trocada"] = True
                return self._proxima_etapa(BANCO.usuario(u["id"]), **estado)
            raise web.ErroAPI(400, "Etapa desconhecida")

        def _falha_etapa(self, token, u, ip, motivo):
            self._registrar_erro(u, ip, motivo)
            raise web.ErroAPI(401, "Código inválido")

        # -- rotas autenticadas -------------------------------------------
        def _rota_servidor(self, metodo, p, q):
            s = self.sessao
            n = len(p)
            raiz = p[0] if p else ""

            if raiz == "sessao" and metodo == "DELETE":
                BANCO.encerrar_sessao(self._token_cookie())
                self.auditar("logout")
                self._json(200, {"ok": True},
                           cookie=self._cookie_sessao("", apagar=True))
                return None

            if raiz == "conta":
                return self._rota_conta(metodo, p)
            if raiz == "usuarios":
                self.exigir("admin")
                return self._rota_usuarios(metodo, p)
            if raiz == "auditoria":
                self.exigir("admin")
                if q.get("verificar") == "1":
                    ok, primeiro = BANCO.verificar_auditoria()
                    return {"integra": ok, "primeiro_invalido": primeiro}
                return BANCO.listar_auditoria(q.get("limite", 500),
                                              q.get("usuario") or None,
                                              q.get("acao") or None)
            if raiz == "cofre":
                return self._rota_cofre(metodo, p)
            if raiz == "agendamentos":
                return self._rota_agendamentos(metodo, p)
            if raiz == "analises":
                return self._rota_analises(metodo, p)

            # Rotas herdadas do painel local, com as regras do servidor.
            if metodo != "GET":
                self.exigir("tecnico")
            if raiz == "info":
                info = web.Manipulador._rota(self, metodo, p, q)
                info.update(modo="servidor", servidor=__version__,
                            usuario=self._dados_sessao(s),
                            permitir_sensivel=CONF.permitir_sensivel and
                            s["papel"] == "admin",
                            permitir_telnet=CONF.permitir_telnet,
                            ca_interna=os.path.isfile(self._caminho_ca()))
                info.pop("pastas", None)
                return info
            if raiz == "painel":
                d = web.painel()
                d["jobs"] = lista_execucoes()[:10]
                d["pastas"] = {"snapshots": "o servidor"}
                return d
            if raiz == "jobs" and metodo == "GET":
                if n == 1:
                    return lista_execucoes()
                if n == 2 and p[1] not in web.JOBS:
                    d = BANCO.execucao(p[1])
                    if not d:
                        raise web.ErroAPI(404, "Execução não encontrada")
                    desde = web.inteiro_valido(q.get("desde"), 0, 0, 10 ** 9,
                                               "desde")
                    d["linhas"] = d["linhas"][desde:]
                    return d
            if raiz in ("coletas", "netdiag") and metodo == "POST":
                return self._nova_execucao(raiz, self._corpo())
            if raiz == "netcve" and metodo == "POST":
                cfg = self._corpo()
                with TRAVA_EXECUCOES:
                    self._checar_limite()
                    job = web.novo_netcve(cfg)
                self._marcar(job)
                self.auditar("netcve_iniciado", job.id)
                return job.resumo()
            if raiz == "jobs" and n == 3 and p[2] == "cancelar":
                self.auditar("execucao_cancelada", p[1])
            if raiz == "arquivo" and q.get("baixar") == "1":
                self.auditar("arquivo_baixado", "/".join(p[1:])[:200])
            self._checar_snapshots_sensiveis(metodo, p, q)
            return web.Manipulador._rota(self, metodo, p, q)

        def _checar_snapshots_sensiveis(self, metodo, p, q):
            """Snapshot coletado com segredos (só admin, com a opção ligada,
            consegue gerar) só é lido por admin, e toda leitura fica na
            auditoria, não apenas o download."""
            if metodo != "GET":
                return
            import netsnap_md as md
            nomes = []
            if p[0] == "snapshots" and len(p) == 2:
                nomes = [p[1]]
            elif p[0] == "arquivo" and len(p) == 3 and p[1] == "snapshot":
                nomes = [p[2]]
            elif p[0] == "comparar":
                nomes = [q.get("a", ""), q.get("b", "")]
            for nome in nomes:
                caminho = web.caminho_snapshot(nome)
                if md.ler_metadados(caminho).get("sensitive_data") != "included":
                    continue
                if self.sessao["papel"] != "admin":
                    self.auditar("snapshot_sensivel_negado", nome[:200])
                    raise web.ErroAPI(403, "Snapshot com dados sensíveis: "
                                           "só administradores")
                self.auditar("snapshot_sensivel_lido", nome[:200])

        def _checar_limite(self):
            if execucoes_ativas() >= CONF.max_execucoes:
                raise web.ErroAPI(429, f"Já há {CONF.max_execucoes} execuções "
                                       "em andamento; aguarde uma terminar")

        def _marcar(self, job):
            job.usuario = self.sessao["nome"]
            job.config["iniciado_por"] = self.sessao["nome"]

        def _nova_execucao(self, tipo, cfg):
            cfg.pop("credencial_nome", None)
            cfg.pop("salvar_como", None)
            if cfg.get("protocolo") == "telnet" and not CONF.permitir_telnet:
                raise web.ErroAPI(403, "Telnet desativado neste servidor")
            if not (CONF.permitir_sensivel and self.sessao["papel"] == "admin"):
                cfg["sensivel"] = False
            limite = web.LIMITE_ALVOS if tipo == "coletas" else LIMITE_NETDIAG
            if tipo == "netdiag":
                linhas = [l for l in str(cfg.get("alvos", "")).splitlines()
                          if l.split("#", 1)[0].strip()]
                if web.contar_alvos(linhas) > LIMITE_NETDIAG:
                    raise web.ErroAPI(400, f"O diagnóstico aceita até "
                                           f"{LIMITE_NETDIAG} equipamentos")
            cid = cfg.get("credencial")
            if cid not in (None, "", 0, "0"):
                preparar_credencial(cfg, cid, limite)
            else:
                cfg.pop("credencial", None)
                cfg["alvos"] = resolver_alvos(
                    cfg.get("alvos", ""),
                    web.porta_valida(cfg.get("porta"),
                                     23 if cfg.get("protocolo") == "telnet" else 22),
                    None, None, limite)
            with TRAVA_EXECUCOES:
                self._checar_limite()
                job = (web.nova_coleta(cfg) if tipo == "coletas"
                       else web.novo_netdiag(cfg))
            self._marcar(job)
            self.auditar("coleta_iniciada" if tipo == "coletas"
                         else "netdiag_iniciado", job.id,
                         f"credencial {cid}" if cfg.get("credencial") else
                         "credencial digitada")
            return job.resumo()

        # -- conta própria ------------------------------------------------
        def _rota_conta(self, metodo, p):
            s = self.sessao
            u = BANCO.usuario(s["usuario_id"])
            if metodo == "GET" and p == ["conta"]:
                return {"usuario": u["nome"], "nome": u["nome_completo"],
                        "papel": u["papel"], "totp": bool(u["totp_ativo"]),
                        "codigos_restantes": len(json.loads(u["recuperacao"])),
                        "ultimo_login": u["ultimo_login"],
                        "senha_alterada": u["senha_alterada"],
                        "sessoes": len(BANCO.consultar(
                            "SELECT 1 FROM sessoes WHERE usuario_id = ?",
                            (u["id"],)))}
            dados = self._corpo()
            if metodo == "POST" and p == ["conta", "senha"]:
                if not BANCO.conferir_senha(u, str(dados.get("atual") or "")):
                    self._registrar_erro(u, self._ip(), "senha atual incorreta "
                                                        "na troca de senha")
                    raise web.ErroAPI(403, "Senha atual incorreta")
                BANCO.trocar_senha(u["id"], str(dados.get("nova") or ""))
                BANCO.encerrar_sessoes_do_usuario(u["id"], self._token_cookie())
                self.auditar("senha_trocada")
                return {"ok": True}
            if metodo == "POST" and p == ["conta", "sair-de-todas"]:
                BANCO.encerrar_sessoes_do_usuario(u["id"], self._token_cookie())
                self.auditar("sessoes_encerradas")
                return {"ok": True}
            if metodo == "POST" and p == ["conta", "codigos"]:
                # Novos códigos de recuperação exigem senha e código atual.
                if not u["totp_ativo"]:
                    raise web.ErroAPI(409, "A verificação em duas etapas não "
                                           "está ativa nesta conta")
                senha_ok = BANCO.conferir_senha(u, str(dados.get("senha") or ""))
                contador = cofre_mod.conferir_totp(
                    BANCO.segredo_totp(u), str(dados.get("codigo") or ""),
                    u["totp_ultimo"])
                # Mesma resposta para senha ou código errados, e a falha conta:
                # uma sessão aberta e esquecida não vira oráculo de senha.
                if not senha_ok or contador is None or \
                        not BANCO.avancar_totp(u["id"], contador):
                    self._registrar_erro(u, self._ip(), "senha ou código "
                                                        "inválidos em Minha conta")
                    raise web.ErroAPI(403, "Senha ou código inválidos")
                codigos = BANCO.ativar_totp(u["id"], BANCO.segredo_totp(u),
                                            contador)
                self.auditar("codigos_recuperacao_gerados")
                return {"codigos_recuperacao": codigos}
            raise web.ErroAPI(404, "Rota não encontrada")

        # -- usuários (admin) ---------------------------------------------
        def _rota_usuarios(self, metodo, p):
            if metodo == "GET" and len(p) == 1:
                return BANCO.listar_usuarios()
            if metodo == "POST" and len(p) == 1:
                d = self._corpo()
                uid = BANCO.criar_usuario(d.get("usuario"), str(d.get("senha") or ""),
                                          d.get("papel"), d.get("nome") or "",
                                          trocar_senha=True)
                self.auditar("usuario_criado", d.get("usuario"),
                             f"papel {d.get('papel')}")
                return {"id": uid}
            if len(p) < 2:
                raise web.ErroAPI(404, "Rota não encontrada")
            try:
                uid = int(p[1])
            except ValueError:
                raise web.ErroAPI(404, "Usuário não encontrado")
            alvo = BANCO.usuario(uid)
            if not alvo:
                raise web.ErroAPI(404, "Usuário não encontrado")
            proprio = uid == self.sessao["usuario_id"]
            ultimo_admin = (alvo["papel"] == "admin" and alvo["ativo"] and
                            BANCO.admins_ativos() <= 1)
            if metodo == "DELETE" and len(p) == 2:
                if proprio or ultimo_admin:
                    raise web.ErroAPI(409, "Não é possível remover a própria "
                                           "conta nem o último administrador")
                BANCO.remover_usuario(uid)
                self.auditar("usuario_removido", alvo["nome"])
                return {"ok": True}
            if metodo == "POST" and len(p) == 3:
                acao, d = p[2], self._corpo()
                if acao == "alterar":
                    campos = {k: d[k] for k in ("papel", "ativo", "nome_completo")
                              if k in d}
                    if "ativo" in campos:
                        if not isinstance(campos["ativo"], (bool, int)):
                            raise web.ErroAPI(400, "ativo deve ser verdadeiro "
                                                   "ou falso")
                        campos["ativo"] = bool(campos["ativo"])
                    rebaixa = (campos.get("papel", "admin") != "admin" or
                               not campos.get("ativo", True))
                    if ultimo_admin and rebaixa:
                        raise web.ErroAPI(409, "O último administrador ativo "
                                               "não pode ser rebaixado nem "
                                               "desativado")
                    if proprio and rebaixa:
                        raise web.ErroAPI(409, "Peça a outro administrador "
                                               "para alterar o seu perfil")
                    BANCO.alterar_usuario(uid, **campos)
                    if "ativo" in campos or "papel" in campos:
                        BANCO.encerrar_sessoes_do_usuario(uid)
                    self.auditar("usuario_alterado", alvo["nome"],
                                 json.dumps(campos, ensure_ascii=False))
                    return {"ok": True}
                if acao == "senha":
                    if proprio:
                        raise web.ErroAPI(409, "Troque a própria senha em "
                                               "Minha conta")
                    BANCO.trocar_senha(uid, str(d.get("senha") or ""),
                                       exigir_troca=True)
                    BANCO.encerrar_sessoes_do_usuario(uid)
                    # Redefinição pelo admin costuma indicar suspeita: o
                    # navegador antigo deixa de contornar o bloqueio da conta.
                    BANCO.remover_dispositivos(uid)
                    self.auditar("usuario_senha_redefinida", alvo["nome"])
                    return {"ok": True}
                if acao == "totp":
                    BANCO.resetar_totp(uid)
                    self.auditar("usuario_totp_resetado", alvo["nome"])
                    return {"ok": True}
                if acao == "desbloquear":
                    BANCO.desbloquear(uid)
                    BLOQUEIOS.limpar(uid)
                    self.auditar("usuario_desbloqueado", alvo["nome"])
                    return {"ok": True}
            raise web.ErroAPI(404, "Rota não encontrada")

        # -- cofre de credenciais -----------------------------------------
        def _rota_cofre(self, metodo, p):
            self.exigir("tecnico")
            if metodo == "GET" and len(p) == 1:
                return BANCO.listar_credenciais()
            if metodo == "POST" and len(p) == 1:
                d = self._corpo()
                telnet = bool(d.get("telnet"))
                if telnet and self.sessao["papel"] != "admin":
                    raise web.ErroAPI(403, "Só um administrador libera Telnet "
                                           "numa credencial")
                cid = BANCO.criar_credencial(
                    d.get("nome"), str(d.get("usuario") or "").strip(),
                    str(d.get("senha") or ""), str(d.get("descricao") or ""),
                    self.sessao["nome"], self.sessao["usuario_id"],
                    d.get("redes"), telnet)
                self.auditar("credencial_criada", d.get("nome"),
                             f"redes {d.get('redes')}" + (", telnet" if telnet
                                                          else ""))
                return {"id": cid}
            if len(p) == 2:
                try:
                    cid = int(p[1])
                except ValueError:
                    raise web.ErroAPI(404, "Credencial não encontrada")
                cred = BANCO.credencial(cid)
                if not cred:
                    raise web.ErroAPI(404, "Credencial não encontrada")
                admin = self.sessao["papel"] == "admin"
                if not admin and cred["criado_por_id"] != self.sessao["usuario_id"]:
                    raise web.ErroAPI(403, "Só o autor da credencial ou um "
                                           "administrador pode alterá-la")
                if metodo == "POST":
                    d = self._corpo()
                    redes = d.get("redes")
                    telnet = d.get("telnet")
                    atual = BANCO.segredo_credencial(cid)
                    if redes is not None and not admin and \
                            BANCO.normalizar_redes(redes) != atual["redes"]:
                        raise web.ErroAPI(403, "Só um administrador muda as "
                                               "redes de uma credencial")
                    if telnet is not None and not admin and \
                            bool(telnet) != atual["telnet"]:
                        raise web.ErroAPI(403, "Só um administrador libera ou "
                                               "bloqueia Telnet numa credencial")
                    descricao = d.get("descricao")
                    BANCO.atualizar_credencial(
                        cid, str(d.get("usuario") or "").strip() or None,
                        str(d.get("senha") or "") or None,
                        None if descricao is None else str(descricao),
                        redes, telnet)
                    self.auditar("credencial_alterada", cred["nome"],
                                 ", ".join(x for x in (
                                     "senha trocada" if d.get("senha") else "",
                                     f"redes {redes}" if redes is not None else "",
                                     f"telnet {bool(telnet)}" if telnet is not None
                                     else "") if x))
                    return {"ok": True}
                if metodo == "DELETE":
                    BANCO.remover_credencial(cid)
                    self.auditar("credencial_removida", cred["nome"])
                    return {"ok": True}
            raise web.ErroAPI(404, "Rota não encontrada")

        # -- agendamentos -------------------------------------------------
        def _rota_agendamentos(self, metodo, p):
            if metodo == "GET" and len(p) == 1:
                return AGENDA.listar()
            self.exigir("tecnico")
            if metodo == "POST" and len(p) == 1:
                item = AGENDA.criar(self._corpo(), self.sessao["nome"])
                self.auditar("agendamento_criado", item["nome"],
                             texto_frequencia(item["frequencia"]))
                return AGENDA.publico(item)
            if len(p) < 2:
                raise web.ErroAPI(404, "Rota não encontrada")
            item = AGENDA.obter(p[1])
            if metodo == "DELETE" and len(p) == 2:
                AGENDA.remover(item["id"])
                self.auditar("agendamento_removido", item["nome"])
                return {"removido": item["id"]}
            if metodo == "POST" and len(p) == 2:
                novo = AGENDA.atualizar(item["id"], self._corpo())
                self.auditar("agendamento_alterado", novo["nome"],
                             texto_frequencia(novo["frequencia"]))
                return AGENDA.publico(novo)
            if metodo == "POST" and len(p) == 3:
                acao = p[2]
                if acao in ("ativar", "pausar"):
                    novo = AGENDA.alternar(item["id"], acao == "ativar")
                    self.auditar(f"agendamento_{'ativado' if acao == 'ativar' else 'pausado'}",
                                 item["nome"])
                    return AGENDA.publico(novo)
                if acao == "executar":
                    return AGENDA.disparar(item["id"],
                                           self.sessao["nome"]).resumo()
            raise web.ErroAPI(404, "Rota não encontrada")

        # -- pacotes de análise -------------------------------------------
        def _rota_analises(self, metodo, p):
            if metodo == "GET" and len(p) == 1:
                return BANCO.listar_analises()
            if len(p) < 2:
                raise web.ErroAPI(404, "Rota não encontrada")
            a = BANCO.analise(p[1])
            if not a:
                raise web.ErroAPI(404, "Pacote não encontrado")
            caminho = os.path.join(CONF.dados, "analises", a["arquivo"])
            if metodo == "GET" and len(p) == 2:
                return a
            if metodo == "GET" and len(p) == 3 and p[2] == "baixar":
                if not os.path.isfile(caminho):
                    raise web.ErroAPI(410, "Arquivo removido pela retenção")
                self.auditar("analise_baixada", a["arquivo"])
                self._arquivo(caminho, "application/zip", baixar=True)
                return None
            if metodo == "DELETE" and len(p) == 2:
                self.exigir("admin")
                try:
                    os.remove(caminho)
                except OSError:
                    pass
                BANCO.remover_analise(a["id"])
                self.auditar("analise_removida", a["arquivo"])
                return {"ok": True}
            raise web.ErroAPI(404, "Rota não encontrada")

    return Manipulador


# ---------------------------------------------------------------------------
# Inicialização
# ---------------------------------------------------------------------------
def iniciar(caminho_config):
    """Carrega configuração, chave, banco e o painel. Usado também pelo
    netsnapctl e pelos testes."""
    global web, analise, CONF, COFRE, BANCO, AGENDA, _pos_job_original
    CONF = Config(caminho_config)
    os.makedirs(CONF.dados, mode=0o700, exist_ok=True)
    for sub in ("analises", "publico"):
        os.makedirs(os.path.join(CONF.dados, sub), mode=0o700, exist_ok=True)
    os.environ["NETSNAP_DADOS"] = CONF.dados
    COFRE = cofre_mod.Cofre(cofre_mod.carregar_chave_mestra(CONF.arquivo_chave))
    # Os processos de coleta herdam o ambiente: não precisam saber onde o
    # systemd guardou a chave-mestra.
    os.environ.pop("CREDENTIALS_DIRECTORY", None)
    BANCO = banco_mod.Banco(CONF.banco, COFRE)
    auditar_banco = BANCO.auditar

    def auditar_com_espelho(usuario, ip, acao, alvo="", detalhe=""):
        # Cópia de cada registro no journald: se o banco inteiro for trocado,
        # o log do sistema ainda guarda a sequência original.
        ident, h = auditar_banco(usuario, ip, acao, alvo, detalhe)
        log(f"auditoria #{ident} {limpo(acao, 40)} usuario={limpo(usuario or '-', 64)} "
            f"ip={limpo(ip or '-', 64)} hash={h[:16]}")
        return ident, h
    BANCO.auditar = auditar_com_espelho
    import netsnap_web
    import netsnap_analise
    web, analise = netsnap_web, netsnap_analise
    AGENDA = AgendaServidor()
    web.AGENDA = AGENDA
    _pos_job_original = web.pos_job
    web.pos_job = pos_job_servidor
    return CONF


class ServidorUnix(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def criar_servidor_http():
    """Socket entregue pelo systemd (netsnap-servidor.socket: socket Unix só
    para o grupo do Nginx/Apache) ou, sem ele, TCP em 127.0.0.1 (testes)."""
    manipulador = criar_manipulador()
    herdados = 0
    if os.environ.get("LISTEN_PID") == str(os.getpid()):
        herdados = int(os.environ.get("LISTEN_FDS", "0") or 0)
    for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(var, None)
    if herdados >= 1:
        sock = socket.socket(fileno=3)
        if sock.family == socket.AF_UNIX:
            servidor = ServidorUnix(sock.getsockname(), manipulador,
                                    bind_and_activate=False)
        else:
            servidor = ThreadingHTTPServer(sock.getsockname()[:2], manipulador,
                                           bind_and_activate=False)
            servidor.daemon_threads = True
        servidor.socket.close()
        servidor.socket = sock
        return servidor, f"socket do systemd {sock.getsockname()}"
    if not CONF.tcp_para_testes:
        raise SystemExit(
            "[ERRO] sem o socket do systemd (netsnap-servidor.socket). Inicie "
            "com 'systemctl start netsnap-servidor'; para testes locais em TCP, "
            "use tcp_para_testes = sim em [servidor]")
    familia = ThreadingHTTPServer
    if ":" in CONF.endereco:
        class Servidor6(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        familia = Servidor6
    servidor = familia((CONF.endereco, CONF.porta), manipulador)
    servidor.daemon_threads = True
    return servidor, f"{CONF.endereco}:{CONF.porta}"


def main():
    ap = argparse.ArgumentParser(description="Servidor do netsnap")
    ap.add_argument("--config", default="/etc/netsnap/servidor.conf")
    ap.add_argument("-v", "--version", action="version",
                    version=f"netsnap_servidor {__version__}")
    args = ap.parse_args()
    os.umask(0o077)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    try:
        iniciar(args.config)
    except (cofre_mod.ErroCofre, banco_mod.ErroBanco) as e:
        raise SystemExit(f"[ERRO] {e}")
    if not web.CAPACIDADES["coleta"]:
        log(f"[!] coleta indisponível: {web.CAPACIDADES['motivo']}")
    if not BANCO.admins_ativos():
        log("[!] nenhum administrador: crie com 'netsnapctl usuario criar'")

    servidor, onde = criar_servidor_http()
    threading.Thread(target=AGENDA.ciclo, daemon=True).start()
    threading.Thread(target=ciclo_manutencao, daemon=True).start()
    log(f"netsnap_servidor {__version__} em {onde} "
        f"(nomes: {', '.join(CONF.nomes)}; dados: {CONF.dados})")

    import signal

    def ao_terminar(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, ao_terminar)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        log("encerrando")
    finally:
        for job in list(web.JOBS.values()):
            if job.estado == "executando" and job.proc:
                job.cancelado = True
                job.proc.terminate()
        servidor.server_close()


if __name__ == "__main__":
    main()
