#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_banco — persistência do servidor netsnap (SQLite)

Usuários, sessões, cofre de credenciais, agendamentos, histórico de execuções,
pacotes de análise e trilha de auditoria. Todo campo secreto chega aqui já
pronto para cifrar e sai decifrado só para quem precisa dele; o arquivo do
banco, copiado sozinho, não revela senha de equipamento nem permite testar
senhas de usuário offline.

A auditoria é encadeada: cada registro leva um HMAC do anterior, então apagar
ou editar uma linha no meio da trilha é detectado por `verificar_auditoria`.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta

import netsnap_cofre as cofre_mod

VERSAO_ESQUEMA = 1
PAPEIS = ("admin", "tecnico", "leitura")
NOME_USUARIO = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
# Bloqueio da conta (todas as origens): alto, para que um atacante não consiga
# trancar os administradores errando a senha de propósito. O bloqueio rápido
# (5 erros) é por conta + IP, em memória, no netsnap_servidor.
MAX_FALHAS_CONTA = 30
BLOQUEIO_CONTA_MIN = 15
# Rede mais ampla aceita numa credencial: /0 anularia a proteção.
PREFIXO_MINIMO = {4: 8, 6: 32}

ESQUEMA = """
CREATE TABLE IF NOT EXISTS meta (
    chave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY,
    nome TEXT NOT NULL UNIQUE,
    nome_completo TEXT NOT NULL DEFAULT '',
    papel TEXT NOT NULL CHECK (papel IN ('admin', 'tecnico', 'leitura')),
    hash_cifrado TEXT NOT NULL,
    totp_cifrado TEXT,
    totp_ativo INTEGER NOT NULL DEFAULT 0,
    totp_ultimo INTEGER NOT NULL DEFAULT 0,
    recuperacao TEXT NOT NULL DEFAULT '[]',
    trocar_senha INTEGER NOT NULL DEFAULT 1,
    ativo INTEGER NOT NULL DEFAULT 1,
    falhas INTEGER NOT NULL DEFAULT 0,
    bloqueado_ate TEXT,
    criado TEXT NOT NULL,
    ultimo_login TEXT,
    senha_alterada TEXT
);
CREATE TABLE IF NOT EXISTS sessoes (
    id_hash TEXT PRIMARY KEY,
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    criada TEXT NOT NULL,
    ultimo_uso TEXT NOT NULL,
    expira TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    agente TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessoes_usuario ON sessoes(usuario_id);
CREATE TABLE IF NOT EXISTS dispositivos (
    id_hash TEXT PRIMARY KEY,
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    criado TEXT NOT NULL,
    ultimo_uso TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credenciais (
    id INTEGER PRIMARY KEY,
    nome TEXT NOT NULL UNIQUE,
    descricao TEXT NOT NULL DEFAULT '',
    segredo_cifrado TEXT NOT NULL,
    criado_por TEXT NOT NULL,
    criado_por_id INTEGER,
    criado TEXT NOT NULL,
    atualizado TEXT NOT NULL,
    ultimo_uso TEXT
);
CREATE TABLE IF NOT EXISTS agendamentos (
    id TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    dados TEXT NOT NULL,
    ativo INTEGER NOT NULL DEFAULT 1,
    proxima TEXT,
    ultima TEXT,
    ultimo_job TEXT,
    ultimo_estado TEXT,
    criado_por TEXT NOT NULL,
    criado TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execucoes (
    id TEXT PRIMARY KEY,
    tipo TEXT NOT NULL,
    titulo TEXT NOT NULL,
    origem TEXT NOT NULL,
    estado TEXT NOT NULL,
    criado TEXT NOT NULL,
    terminado TEXT,
    usuario TEXT NOT NULL DEFAULT '',
    resumo TEXT NOT NULL,
    detalhe TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS execucoes_criado ON execucoes(criado);
CREATE TABLE IF NOT EXISTS analises (
    id TEXT PRIMARY KEY,
    agendamento_id TEXT,
    job_id TEXT NOT NULL,
    criado TEXT NOT NULL,
    arquivo TEXT NOT NULL,
    resumo TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY,
    quando TEXT NOT NULL,
    usuario TEXT NOT NULL,
    ip TEXT NOT NULL,
    acao TEXT NOT NULL,
    alvo TEXT NOT NULL,
    detalhe TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


def agora():
    return datetime.now().replace(microsecond=0)


def iso(dt):
    return dt.isoformat(timespec="seconds") if dt else None


class ErroBanco(Exception):
    pass


class Banco:
    def __init__(self, caminho, cofre):
        self.caminho = caminho
        self.cofre = cofre
        self._local = threading.local()
        self._trava_auditoria = threading.Lock()
        # executescript confirma qualquer transação aberta: roda antes.
        self._con().executescript(ESQUEMA)
        colunas = {r[1] for r in self._con().execute(
            "PRAGMA table_info(credenciais)")}
        if "criado_por_id" not in colunas:
            self._con().execute("ALTER TABLE credenciais ADD COLUMN "
                                "criado_por_id INTEGER")
        with self.transacao() as c:
            versao = self._meta(c, "versao_esquema")
            if versao is None:
                c.execute("INSERT INTO meta VALUES ('versao_esquema', ?)",
                          (str(VERSAO_ESQUEMA),))
                c.execute("INSERT INTO meta VALUES ('impressao_chave', ?)",
                          (cofre.impressao(),))
                c.execute("INSERT INTO meta VALUES ('auditoria_ancora', ?)",
                          (self._ancora(0, ""),))
            elif int(versao) > VERSAO_ESQUEMA:
                raise ErroBanco("banco criado por versão mais nova do servidor")
            if self._meta(c, "impressao_chave") != cofre.impressao():
                raise ErroBanco(
                    "a chave-mestra carregada não é a que criou este banco. "
                    "Se o servidor foi reinstalado, importe a cópia da chave "
                    "com 'netsnapctl chave importar'")

    # -- conexão ----------------------------------------------------------
    def _con(self):
        c = getattr(self._local, "con", None)
        if c is None:
            novo = not os.path.exists(self.caminho)
            c = sqlite3.connect(self.caminho, timeout=10,
                                isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=10000")
            c.execute("PRAGMA secure_delete=ON")
            if novo and os.name == "posix":
                os.chmod(self.caminho, 0o600)
            self._local.con = c
        return c

    def fechar_da_thread(self):
        """Fecha a conexão da thread atual (a próxima chamada abre outra)."""
        c = getattr(self._local, "con", None)
        if c is not None:
            self._local.con = None
            c.close()

    @contextmanager
    def transacao(self):
        c = self._con()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except BaseException:
            if c.in_transaction:
                c.execute("ROLLBACK")
            raise

    def consultar(self, sql, args=()):
        return [dict(r) for r in self._con().execute(sql, args).fetchall()]

    def um(self, sql, args=()):
        r = self._con().execute(sql, args).fetchone()
        return dict(r) if r else None

    @staticmethod
    def _meta(c, chave):
        r = c.execute("SELECT valor FROM meta WHERE chave = ?",
                      (chave,)).fetchone()
        return r[0] if r else None

    # -- usuários ---------------------------------------------------------
    def criar_usuario(self, nome, senha, papel, nome_completo="",
                      trocar_senha=True):
        nome = (nome or "").strip().lower()
        if not NOME_USUARIO.match(nome):
            raise ErroBanco("nome de usuário: 2 a 32 caracteres, letras "
                            "minúsculas, números, ponto, hífen ou sublinhado")
        if papel not in PAPEIS:
            raise ErroBanco("papel inválido")
        problema = cofre_mod.problema_na_senha(senha, nome)
        if problema:
            raise ErroBanco(problema)
        hash_ = cofre_mod.hash_senha(senha)
        with self.transacao() as c:
            if c.execute("SELECT 1 FROM usuarios WHERE nome = ?",
                         (nome,)).fetchone():
                raise ErroBanco("usuário já existe")
            cur = c.execute(
                "INSERT INTO usuarios (nome, nome_completo, papel, "
                "hash_cifrado, trocar_senha, criado) VALUES (?, ?, ?, '', ?, ?)",
                (nome, (nome_completo or "")[:80], papel, int(trocar_senha),
                 iso(agora())))
            uid = cur.lastrowid
            c.execute("UPDATE usuarios SET hash_cifrado = ? WHERE id = ?",
                      (self.cofre.cifrar(hash_, f"usuario-senha:{uid}"), uid))
        return uid

    def usuario(self, uid=None, nome=None):
        if uid is not None:
            return self.um("SELECT * FROM usuarios WHERE id = ?", (uid,))
        return self.um("SELECT * FROM usuarios WHERE nome = ?",
                       ((nome or "").strip().lower(),))

    def listar_usuarios(self):
        return self.consultar(
            "SELECT id, nome, nome_completo, papel, totp_ativo, ativo, "
            "trocar_senha, falhas, bloqueado_ate, criado, ultimo_login "
            "FROM usuarios ORDER BY nome")

    def conferir_senha(self, usuario, senha):
        try:
            hash_ = self.cofre.decifrar(usuario["hash_cifrado"],
                                        f"usuario-senha:{usuario['id']}")
        except cofre_mod.ErroCofre:
            return False
        return cofre_mod.conferir_senha(senha, hash_.decode())

    def trocar_senha(self, uid, senha, exigir_troca=False):
        u = self.usuario(uid)
        problema = cofre_mod.problema_na_senha(senha, u["nome"])
        if problema:
            raise ErroBanco(problema)
        hash_ = cofre_mod.hash_senha(senha)
        with self.transacao() as c:
            c.execute(
                "UPDATE usuarios SET hash_cifrado = ?, trocar_senha = ?, "
                "senha_alterada = ?, falhas = 0, bloqueado_ate = NULL "
                "WHERE id = ?",
                (self.cofre.cifrar(hash_, f"usuario-senha:{uid}"),
                 int(exigir_troca), iso(agora()), uid))
            if exigir_troca:
                # Senha redefinida pelo administrador: dispositivos esquecidos.
                c.execute("DELETE FROM dispositivos WHERE usuario_id = ?",
                          (uid,))

    def alterar_usuario(self, uid, **campos):
        permitidos = {"papel", "ativo", "nome_completo"}
        sets, args = [], []
        for k, v in campos.items():
            if k not in permitidos:
                raise ErroBanco(f"campo não editável: {k}")
            if k == "papel" and v not in PAPEIS:
                raise ErroBanco("papel inválido")
            if k == "ativo" and not isinstance(v, (bool, int)):
                raise ErroBanco("ativo deve ser verdadeiro ou falso")
            if k == "nome_completo":
                v = str(v)[:80]
            sets.append(f"{k} = ?")
            args.append(int(bool(v)) if k == "ativo" else v)
        if sets:
            with self.transacao() as c:
                c.execute(f"UPDATE usuarios SET {', '.join(sets)} WHERE id = ?",
                          args + [uid])

    def remover_usuario(self, uid):
        with self.transacao() as c:
            c.execute("DELETE FROM usuarios WHERE id = ?", (uid,))

    def admins_ativos(self):
        r = self.um("SELECT COUNT(*) AS n FROM usuarios WHERE papel = 'admin' "
                    "AND ativo = 1")
        return r["n"]

    def registrar_falha(self, uid):
        """Conta a falha da conta. Ao atingir o limite, bloqueia por tempo
        fixo e zera a contagem: errar de propósito não estende o bloqueio
        indefinidamente."""
        with self.transacao() as c:
            r = c.execute("SELECT falhas FROM usuarios WHERE id = ?",
                          (uid,)).fetchone()
            falhas = (r[0] if r else 0) + 1
            bloqueio = None
            if falhas >= MAX_FALHAS_CONTA:
                bloqueio = iso(agora() + timedelta(minutes=BLOQUEIO_CONTA_MIN))
                falhas = 0
            c.execute("UPDATE usuarios SET falhas = ?, bloqueado_ate = "
                      "COALESCE(?, bloqueado_ate) WHERE id = ?",
                      (falhas, bloqueio, uid))
        return falhas, bloqueio

    def registrar_login(self, uid):
        with self.transacao() as c:
            c.execute("UPDATE usuarios SET falhas = 0, bloqueado_ate = NULL, "
                      "ultimo_login = ? WHERE id = ?", (iso(agora()), uid))

    def desbloquear(self, uid):
        with self.transacao() as c:
            c.execute("UPDATE usuarios SET falhas = 0, bloqueado_ate = NULL "
                      "WHERE id = ?", (uid,))

    @staticmethod
    def bloqueado(usuario):
        ate = usuario.get("bloqueado_ate")
        return bool(ate) and datetime.fromisoformat(ate) > agora()

    # -- TOTP -------------------------------------------------------------
    def segredo_totp(self, usuario):
        if not usuario.get("totp_cifrado"):
            return None
        return self.cofre.decifrar(usuario["totp_cifrado"],
                                   f"usuario-totp:{usuario['id']}").decode()

    def ativar_totp(self, uid, segredo, contador):
        """Grava o segredo confirmado e gera os códigos de recuperação."""
        codigos = cofre_mod.novos_codigos_recuperacao()
        hashes = [self.cofre.hmac("recuperacao", f"{uid}:" +
                                  cofre_mod.normalizar_codigo_recuperacao(x))
                  for x in codigos]
        with self.transacao() as c:
            c.execute(
                "UPDATE usuarios SET totp_cifrado = ?, totp_ativo = 1, "
                "totp_ultimo = ?, recuperacao = ? WHERE id = ?",
                (self.cofre.cifrar(segredo, f"usuario-totp:{uid}"), contador,
                 json.dumps(hashes), uid))
        return codigos

    def avancar_totp(self, uid, contador):
        """Grava o contador aceito, só se for maior (corrida entre abas)."""
        with self.transacao() as c:
            cur = c.execute("UPDATE usuarios SET totp_ultimo = ? WHERE id = ? "
                            "AND totp_ultimo < ?", (contador, uid, contador))
            return cur.rowcount == 1

    def usar_codigo_recuperacao(self, uid, codigo):
        alvo = self.cofre.hmac("recuperacao", f"{uid}:" +
                               cofre_mod.normalizar_codigo_recuperacao(codigo))
        with self.transacao() as c:
            r = c.execute("SELECT recuperacao FROM usuarios WHERE id = ?",
                          (uid,)).fetchone()
            lista = json.loads(r[0]) if r else []
            achado = next((h for h in lista
                           if secrets.compare_digest(h, alvo)), None)
            if not achado:
                return None
            lista.remove(achado)
            c.execute("UPDATE usuarios SET recuperacao = ? WHERE id = ?",
                      (json.dumps(lista), uid))
            return len(lista)

    # -- dispositivos conhecidos --------------------------------------------
    # Navegador onde o usuário já entrou com sucesso. O bloqueio da conta
    # inteira (erros vindos de muitas origens) não vale para ele: quem tenta
    # trancar o administrador de fora não consegue impedi-lo de entrar.
    VALIDADE_DISPOSITIVO = timedelta(days=180)

    def criar_dispositivo(self, uid):
        token = secrets.token_urlsafe(32)
        t = iso(agora())
        with self.transacao() as c:
            c.execute("INSERT INTO dispositivos VALUES (?, ?, ?, ?)",
                      (self.cofre.hmac("sessao", "dispositivo|" + token), uid,
                       t, t))
            c.execute("DELETE FROM dispositivos WHERE ultimo_uso < ?",
                      (iso(agora() - self.VALIDADE_DISPOSITIVO),))
        return token

    def dispositivo_valido(self, uid, token):
        if not token or len(token) > 128:
            return False
        h = self.cofre.hmac("sessao", "dispositivo|" + token)
        limite = iso(agora() - self.VALIDADE_DISPOSITIVO)
        with self.transacao() as c:
            cur = c.execute("UPDATE dispositivos SET ultimo_uso = ? WHERE "
                            "id_hash = ? AND usuario_id = ? AND ultimo_uso >= ?",
                            (iso(agora()), h, uid, limite))
            return cur.rowcount == 1

    def remover_dispositivos(self, uid):
        with self.transacao() as c:
            c.execute("DELETE FROM dispositivos WHERE usuario_id = ?", (uid,))

    def resetar_totp(self, uid):
        with self.transacao() as c:
            c.execute("DELETE FROM dispositivos WHERE usuario_id = ?", (uid,))
            c.execute("UPDATE usuarios SET totp_cifrado = NULL, totp_ativo = 0, "
                      "totp_ultimo = 0, recuperacao = '[]' WHERE id = ?",
                      (uid,))
            c.execute("DELETE FROM sessoes WHERE usuario_id = ?", (uid,))

    # -- sessões ----------------------------------------------------------
    def criar_sessao(self, uid, ip, agente, duracao_max):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        t = agora()
        with self.transacao() as c:
            c.execute(
                "INSERT INTO sessoes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self.cofre.hmac("sessao", token), uid, csrf, iso(t), iso(t),
                 iso(t + duracao_max), ip[:64], (agente or "")[:200]))
        return token, csrf

    def sessao(self, token, ociosidade):
        """Sessão válida ou None. Renova o último uso a cada consulta."""
        if not token or len(token) > 128:
            return None
        id_hash = self.cofre.hmac("sessao", token)
        s = self.um(
            "SELECT s.*, u.nome, u.papel, u.ativo, u.trocar_senha, "
            "u.totp_ativo, u.nome_completo FROM sessoes s "
            "JOIN usuarios u ON u.id = s.usuario_id WHERE s.id_hash = ?",
            (id_hash,))
        if not s:
            return None
        t = agora()
        if (not s["ativo"] or datetime.fromisoformat(s["expira"]) <= t or
                datetime.fromisoformat(s["ultimo_uso"]) + ociosidade <= t):
            self.encerrar_sessao(token)
            return None
        # Gravar a cada pedido sobrecarregaria o banco com o painel aberto
        # (o painel consulta a cada poucos segundos durante uma coleta).
        if datetime.fromisoformat(s["ultimo_uso"]) + timedelta(seconds=30) <= t:
            with self.transacao() as c:
                c.execute("UPDATE sessoes SET ultimo_uso = ? WHERE id_hash = ?",
                          (iso(t), id_hash))
        return s

    def encerrar_sessao(self, token):
        with self.transacao() as c:
            c.execute("DELETE FROM sessoes WHERE id_hash = ?",
                      (self.cofre.hmac("sessao", token),))

    def encerrar_sessoes_do_usuario(self, uid, exceto_token=None):
        manter = self.cofre.hmac("sessao", exceto_token) if exceto_token else ""
        with self.transacao() as c:
            c.execute("DELETE FROM sessoes WHERE usuario_id = ? AND id_hash != ?",
                      (uid, manter))

    def limpar_sessoes(self, ociosidade):
        limite = iso(agora() - ociosidade)
        with self.transacao() as c:
            c.execute("DELETE FROM sessoes WHERE expira <= ? OR ultimo_uso <= ?",
                      (iso(agora()), limite))

    # -- cofre de credenciais de equipamento ------------------------------
    @staticmethod
    def normalizar_redes(redes):
        """Redes onde a credencial pode ser usada. Obrigatórias: sem elas,
        quem pode coletar apontaria a credencial para um servidor próprio e
        receberia a senha."""
        if isinstance(redes, str):
            redes = [r for r in re.split(r"[\s,;]+", redes) if r]
        saida = []
        for r in redes or []:
            try:
                rede = ipaddress.ip_network(str(r).strip(), strict=False)
            except ValueError:
                raise ErroBanco(f"rede inválida: {r}")
            if rede.prefixlen < PREFIXO_MINIMO[rede.version]:
                raise ErroBanco(f"rede ampla demais: {rede} (use até /"
                                f"{PREFIXO_MINIMO[rede.version]})")
            if str(rede) not in saida:
                saida.append(str(rede))
        if not saida:
            raise ErroBanco("informe as redes (CIDR) onde esta credencial "
                            "pode ser usada")
        if len(saida) > 64:
            raise ErroBanco("no máximo 64 redes por credencial")
        return saida

    def criar_credencial(self, nome, usuario_disp, senha_disp, descricao,
                         criado_por, criado_por_id, redes, telnet=False):
        nome = (nome or "").strip()
        if not 1 <= len(nome) <= 64:
            raise ErroBanco("nome da credencial: 1 a 64 caracteres")
        if not usuario_disp or not senha_disp:
            raise ErroBanco("informe usuário e senha do equipamento")
        if len(usuario_disp) > 128 or len(senha_disp) > 512:
            raise ErroBanco("usuário ou senha longos demais")
        redes = self.normalizar_redes(redes)
        t = iso(agora())
        with self.transacao() as c:
            if c.execute("SELECT 1 FROM credenciais WHERE nome = ?",
                         (nome,)).fetchone():
                raise ErroBanco("já existe credencial com esse nome")
            cur = c.execute(
                "INSERT INTO credenciais (nome, descricao, segredo_cifrado, "
                "criado_por, criado_por_id, criado, atualizado) "
                "VALUES (?, ?, '', ?, ?, ?, ?)",
                (nome, (descricao or "")[:200], criado_por, criado_por_id, t, t))
            cid = cur.lastrowid
            c.execute("UPDATE credenciais SET segredo_cifrado = ? WHERE id = ?",
                      (self._cifrar_credencial(cid, usuario_disp, senha_disp,
                                               redes, telnet), cid))
        return cid

    def _cifrar_credencial(self, cid, usuario_disp, senha_disp, redes, telnet):
        # Redes e permissão de Telnet vão dentro do conteúdo cifrado e
        # autenticado: alterar no banco sem a chave invalida a credencial.
        return self.cofre.cifrar_json(
            {"usuario": usuario_disp, "senha": senha_disp, "redes": redes,
             "telnet": bool(telnet)}, f"credencial:{cid}")

    def atualizar_credencial(self, cid, usuario_disp=None, senha_disp=None,
                             descricao=None, redes=None, telnet=None):
        atual = self.segredo_credencial(cid)
        novo_usuario = usuario_disp or atual["usuario"]
        nova_senha = senha_disp or atual["senha"]
        novas_redes = atual["redes"] if redes is None else \
            self.normalizar_redes(redes)
        novo_telnet = atual["telnet"] if telnet is None else bool(telnet)
        if len(novo_usuario) > 128 or len(nova_senha) > 512:
            raise ErroBanco("usuário ou senha longos demais")
        with self.transacao() as c:
            c.execute(
                "UPDATE credenciais SET segredo_cifrado = ?, atualizado = ?, "
                "descricao = COALESCE(?, descricao) WHERE id = ?",
                (self._cifrar_credencial(cid, novo_usuario, nova_senha,
                                         novas_redes, novo_telnet),
                 iso(agora()),
                 descricao[:200] if descricao is not None else None, cid))

    def listar_credenciais(self):
        """Sem a senha: só o necessário para escolher a credencial."""
        lista = self.consultar("SELECT id, nome, descricao, criado_por, "
                               "criado_por_id, criado, atualizado, ultimo_uso, "
                               "segredo_cifrado FROM credenciais ORDER BY nome")
        for item in lista:
            try:
                s = self.cofre.decifrar_json(item["segredo_cifrado"],
                                             f"credencial:{item['id']}")
                item.update(usuario=s["usuario"], redes=s.get("redes") or [],
                            telnet=bool(s.get("telnet")))
            except cofre_mod.ErroCofre:
                item.update(usuario="(ilegível)", redes=[], telnet=False)
            del item["segredo_cifrado"]
        return lista

    def credencial(self, cid):
        return self.um("SELECT id, nome, descricao, criado_por, criado_por_id "
                       "FROM credenciais WHERE id = ?", (cid,))

    def segredo_credencial(self, cid, marcar_uso=False):
        r = self.um("SELECT segredo_cifrado FROM credenciais WHERE id = ?",
                    (cid,))
        if not r:
            raise ErroBanco("credencial não encontrada")
        segredo = self.cofre.decifrar_json(r["segredo_cifrado"],
                                           f"credencial:{cid}")
        segredo.setdefault("redes", [])
        segredo["telnet"] = bool(segredo.get("telnet"))
        if marcar_uso:
            with self.transacao() as c:
                c.execute("UPDATE credenciais SET ultimo_uso = ? WHERE id = ?",
                          (iso(agora()), cid))
        return segredo

    def remover_credencial(self, cid):
        em_uso = [a["nome"] for a in self.consultar(
            "SELECT nome, dados FROM agendamentos")
            if json.loads(a["dados"]).get("credencial") == cid]
        if em_uso:
            raise ErroBanco("credencial em uso pelos agendamentos: " +
                            ", ".join(em_uso))
        with self.transacao() as c:
            c.execute("DELETE FROM credenciais WHERE id = ?", (cid,))

    # -- auditoria --------------------------------------------------------
    def _ancora(self, ultimo_id, ultimo_hash):
        """Assinatura do fim da trilha. Sem a chave não se forja: apagar as
        últimas linhas (e acertar a âncora) é detectado."""
        return self.cofre.hmac("auditoria", f"ancora|{ultimo_id}|{ultimo_hash}")

    def auditar(self, usuario, ip, acao, alvo="", detalhe=""):
        with self._trava_auditoria, self.transacao() as c:
            r = c.execute("SELECT id, hash FROM auditoria ORDER BY id DESC "
                          "LIMIT 1").fetchone()
            ident, anterior = ((r[0] + 1, r[1]) if r else (1, ""))
            quando = iso(agora())
            campos = [quando, usuario or "", ip or "", acao, str(alvo)[:200],
                      str(detalhe)[:500]]
            h = self.cofre.hmac("auditoria", "\x1f".join(
                [anterior, str(ident)] + campos))
            c.execute("INSERT INTO auditoria (id, quando, usuario, ip, acao, "
                      "alvo, detalhe, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      [ident] + campos + [h])
            c.execute("INSERT OR REPLACE INTO meta VALUES "
                      "('auditoria_ancora', ?)", (self._ancora(ident, h),))
        return ident, h

    def listar_auditoria(self, limite=500, usuario=None, acao=None):
        sql = "SELECT id, quando, usuario, ip, acao, alvo, detalhe FROM auditoria"
        filtros, args = [], []
        if usuario:
            filtros.append("usuario = ?")
            args.append(usuario)
        if acao:
            filtros.append("acao LIKE ?")
            args.append(acao + "%")
        if filtros:
            sql += " WHERE " + " AND ".join(filtros)
        sql += " ORDER BY id DESC LIMIT ?"
        try:
            args.append(max(1, min(5000, int(limite))))
        except (TypeError, ValueError):
            args.append(500)
        return self.consultar(sql, args)

    def verificar_auditoria(self):
        """Recalcula a cadeia e confere a âncora.

        Devolve (ok, id do primeiro registro inválido ou None). Detecta
        edição, remoção no meio e corte do fim. Apagar a trilha inteira e
        restaurar a âncora inicial exige ter guardado essa âncora antes; para
        esse caso o serviço também escreve cada hash no log (journald)."""
        anterior, ultimo_id, esperado_id = "", 0, 1
        for r in self._con().execute(
                "SELECT id, quando, usuario, ip, acao, alvo, detalhe, hash "
                "FROM auditoria ORDER BY id"):
            campos = [r["quando"], r["usuario"], r["ip"], r["acao"], r["alvo"],
                      r["detalhe"]]
            calculado = self.cofre.hmac("auditoria", "\x1f".join(
                [anterior, str(r["id"])] + campos))
            if r["id"] != esperado_id or \
                    not secrets.compare_digest(calculado, r["hash"]):
                return False, r["id"]
            anterior, ultimo_id, esperado_id = r["hash"], r["id"], r["id"] + 1
        ancora = self.um("SELECT valor FROM meta WHERE chave = "
                         "'auditoria_ancora'")
        if not ancora or not secrets.compare_digest(
                ancora["valor"], self._ancora(ultimo_id, anterior)):
            return False, None
        return True, None

    # -- agendamentos -----------------------------------------------------
    def salvar_agendamento(self, item):
        dados = {k: v for k, v in item.items() if k not in (
            "id", "nome", "ativo", "proxima", "ultima", "ultimo_job",
            "ultimo_estado", "criado_por", "criado")}
        with self.transacao() as c:
            c.execute(
                "INSERT OR REPLACE INTO agendamentos VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item["id"], item["nome"], json.dumps(dados, ensure_ascii=False),
                 int(item["ativo"]), item.get("proxima"), item.get("ultima"),
                 item.get("ultimo_job"), item.get("ultimo_estado"),
                 item["criado_por"], item["criado"]))

    def listar_agendamentos(self):
        itens = []
        for r in self.consultar("SELECT * FROM agendamentos ORDER BY nome"):
            item = json.loads(r.pop("dados"))
            item.update(r)
            item["ativo"] = bool(item["ativo"])
            itens.append(item)
        return itens

    def remover_agendamento(self, ident):
        with self.transacao() as c:
            c.execute("DELETE FROM agendamentos WHERE id = ?", (ident,))

    # -- execuções e análises ---------------------------------------------
    def salvar_execucao(self, resumo, detalhe, usuario):
        with self.transacao() as c:
            c.execute(
                "INSERT OR REPLACE INTO execucoes VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (resumo["id"], resumo["tipo"], resumo["titulo"],
                 resumo["origem"], resumo["estado"], resumo["criado"],
                 resumo.get("terminado"), usuario or "",
                 json.dumps(resumo, ensure_ascii=False),
                 json.dumps(detalhe, ensure_ascii=False)))

    def listar_execucoes(self, limite=200):
        return [json.loads(r["resumo"]) for r in self.consultar(
            "SELECT resumo FROM execucoes ORDER BY criado DESC LIMIT ?",
            (limite,))]

    def execucao(self, ident):
        r = self.um("SELECT detalhe FROM execucoes WHERE id = ?", (ident,))
        return json.loads(r["detalhe"]) if r else None

    def salvar_analise(self, ident, agendamento_id, job_id, arquivo, resumo):
        with self.transacao() as c:
            c.execute("INSERT INTO analises VALUES (?, ?, ?, ?, ?, ?)",
                      (ident, agendamento_id, job_id, iso(agora()), arquivo,
                       json.dumps(resumo, ensure_ascii=False)))

    def listar_analises(self, limite=200):
        lista = self.consultar("SELECT * FROM analises ORDER BY criado DESC "
                               "LIMIT ?", (limite,))
        for item in lista:
            item["resumo"] = json.loads(item["resumo"])
        return lista

    def analise(self, ident):
        r = self.um("SELECT * FROM analises WHERE id = ?", (ident,))
        if r:
            r["resumo"] = json.loads(r["resumo"])
        return r

    def remover_analise(self, ident):
        with self.transacao() as c:
            c.execute("DELETE FROM analises WHERE id = ?", (ident,))

    def limpar_execucoes(self, dias):
        limite = iso(agora() - timedelta(days=dias))
        with self.transacao() as c:
            c.execute("DELETE FROM execucoes WHERE criado < ?", (limite,))
