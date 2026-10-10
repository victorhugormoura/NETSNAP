#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_transporte — camada de acesso a equipamentos sem dependências externas

Fornece sessões interativas de SSH e Telnet usando exclusivamente a biblioteca
padrão do Python, de modo que o netsnap possa ser copiado e executado em
qualquer máquina com Python 3.8 ou superior, sem instalação de pacotes.

Por que não implementar SSH em Python puro: o protocolo exige troca de chaves
Diffie-Hellman/Curve25519, cifras de bloco e HMAC. A biblioteca padrão oferece
apenas resumo criptográfico (hashlib, hmac) — não há AES nem curvas elípticas.
Reimplementá-los seria lento e, sobretudo, inseguro. A solução adotada é
delegar ao cliente OpenSSH do próprio sistema, presente por padrão em Linux,
macOS, BSD e no Windows 10/11.

Telnet, ao contrário, é texto sobre TCP com negociação de opções simples
(RFC 854) e está implementado aqui integralmente. Isso também resolve a
remoção de telnetlib da biblioteca padrão no Python 3.13 (PEP 594).

Estratégias de autenticação SSH, escolhidas automaticamente:
  pty          conduz o binário ssh por um pseudoterminal (Unix)
  askpass      fornece a senha por SSH_ASKPASS, sem terminal (Unix e Windows)
  chave        autenticação por chave pública, sem senha

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.1.2"

import codecs
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

WINDOWS = sys.platform.startswith("win")

try:
    import pty
    import termios
    import fcntl
    import select
    TEM_PTY = not WINDOWS
except ImportError:
    TEM_PTY = False


class ErroTransporte(Exception):
    """Falha de conexão, de autenticação ou de leitura."""


class ErroAutenticacao(ErroTransporte):
    """Credenciais recusadas pelo equipamento."""


class ErroConexao(ErroTransporte):
    """Equipamento inacessível ou sessão encerrada."""


# ---------------------------------------------------------------------------
# Utilidades comuns
# ---------------------------------------------------------------------------
PADRAO_ANSI = re.compile(r"\x1b\[[0-9;:?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
PADRAO_SENHA = re.compile(r"(?i)(password|senha|passwd)\s*:\s*$")
PADRAO_USUARIO = re.compile(r"(?i)(login|user\s*name|username|usuario)\s*:\s*$")
# Prompt genérico, usado só enquanto o prompt real não é conhecido. O fim
# é [ \t]*\Z: com \s*, ou com $ (que também casa antes de uma quebra de
# linha final), qualquer linha de saída terminada em %, >, # ou ] (ex.:
# "CPU: 5%") seguida de quebra de linha passaria por prompt e cortaria a
# saída no meio.
PADRAO_PROMPT = re.compile(r"[\r\n][^\r\n]{0,80}[\$#>\]%][ \t]*\Z")
# Paginadores: Huawei/SmartAX "---- More ( Press 'Q' to break ) ----",
# Junos "---(more 12%)---", Cisco "--More--", MikroTik "-- [Q quit|D dump|...]".
PADRAO_PAGINACAO = re.compile(
    r"(?i)(-{2,}\s*\(?\s*more\b[^\r\n]{0,40}?-{2,}|--more--|<space>|"
    r"press any key|more:\s*<space>|\(more\)|--\s*mais\s*--|\[Q quit\|)"
)
PADRAO_FALHA_LOGIN = re.compile(
    r"(?i)login incorrect|authentication fail|access denied|"
    r"authentication is rejected|invalid (?:user|password|login)|"
    r"(?:password|user\s*name)\s+(?:is\s+)?(?:invalid|incorrect)|"
    r"bad password|login failed"
)


# Gancho de depuração: quem integrar o transporte (o netsnap, quando migrar
# para esta camada) substitui esta função para registrar os eventos de
# transporte no mesmo log dos demais componentes.
def depurar_transporte(host: str, mensagem: str):
    pass


def _aplicar_retrocesso(linha: str) -> str:
    saida = []
    for c in linha:
        if c == "\b":
            if saida:
                saida.pop()
        else:
            saida.append(c)
    return "".join(saida)


def limpar(texto: str) -> str:
    """Remove códigos ANSI, aplica retrocessos e normaliza fim de linha.

    Paginadores apagam o próprio aviso com movimento de cursor: o Huawei
    envia ESC[42D, 42 espaços e ESC[42D; o Cisco, backspaces. Apenas remover
    os códigos deixaria dezenas de espaços (ou \b literais) no meio da
    saída, deslocando linhas conforme o ponto da quebra de página."""
    texto = re.sub(r"\x1b\[(\d*)D", lambda m: "\b" * int(m.group(1) or 1),
                   texto or "")
    texto = PADRAO_ANSI.sub("", texto)
    # CR antes ou depois do LF (\r\r\n, \n\r) é fim de linha único; contado
    # duas vezes, inseria linhas em branco que não existem na saída. Um
    # "texto\r   \r" é o paginador apagando o próprio aviso.
    texto = re.sub(r"\r*\n\r?", "\n", texto)
    texto = re.sub(r"[^\r\n]*\r[ \t]*\r", "", texto)
    texto = texto.replace("\r", "\n")
    if "\b" in texto:
        texto = "\n".join(_aplicar_retrocesso(l) for l in texto.split("\n"))
    return texto


LIMITE_PAGINAS = 100000


def porta_aberta(host: str, porta: int, tempo: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, porta), timeout=tempo):
            return True
    except OSError:
        return False


class _Sessao:
    """Comportamento comum às sessões: leitura até prompt e envio de comandos.

    As subclasses implementam apenas _escrever(), _ler_bruto() e _fechar()."""

    def __init__(self, host, timeout_leitura=180.0):
        self.host = host
        self.timeout_leitura = timeout_leitura
        self.prompt = ""
        self.encerrada = False
        self._acumulado = ""
        # Decodificação incremental: um caractere multibyte (acentos em
        # descrições de interface) partido entre duas leituras viraria U+FFFD.
        self._decodificador = codecs.getincrementaldecoder("utf-8")("replace")

    def _decodificar(self, dados: bytes) -> str:
        return self._decodificador.decode(dados)

    def _fim_de_comando(self):
        """Padrão que encerra a leitura de um comando.

        Conhecido o prompt, só ele serve: o padrão genérico confunde linhas
        de saída com prompt. Após mudar de modo (enable, config), chame
        descobrir_prompt() de novo."""
        if self.prompt:
            return re.compile(r"(?:^|\n)[ \t]*" + re.escape(self.prompt)
                              + r"[ \t]*\Z")
        return PADRAO_PROMPT

    # -- a implementar nas subclasses -------------------------------------
    def _escrever(self, dados: bytes):
        raise NotImplementedError

    def _ler_bruto(self, tempo: float) -> str:
        raise NotImplementedError

    def _fechar(self):
        raise NotImplementedError

    # -- interface pública -------------------------------------------------
    def ler(self, tempo=2.0, ate=None, silencio=0.5) -> str:
        """Lê do canal até casar 'ate', esgotar 'tempo' ou o fluxo silenciar.

        O critério de silêncio evita esperar o tempo inteiro quando o
        equipamento já terminou de responder — sem ele, cada comando custaria
        o timeout completo."""
        acumulado = ""
        limite = time.time() + tempo
        ultimo = time.time()
        while time.time() < limite:
            pedaco = self._ler_bruto(0.2)
            if pedaco:
                acumulado += pedaco
                ultimo = time.time()
                # Só o final é limpo: limpar o buffer inteiro a cada leitura
                # tornava a coleta de saídas grandes quadrática.
                if ate and ate.search(limpar(acumulado[-2000:])[-400:]):
                    break
            elif acumulado and time.time() - ultimo > silencio:
                break
            elif self.encerrada:
                break
        return acumulado

    FIM_DE_LINHA = b"\n"

    def drenar(self, silencio=0.3, maximo=3.0):
        """Descarta o que estiver pendente no canal antes de um comando.

        Um prompt atrasado (de um retorno enviado antes, por exemplo para
        passar um "--Press any key--") seria lido como fim do próximo
        comando, e toda saída seguinte ficaria deslocada de um comando."""
        limite = time.time() + maximo
        while time.time() < limite:
            if not self._ler_bruto(silencio):
                return

    def enviar(self, texto: str):
        if self.encerrada:
            raise ErroConexao("sessão encerrada")
        self._escrever(texto.encode("utf-8", "replace") + self.FIM_DE_LINHA)

    def descobrir_prompt(self, tentativas=3) -> str:
        """Determina o prompt enviando uma linha vazia e lendo a resposta.

        Também atende equipamentos que exigem uma tecla após o login, como as
        OLTs que apresentam '--Press any key to continue--': nesses casos o
        próprio retorno enviado serve de tecla."""
        for _ in range(tentativas):
            self.enviar("")
            saida = limpar(self.ler(3.0, ate=PADRAO_PROMPT))
            linhas = [l for l in saida.splitlines() if l.strip()]
            if not linhas:
                continue
            candidato = linhas[-1].strip()
            if PADRAO_PAGINACAO.search(candidato) or PADRAO_SENHA.search(candidato):
                continue
            if candidato:
                self.prompt = candidato
                return candidato
        return self.prompt

    def executar(self, comando: str, tempo=None, paginacao_automatica=True) -> str:
        """Envia um comando e devolve a saída, sem o eco nem o prompt final."""
        tempo = tempo or self.timeout_leitura
        self.drenar()
        if not self.prompt and self.sem_terminal:
            return self._executar_com_marcador(comando, tempo)
        fim = self._fim_de_comando()
        self.enviar(comando)
        saida = ""
        limite = time.time() + tempo
        paginas = 0
        ultimo_dado = time.time()
        while time.time() < limite:
            trecho = self.ler(min(15.0, max(2.0, tempo / 8)), ate=fim)
            if not trecho:
                # Comandos pesados (ex.: Junos gerando a saída inteira antes
                # de filtrar) ficam dezenas de segundos em silêncio. Com o
                # prompt conhecido, espera-se até o limite; sem ele, desiste
                # após 30 s de silêncio para não pender em prompt exótico.
                if self.encerrada or (not self.prompt and
                                      time.time() - ultimo_dado > 30):
                    break
                continue
            ultimo_dado = time.time()
            saida += trecho
            # A verificação recai sobre o trecho recém-lido, não sobre o
            # acumulado: um "--More--" já respondido permaneceria no buffer e
            # o laço ficaria enviando espaços até esgotar o tempo.
            recente = limpar(trecho)
            # O teto de páginas só protege contra laço; o limite real é o
            # tempo. Com 500, uma configuração Huawei paginada a cada 24
            # linhas era cortada em ~12 mil linhas.
            if (paginacao_automatica and paginas < LIMITE_PAGINAS
                    and PADRAO_PAGINACAO.search(recente[-200:])):
                paginas += 1
                self._escrever(b" ")
                continue
            if fim.search(limpar(saida[-3000:])[-300:]):
                break
        if paginas:
            depurar_transporte(self.host,
                               f"{paginas} página(s) respondida(s) em: {comando[:60]}"
                               + (" (teto atingido; saída incompleta)"
                                  if paginas >= LIMITE_PAGINAS else ""))
        return self._limpar_saida(saida, comando)

    # Sessão sem terminal (askpass, -T) com um shell Unix do outro lado não
    # exibe prompt algum. O fim de cada saída é marcado por um echo enviado
    # logo depois do comando; sem isso, só restaria adivinhar pelo silêncio
    # ou por um padrão genérico que confunde "CPU: 5%" com prompt.
    sem_terminal = False

    def _executar_com_marcador(self, comando, tempo):
        marcador = f"__NETSNAP_FIM_{int(time.time() * 1000) % 10**9}__"
        self.enviar(comando)
        self.enviar(f"echo {marcador}")
        fim = re.compile(r"(?:^|\n)" + marcador + r"[ \t]*\n?$")
        saida, limite = "", time.time() + tempo
        while time.time() < limite and not self.encerrada:
            saida += self.ler(min(15.0, tempo), ate=fim)
            if fim.search(limpar(saida)[-200:]):
                break
        texto = limpar(saida)
        texto = texto[:texto.rfind(marcador)] if marcador in texto else texto
        return texto.strip("\n")

    def _limpar_saida(self, saida: str, comando: str) -> str:
        texto = limpar(saida)
        texto = PADRAO_PAGINACAO.sub("", texto)
        linhas = texto.splitlines()
        # Remove o eco do comando na primeira linha
        if linhas and comando.strip() and comando.strip() in linhas[0]:
            linhas = linhas[1:]
        # Remove o prompt repetido ao final
        while linhas and self.prompt and linhas[-1].strip().endswith(
                self.prompt.strip()[-12:]):
            linhas.pop()
        return "\n".join(linhas).strip("\n")

    # Distinto de 'encerrada', que também indica fim de fluxo visto na leitura:
    # uma sessão encerrada pelo equipamento ainda precisa liberar descritor,
    # processo e arquivos temporários.
    _fechado = False

    def fechar(self):
        if self._fechado:
            return
        self._fechado = True
        try:
            self._fechar()
        except Exception:
            pass
        self.encerrada = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.fechar()
        return False


# ---------------------------------------------------------------------------
# Telnet — implementado sobre socket, sem telnetlib
# ---------------------------------------------------------------------------
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_ECHO, OPT_SGA, OPT_TTYPE, OPT_NAWS = 1, 3, 24, 31


class SessaoTelnet(_Sessao):
    # RFC 854: fim de linha é CR LF. As credenciais vão só com CR (como faz o
    # Netmiko): o LF extra seria lido por alguns equipamentos como uma
    # segunda resposta vazia ao pedido seguinte.
    FIM_DE_LINHA = b"\r\n"

    """Cliente Telnet mínimo conforme a RFC 854.

    Recusa todas as opções propostas pelo equipamento, exceto supressão de
    'go ahead' e tipo de terminal, que muitas CLIs exigem para liberar o
    prompt. Isso mantém a sessão em modo linha, previsível para automação."""

    def __init__(self, host, usuario, senha, porta=23, timeout=30.0,
                 timeout_leitura=180.0):
        super().__init__(host, timeout_leitura)
        self.porta = porta
        try:
            self.sock = socket.create_connection((host, porta), timeout=timeout)
        except OSError as e:
            raise ErroConexao(f"sem resposta TCP em {host}:{porta} ({e})")
        self.sock.settimeout(0.2)
        self._resto = b""
        # Estado de cada opção (True ativa, False recusada, ausente nunca
        # negociada): só se responde a mudança de estado. Responder de novo
        # a cada pedido repetido viola a RFC 854 e, com um par que faça o
        # mesmo, a troca não termina.
        self._local, self._remota = {}, {}
        try:
            self._autenticar(usuario, senha, timeout)
        except BaseException:
            self.fechar()
            raise

    def _negociar(self, dados: bytes) -> bytes:
        """Separa o texto da negociação de opções, respondendo às propostas."""
        saida, resposta, i = bytearray(), bytearray(), 0
        dados = self._resto + dados
        self._resto = b""
        while i < len(dados):
            b = dados[i]
            if b != IAC:
                saida.append(b)
                i += 1
                continue
            if i + 1 >= len(dados):
                self._resto = dados[i:]
                break
            cmd = dados[i + 1]
            if cmd == IAC:                       # 0xFF escapado
                saida.append(IAC)
                i += 2
            elif cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(dados):
                    self._resto = dados[i:]
                    break
                opt = dados[i + 2]
                if cmd == DO:
                    aceita = opt in (OPT_SGA, OPT_TTYPE, OPT_NAWS)
                    if self._local.get(opt) is not aceita:
                        self._local[opt] = aceita
                        resposta += bytes([IAC, WILL if aceita else WONT, opt])
                        if aceita and opt == OPT_NAWS:
                            # Janela larga e alta: menos quebras de linha e
                            # menos paginação. 254 evita o byte 0xFF, que
                            # exigiria escape.
                            resposta += bytes([IAC, SB, OPT_NAWS, 0, 254, 0,
                                               200, IAC, SE])
                elif cmd == DONT:
                    if self._local.get(opt):
                        self._local[opt] = False
                        resposta += bytes([IAC, WONT, opt])
                elif cmd == WILL:
                    aceita = opt in (OPT_ECHO, OPT_SGA)
                    if self._remota.get(opt) is not aceita:
                        self._remota[opt] = aceita
                        resposta += bytes([IAC, DO if aceita else DONT, opt])
                else:                            # WONT
                    if self._remota.get(opt):
                        self._remota[opt] = False
                        resposta += bytes([IAC, DONT, opt])
                i += 3
            elif cmd == SB:                      # subnegociação
                # O fim é IAC SE; um IAC IAC dentro dela é um 0xFF escapado.
                fim, j = -1, i + 2
                while True:
                    k = dados.find(bytes([IAC]), j)
                    if k == -1 or k + 1 >= len(dados):
                        break
                    if dados[k + 1] == SE:
                        fim = k
                        break
                    j = k + 2
                if fim == -1:
                    self._resto = dados[i:]
                    break
                trecho = dados[i:fim]
                # Só "SB TTYPE SEND" pede o tipo de terminal.
                if len(trecho) >= 4 and trecho[2] == OPT_TTYPE and trecho[3] == 1:
                    resposta += bytes([IAC, SB, OPT_TTYPE, 0]) + b"VT100" + \
                                bytes([IAC, SE])
                i = fim + 2
            else:
                i += 2
        if resposta:
            try:
                self.sock.sendall(bytes(resposta))
            except OSError:
                pass
        return bytes(saida)

    def _ler_bruto(self, tempo: float) -> str:
        self.sock.settimeout(tempo)
        try:
            dados = self.sock.recv(65536)
        except socket.timeout:
            return ""
        except OSError as e:
            self.encerrada = True
            raise ErroConexao(f"conexão telnet encerrada ({e})")
        if not dados:
            self.encerrada = True
            return ""
        return self._decodificar(self._negociar(dados)).replace("\x00", "")

    def _escrever(self, dados: bytes):
        try:
            self.sock.sendall(dados.replace(b"\xff", b"\xff\xff"))
        except OSError as e:
            self.encerrada = True
            raise ErroConexao(f"conexão telnet encerrada ({e})")

    def _fechar(self):
        self.sock.close()

    def _autenticar(self, usuario, senha, timeout=30.0):
        """Responde aos pedidos de usuário e senha do equipamento.

        As credenciais são enviadas uma única vez. Um novo pedido depois
        disso é recusa, e a sessão termina sem nova tentativa: em OLT,
        tentativas repetidas levam ao bloqueio da conta."""
        banner, pediu_usuario, pediu_senha = "", False, False
        limite = time.time() + max(timeout, 30)
        while time.time() < limite:
            trecho = self._ler_bruto(1.0)
            banner += trecho
            recente = limpar(banner)[-200:]
            if (pediu_usuario or pediu_senha) and PADRAO_FALHA_LOGIN.search(recente):
                raise ErroAutenticacao(f"credenciais recusadas por {self.host}")
            if PADRAO_USUARIO.search(recente):
                if pediu_usuario or pediu_senha:
                    raise ErroAutenticacao(
                        f"credenciais recusadas por {self.host}")
                self._escrever(usuario.encode() + b"\r")
                pediu_usuario, banner = True, ""
                continue
            if PADRAO_SENHA.search(recente):
                if pediu_senha:
                    raise ErroAutenticacao(
                        f"credenciais recusadas por {self.host}")
                self._escrever(senha.encode() + b"\r")
                pediu_senha, banner = True, ""
                continue
            if pediu_senha and (PADRAO_PROMPT.search(limpar(banner)) or
                                PADRAO_PAGINACAO.search(recente)):
                self.banner_login = limpar(banner)
                return
            if self.encerrada:
                if pediu_senha:
                    # Sessão encerrada logo após a senha, sem mensagem: é como
                    # boa parte dos equipamentos recusa credenciais.
                    raise ErroAutenticacao(
                        f"credenciais recusadas por {self.host} (sessão "
                        "encerrada após a senha)")
                raise ErroConexao("equipamento encerrou a sessão durante o login")
        if not pediu_senha:
            raise ErroConexao(f"pedido de login não reconhecido em {self.host}: "
                              f"{' '.join(limpar(banner).split())[-80:]!r}")
        # Senha enviada, sem recusa e sem prompt reconhecível: a sessão segue
        # e descobrir_prompt() decide.
        self.banner_login = limpar(banner)


# ---------------------------------------------------------------------------
# SSH — delegado ao cliente OpenSSH do sistema
# ---------------------------------------------------------------------------
# Algoritmos antigos que switches, OLTs e roteadores em produção ainda usam.
# Precisam ser pedidos explicitamente porque o OpenSSH recente os desabilita
# por padrão — sem eles a conexão a boa parte do parque é recusada.
LEGADO_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
              "diffie-hellman-group-exchange-sha1",
              "diffie-hellman-group-exchange-sha256"]
LEGADO_CHAVE = ["ssh-rsa", "ssh-dss"]
LEGADO_CIFRA = ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"]
LEGADO_MAC = ["hmac-sha1", "hmac-md5", "hmac-sha1-96"]

_cache_opcoes = None


def _suportados(categoria) -> set:
    """Algoritmos que este cliente OpenSSH conhece, via 'ssh -Q'."""
    ssh = ssh_disponivel()
    if not ssh:
        return set()
    try:
        r = subprocess.run([ssh, "-Q", categoria], capture_output=True,
                           text=True, timeout=5)
        return {l.strip() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        return set()


def opcoes_ssh() -> list:
    """Monta as opções do cliente, pedindo apenas algoritmos que ele conhece.

    O OpenSSH aborta com "Bad key types" quando recebe um nome de algoritmo
    que não implementa — e o OpenSSH 10 removeu o DSA por completo. Uma lista
    fixa, portanto, impediria toda e qualquer conexão nas versões mais novas.
    A consulta é feita uma vez por execução e reaproveitada."""
    global _cache_opcoes
    if _cache_opcoes is not None:
        return list(_cache_opcoes)

    opcoes = [
        # Chave do equipamento aprendida no primeiro acesso e conferida nos
        # seguintes, no mesmo arquivo do netsnap (formato do OpenSSH): chave
        # diferente encerra a conexão antes de a senha ser enviada. O '~' é
        # expandido pelo próprio cliente, também no Windows, e evita o
        # problema de caminhos com espaço. accept-new existe desde o
        # OpenSSH 7.6.
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=~/.netsnap_known_hosts",
        # Sem isto, uma chave antiga do equipamento em /etc/ssh/ssh_known_hosts
        # ainda seria consultada e recusaria a conexão por um registro que não
        # é do netsnap.
        "-o", "GlobalKnownHostsFile=" + ("NUL" if WINDOWS else "/dev/null"),
        "-o", "LogLevel=ERROR",
        "-o", "NumberOfPasswordPrompts=1",
        # Sem estes, um host inacessível só falha no timeout TCP do sistema
        # (minutos) e uma sessão morta nunca é percebida.
        "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    for parametro, categoria, desejados in (
            ("KexAlgorithms", "kex", LEGADO_KEX),
            ("HostKeyAlgorithms", "key", LEGADO_CHAVE),
            # Nome antigo de propósito: 'PubkeyAcceptedAlgorithms' só existe a
            # partir do OpenSSH 8.5, e opção desconhecida aborta o cliente
            # (Windows 10 traz 8.1; Ubuntu 20.04, 8.2; RHEL 8, 8.0). As
            # versões novas continuam aceitando o nome antigo.
            ("PubkeyAcceptedKeyTypes", "key", ["ssh-rsa"]),
            ("Ciphers", "cipher", LEGADO_CIFRA),
            ("MACs", "mac", LEGADO_MAC)):
        conhecidos = _suportados(categoria)
        aceitos = [a for a in desejados if a in conhecidos]
        if aceitos:
            opcoes += ["-o", f"{parametro}=+{','.join(aceitos)}"]
    _cache_opcoes = opcoes
    return list(opcoes)


def ssh_disponivel() -> str:
    """Caminho do cliente OpenSSH, ou string vazia se ausente."""
    return shutil.which("ssh") or ""


_cache_versao = None


def versao_ssh() -> tuple:
    """Versão do cliente OpenSSH como tupla (maior, menor), ou (0, 0)."""
    global _cache_versao
    if _cache_versao is None:
        _cache_versao = (0, 0)
        ssh = ssh_disponivel()
        if ssh:
            try:
                r = subprocess.run([ssh, "-V"], capture_output=True, text=True,
                                   timeout=5)
                m = re.search(r"OpenSSH\w*_(\d+)\.(\d+)", r.stderr + r.stdout)
                if m:
                    _cache_versao = (int(m.group(1)), int(m.group(2)))
            except Exception:
                pass
    return _cache_versao


def _args_ssh(host, usuario, porta, com_senha, terminal):
    args = [ssh_disponivel(), terminal, "-p", str(porta)] + opcoes_ssh()
    if com_senha:
        args += ["-o", "PreferredAuthentications=password,keyboard-interactive",
                 "-o", "PubkeyAuthentication=no"]
    else:
        args += ["-o", "BatchMode=yes"]
    # Usuário e destino separados, com '--': um alvo começando por '-' não
    # pode ser lido como opção do ssh. Nada pode vir depois do destino: o ssh
    # trataria como comando remoto.
    return args + ["-l", usuario, "--", host]


class SessaoSSHPty(_Sessao):
    """Sessão SSH interativa conduzida por pseudoterminal (Unix).

    O pty é necessário por dois motivos: o OpenSSH lê a senha de /dev/tty, e
    não de stdin; e o equipamento precisa de um terminal para apresentar a
    CLI. O pty também deve ser o terminal de *controle* do processo filho,
    caso contrário /dev/tty não existe para ele e a autenticação falha antes
    mesmo de perguntar a senha."""

    def __init__(self, host, usuario, senha, porta=22, timeout=30.0,
                 timeout_leitura=180.0):
        super().__init__(host, timeout_leitura)
        if not ssh_disponivel():
            raise ErroTransporte("cliente ssh não encontrado no sistema")
        mestre, escravo = pty.openpty()
        self.fd = mestre
        self.proc = None
        self._logado = False
        try:
            # Sem desligar o eco, o ssh lê a própria saída como entrada e
            # consome as tentativas de senha com linhas vazias.
            try:
                attr = termios.tcgetattr(escravo)
                attr[3] &= ~(termios.ECHO | termios.ECHONL)
                termios.tcsetattr(escravo, termios.TCSANOW, attr)
            except termios.error:
                pass
            # Terminal 0x0 faz algumas CLIs quebrarem linha a cada caractere
            # ou paginarem a cada linha.
            try:
                fcntl.ioctl(escravo, termios.TIOCSWINSZ,
                            struct.pack("HHHH", 200, 254, 0, 0))
            except OSError:
                pass

            def preparar_filho():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            self.proc = subprocess.Popen(
                _args_ssh(host, usuario, porta, bool(senha), "-tt"),
                stdin=escravo, stdout=escravo, stderr=escravo,
                close_fds=True, preexec_fn=preparar_filho)
        except BaseException:
            os.close(escravo)
            os.close(mestre)
            raise
        os.close(escravo)
        try:
            self._autenticar(senha, timeout)
        except BaseException:
            self.fechar()
            raise

    def _ler_bruto(self, tempo: float) -> str:
        try:
            pronto, _, _ = select.select([self.fd], [], [], tempo)
        except (OSError, ValueError):
            self.encerrada = True
            return ""
        if not pronto:
            return ""
        try:
            dados = os.read(self.fd, 65536)
        except OSError:
            self.encerrada = True
            return ""
        if not dados:
            self.encerrada = True
            return ""
        return self._decodificar(dados)

    def _escrever(self, dados: bytes):
        try:
            os.write(self.fd, dados)
        except OSError as e:
            self.encerrada = True
            raise ErroConexao(f"sessão ssh encerrada ({e})")

    def _fechar(self):
        # "exit" só com a CLI aberta: diante de um pedido de senha ele seria
        # enviado como senha e somaria uma tentativa de login falha.
        if self._logado and not self.encerrada:
            try:
                os.write(self.fd, b"exit\n")
                time.sleep(0.2)
            except OSError:
                pass
        try:
            if self.proc is not None:
                self.proc.terminate()
                self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except Exception:
                pass
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _autenticar(self, senha, timeout):
        acumulado, recebeu_algo, enviou_senha = "", False, False
        limite = time.time() + timeout
        while time.time() < limite:
            pedaco = self._ler_bruto(0.5)
            if pedaco:
                recebeu_algo = True
            acumulado += pedaco
            recente = limpar(acumulado)[-300:]
            if PADRAO_SENHA.search(recente):
                if not senha:
                    raise ErroAutenticacao("equipamento pediu senha e nenhuma "
                                           "foi informada")
                if enviou_senha:
                    raise ErroAutenticacao("credenciais recusadas")
                self._escrever(senha.encode() + b"\n")
                enviou_senha, acumulado = True, ""
                continue
            erro = _erro_de_ssh(recente, enviou_senha)
            if erro:
                raise erro
            if PADRAO_PROMPT.search(limpar(acumulado)) or \
                    PADRAO_PAGINACAO.search(recente):
                self._logado = True
                return
            if self.encerrada:
                raise _erro_de_ssh(recente, enviou_senha) or ErroConexao(
                    "sessão ssh encerrada durante o login")
        if not recebeu_algo:
            raise ErroConexao(f"sem resposta de {self.host} em {timeout:.0f}s")
        self._logado = True
        # Recebeu algo, sem prompt reconhecido: a sessão pode estar viva com
        # prompt exótico. descobrir_prompt() decide depois.


class SessaoSSHAskpass(_Sessao):
    sem_terminal = True

    """Sessão SSH com a senha fornecida por SSH_ASKPASS, sem pseudoterminal.

    Alternativa para Windows, onde não há o módulo pty. O OpenSSH executa o
    programa apontado por SSH_ASKPASS para obter a senha; com
    SSH_ASKPASS_REQUIRE=force (OpenSSH 8.4 ou superior) isso ocorre mesmo sem
    terminal. A senha vai por variável de ambiente do processo auxiliar, não
    pela linha de comando, e o arquivo temporário é removido em seguida."""

    def __init__(self, host, usuario, senha, porta=22, timeout=30.0,
                 timeout_leitura=180.0):
        super().__init__(host, timeout_leitura)
        if not ssh_disponivel():
            raise ErroTransporte("cliente ssh não encontrado no sistema")
        if senha and versao_ssh() < (8, 4) and versao_ssh() != (0, 0):
            # SSH_ASKPASS_REQUIRE=force surgiu no OpenSSH 8.4. Antes disso o
            # cliente pediria a senha no console do operador e a sessão
            # ficaria parada.
            raise ErroTransporte(
                f"OpenSSH {versao_ssh()[0]}.{versao_ssh()[1]} não aceita senha "
                "por SSH_ASKPASS (requer 8.4+). Atualize o cliente OpenSSH ou "
                "use transporte='netmiko'.")
        self._dir = tempfile.mkdtemp(prefix="netsnap_")
        self.proc = None
        self._recusa = None
        env = dict(os.environ)
        if senha:
            # A senha é entregue uma única vez. Com password e
            # keyboard-interactive habilitados, o ssh chama o askpass de novo
            # para o segundo método, e responder outra vez dobraria as
            # tentativas falhas a cada senha errada. Encerrar o askpass com
            # erro não basta: o ssh envia então uma resposta vazia, que também
            # conta como tentativa. No segundo pedido o askpass marca a recusa
            # e espera; _confirmar_login vê a marca e encerra o ssh antes.
            if WINDOWS:
                # A senha não passa pelo interpretador do cmd: '%VAR%' sem
                # aspas faria & | < > ^ da senha virarem sintaxe do shell. O
                # próprio Python que executa o netsnap a imprime, em UTF-8 —
                # sys.stdout num pipe usaria a página de código ANSI.
                script = os.path.join(self._dir, "ask.cmd")
                conteudo = (
                    '@if exist "%~f0.usado" (type nul > "%~f0.recusada" & '
                    'ping -n 21 127.0.0.1 >nul & exit /b 1)\r\n'
                    '@type nul > "%~f0.usado"\r\n'
                    f'@"{sys.executable}" -c "import os,sys;'
                    "sys.stdout.buffer.write(os.environ['NETSNAP_PW']"
                    '.encode(\'utf-8\'))"\r\n')
                # O cmd lê o .cmd na página de código OEM: um caminho com
                # acento (C:\\Users\\João) gravado em ANSI ficaria ilegível.
                try:
                    dados = conteudo.encode("oem")
                except (LookupError, UnicodeEncodeError):
                    dados = conteudo.encode("mbcs", "replace")
                with open(script, "wb") as f:
                    f.write(dados)
            else:
                script = os.path.join(self._dir, "ask.sh")
                with open(script, "w") as f:
                    f.write("#!/bin/sh\n"
                            "if [ -e \"$0.usado\" ]; then "
                            ": > \"$0.recusada\"; sleep 20; exit 1; fi\n"
                            ": > \"$0.usado\"\n"
                            "printf '%s' \"$NETSNAP_PW\"\n")
                os.chmod(script, 0o700)
            self._recusa = script + ".recusada"
            env.update(NETSNAP_PW=senha, SSH_ASKPASS=script,
                       SSH_ASKPASS_REQUIRE="force", DISPLAY=env.get("DISPLAY", ":0"))
        try:
            self.proc = subprocess.Popen(
                _args_ssh(host, usuario, porta, bool(senha), "-T"),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env, bufsize=0,
                # Grupo próprio: ao fechar, o askpass que espera no segundo
                # pedido termina junto com o ssh.
                start_new_session=not WINDOWS)
            self._configurar_leitura_nao_bloqueante()
            self._confirmar_login(timeout)
        except BaseException:
            self.fechar()
            raise

    def _confirmar_login(self, timeout):
        """Aguarda a primeira saída da sessão ou a recusa do cliente.

        Sem terminal não há prompt garantido, então o critério é: erro do
        cliente ssh (recusa, inacessível) ou qualquer saída do equipamento.
        RADIUS/TACACS lentos podem levar vários segundos para recusar."""
        acumulado, inicio, cutucou = "", time.time(), False
        while time.time() - inicio < timeout:
            acumulado += self._ler_bruto(0.5)
            texto = limpar(acumulado)
            if self._recusa and os.path.exists(self._recusa):
                raise ErroAutenticacao("credenciais recusadas")
            # A marca '.usado' indica que o askpass já entregou a senha.
            erro = _erro_de_ssh(texto, bool(self._recusa) and os.path.exists(
                self._recusa.replace(".recusada", ".usado")))
            if erro:
                raise erro
            if texto.strip():
                return
            if self.encerrada:
                raise ErroConexao("sessão ssh encerrada durante o login")
            if not cutucou and time.time() - inicio > 5:
                # Equipamento que não envia nada antes do primeiro comando:
                # um retorno provoca o prompt. A senha vem do askpass, não
                # da entrada padrão, então a linha não interfere no login.
                self._escrever(b"\n")
                cutucou = True
        raise ErroConexao(f"sem resposta de {self.host} em {timeout:.0f}s")

    def _configurar_leitura_nao_bloqueante(self):
        if WINDOWS:
            self._fila = []
            import threading

            def bombear():
                while True:
                    # Num pipe do Windows, read(n) devolve o que estiver
                    # disponível, sem esperar completar n bytes.
                    d = self.proc.stdout.read(65536)
                    if not d:
                        self.encerrada = True
                        break
                    self._fila.append(d)
            threading.Thread(target=bombear, daemon=True).start()
        else:
            fl = fcntl.fcntl(self.proc.stdout, fcntl.F_GETFL)
            fcntl.fcntl(self.proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def _ler_bruto(self, tempo: float) -> str:
        if WINDOWS:
            fim = time.time() + tempo
            dados = b""
            while time.time() < fim:
                if self._fila:
                    # Retira só o que já estava na fila: um bloco acrescentado
                    # pela outra thread entre o join e um clear() se perderia.
                    n = len(self._fila)
                    dados += b"".join(self._fila[:n])
                    del self._fila[:n]
                    break
                time.sleep(0.05)
            return self._decodificar(dados)
        try:
            pronto, _, _ = select.select([self.proc.stdout], [], [], tempo)
        except (OSError, ValueError):
            self.encerrada = True
            return ""
        if not pronto:
            return ""
        dados = self.proc.stdout.read() or b""
        if not dados and self.proc.poll() is not None:
            self.encerrada = True
        return self._decodificar(dados)

    def _escrever(self, dados: bytes):
        try:
            self.proc.stdin.write(dados)
            self.proc.stdin.flush()
        except (OSError, ValueError) as e:
            self.encerrada = True
            raise ErroConexao(f"sessão ssh encerrada ({e})")

    def _fechar(self):
        for canal in ("stdin", "stdout"):
            try:
                getattr(self.proc, canal).close()
            except Exception:
                pass
        if not WINDOWS and self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except OSError:
                pass
        try:
            if self.proc is not None:
                self.proc.terminate()
                self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(self._dir, ignore_errors=True)


def _erro_de_ssh(texto: str, enviou_senha: bool = False):
    """Traduz mensagens do cliente OpenSSH em exceções do netsnap."""
    if not texto:
        return None
    if re.search(r"(?i)permission denied|authentication fail|"
                 r"too many authentication failures", texto):
        return ErroAutenticacao("credenciais recusadas")
    if enviou_senha and not re.search(r"(?i)kex_exchange_identification",
                                      texto) and \
            re.search(r"(?i)connection closed by|connection reset|"
                      r"received disconnect", texto):
        # Vários equipamentos derrubam a conexão diante de senha errada, em
        # vez de pedir de novo.
        return ErroAutenticacao("credenciais recusadas (conexão encerrada "
                                "após a senha)")
    if re.search(r"(?i)connection refused", texto):
        return ErroConexao("conexão recusada")
    if re.search(r"(?i)no route to host|network is unreachable", texto):
        return ErroConexao("sem rota até o host")
    if re.search(r"(?i)kex_exchange_identification|connection reset|"
                 r"connection closed by", texto):
        return ErroConexao("conexão encerrada pelo equipamento antes do login "
                           "(limite de sessões ou proteção contra força bruta)")
    if re.search(r"(?i)bad configuration option|unsupported option", texto):
        return ErroTransporte(f"opção não aceita por este cliente OpenSSH: "
                              f"{' '.join(texto.split())[-120:]}")
    if re.search(r"(?i)connection timed out|operation timed out", texto):
        return ErroConexao("tempo de conexão esgotado")
    if re.search(r"(?i)no matching (key exchange|host key|cipher|mac)", texto):
        return ErroConexao(
            "algoritmos incompatíveis: o equipamento usa criptografia que o "
            "cliente OpenSSH recusa por padrão, ou que esta versão do "
            "OpenSSH removeu. Acrescente o algoritmo indicado às listas "
            "LEGADO_* — só entram na conexão os que 'ssh -Q' reconhecer")
    if re.search(r"(?i)remote host identification has changed|"
                 r"host key verification failed", texto):
        return ErroConexao(
            "a chave SSH do equipamento é diferente da registrada no primeiro "
            "acesso — possível interceptação; a senha não foi enviada. Se o "
            "equipamento foi trocado ou teve a chave refeita, apague a linha "
            "dele em ~/.netsnap_known_hosts")
    if re.search(r"(?i)could not resolve hostname", texto):
        return ErroConexao("nome não resolvido")
    return None


# ---------------------------------------------------------------------------
# Netmiko — transporte alternativo, usado apenas quando disponível
#
# Mantido por dois motivos: permite comparar o comportamento em algum
# equipamento problemático, e cobre a máquina onde o cliente OpenSSH não
# esteja instalado nem possa ser instalado. Envolvido na mesma interface das
# demais sessões, de modo que quem chama não distingue um do outro.
# ---------------------------------------------------------------------------
def netmiko_disponivel() -> bool:
    """Presença do Netmiko, verificada sem importá-lo.

    A importação do Netmiko é lenta e carrega dezenas de módulos; basta saber
    se ele existe, o que o localizador de módulos responde sem executar nada."""
    try:
        import importlib.util
        return importlib.util.find_spec("netmiko") is not None
    except Exception:
        return False


class SessaoNetmiko(_Sessao):
    """Adaptação do Netmiko à interface de sessão do netsnap."""

    def __init__(self, host, usuario, senha, porta, driver,
                 timeout=30.0, timeout_leitura=180.0, usa_timing=False):
        super().__init__(host, timeout_leitura)
        from netmiko import ConnectHandler
        from netmiko.exceptions import (NetmikoAuthenticationException,
                                        NetmikoTimeoutException)
        self.usa_timing = usa_timing
        try:
            self.conn = ConnectHandler(
                device_type=driver, host=host, username=usuario,
                password=senha, port=porta, timeout=45, conn_timeout=15)
        except NetmikoAuthenticationException as e:
            raise ErroAutenticacao(str(e))
        except NetmikoTimeoutException as e:
            raise ErroConexao(str(e))
        except Exception as e:
            raise ErroConexao(f"{type(e).__name__}: {e}")

    def descobrir_prompt(self, tentativas=3) -> str:
        for _ in range(tentativas):
            try:
                bruto = self.conn.find_prompt()
            except Exception:
                return self.prompt
            if not PADRAO_PAGINACAO.search(bruto or ""):
                self.prompt = (bruto or "").strip()
                return self.prompt
            try:
                self.conn.write_channel(self.conn.RETURN)
                time.sleep(1.5)
                self.conn.read_channel()
            except Exception:
                break
        return self.prompt

    def executar(self, comando, tempo=None, paginacao_automatica=True) -> str:
        tempo = tempo or self.timeout_leitura
        try:
            if self.usa_timing:
                return self.conn.send_command_timing(
                    comando, read_timeout=tempo, last_read=3)
            return self.conn.send_command(comando, read_timeout=tempo)
        except Exception as e:
            if re.search(r"(?i)eof|closed|not connected", str(e)):
                self.encerrada = True
            return f"[ERRO ao executar comando: {e}]"

    def enviar(self, texto):
        self.conn.write_channel(texto + "\n")

    def _escrever(self, dados):
        self.conn.write_channel(dados.decode("utf-8", "replace"))

    def _ler_bruto(self, tempo):
        time.sleep(min(tempo, 0.3))
        try:
            return self.conn.read_channel()
        except Exception:
            self.encerrada = True
            return ""

    def _fechar(self):
        self.conn.disconnect()


# ---------------------------------------------------------------------------
# Ponto de entrada da camada
# ---------------------------------------------------------------------------
def transporte_padrao() -> str:
    """Transporte escolhido quando o operador não indica um.

    Prefere-se o nativo por não exigir instalação; o Netmiko entra apenas se
    o cliente OpenSSH estiver ausente e o Netmiko presente."""
    if ssh_disponivel():
        return "nativo"
    return "netmiko" if netmiko_disponivel() else "nativo"


def conectar(host, usuario, senha, porta=None, protocolo="ssh",
             timeout=30.0, timeout_leitura=180.0, preferir_pty=None,
             transporte="auto", driver=None, usa_timing=False):
    """Abre uma sessão com o equipamento e devolve o objeto de sessão.

    'transporte' aceita 'auto', 'nativo' ou 'netmiko'. Levanta
    ErroAutenticacao ou ErroConexao em qualquer um dos casos."""
    if transporte == "auto":
        # Telnet nativo não depende de nada; o Netmiko só entra em Telnet se
        # pedido explicitamente.
        transporte = "nativo" if protocolo == "telnet" else transporte_padrao()

    if transporte == "netmiko":
        if not netmiko_disponivel():
            raise ErroTransporte("netmiko solicitado mas não instalado")
        if not driver:
            raise ErroTransporte("transporte netmiko exige o device_type")
        return SessaoNetmiko(host, usuario, senha,
                             porta or (23 if protocolo == "telnet" else 22),
                             driver, timeout, timeout_leitura, usa_timing)

    if protocolo == "telnet":
        return SessaoTelnet(host, usuario, senha, porta or 23,
                            timeout, timeout_leitura)
    porta = porta or 22
    if not ssh_disponivel():
        extra = (" O netmiko está instalado: use transporte='netmiko'."
                 if netmiko_disponivel() else "")
        raise ErroTransporte(
            "cliente ssh não encontrado. Instale o OpenSSH (Linux: "
            "openssh-client; Windows: Configurações > Aplicativos > Recursos "
            "opcionais > Cliente OpenSSH)." + extra)
    usar_pty = TEM_PTY if preferir_pty is None else (preferir_pty and TEM_PTY)
    if usar_pty:
        return SessaoSSHPty(host, usuario, senha, porta, timeout,
                            timeout_leitura)
    return SessaoSSHAskpass(host, usuario, senha, porta, timeout,
                            timeout_leitura)


def ler_banner_ssh(host, porta=22, tempo=4.0):
    """Lê a identificação anunciada pelo servidor SSH, sem autenticar."""
    try:
        with socket.create_connection((host, porta), timeout=tempo) as s:
            s.settimeout(tempo)
            dados = b""
            while b"\n" not in dados and len(dados) < 512:
                pedaco = s.recv(256)
                if not pedaco:
                    break
                dados += pedaco
        return dados.decode("utf-8", "replace").strip() or None
    except OSError:
        return None


def ler_banner_telnet(host, porta=23, tempo=6.0):
    """Lê o texto inicial de uma sessão Telnet, sem autenticar.

    Devolve None se a porta não responde e "" se conecta sem texto. A
    negociação é respondida (recusando tudo): vários equipamentos só exibem
    o pedido de login depois que o cliente responde às opções."""
    limpo = bytearray()
    try:
        with socket.create_connection((host, porta), timeout=tempo) as s:
            s.settimeout(tempo)
            pendente = b""
            fim = time.time() + tempo
            while len(limpo) < 4096 and time.time() < fim:
                try:
                    pedaco = s.recv(512)
                except socket.timeout:
                    break
                if not pedaco:
                    break
                dados, pendente, i = pendente + pedaco, b"", 0
                while i < len(dados):
                    if dados[i] != IAC:
                        limpo.append(dados[i])
                        i += 1
                        continue
                    if i + 1 >= len(dados):
                        pendente = dados[i:]
                        break
                    cmd = dados[i + 1]
                    if cmd in (WILL, WONT, DO, DONT):
                        if i + 2 >= len(dados):
                            pendente = dados[i:]
                            break
                        if cmd == DO:
                            s.sendall(bytes((IAC, WONT, dados[i + 2])))
                        elif cmd == WILL:
                            s.sendall(bytes((IAC, DONT, dados[i + 2])))
                        i += 3
                    elif cmd == SB:
                        f = dados.find(bytes((IAC, SE)), i + 2)
                        if f < 0:
                            pendente = dados[i:]
                            break
                        i = f + 2
                    elif cmd == IAC:
                        limpo.append(IAC)
                        i += 2
                    else:
                        i += 2
                if re.search(rb"(?i)(name|login|user|password)\s*:\s*$",
                             bytes(limpo[-40:])):
                    break
    except OSError:
        return None
    texto = limpar(limpo.decode("utf-8", "replace")).replace("\x00", "")
    return texto.strip()


def diagnostico() -> dict:
    """Recursos de transporte disponíveis nesta máquina."""
    ssh = ssh_disponivel()
    versao = ""
    if ssh:
        try:
            r = subprocess.run([ssh, "-V"], capture_output=True, text=True,
                               timeout=5)
            versao = (r.stderr or r.stdout).strip().splitlines()[0]
        except Exception:
            pass
    legado = []
    for cat, desejados in (("kex", LEGADO_KEX), ("key", LEGADO_CHAVE),
                           ("cipher", LEGADO_CIFRA), ("mac", LEGADO_MAC)):
        conhecidos = _suportados(cat)
        legado += [a for a in desejados if a in conhecidos]
    ausentes = []
    for cat, desejados in (("kex", LEGADO_KEX), ("key", LEGADO_CHAVE),
                           ("cipher", LEGADO_CIFRA), ("mac", LEGADO_MAC)):
        conhecidos = _suportados(cat)
        ausentes += [a for a in desejados if a not in conhecidos]
    return {
        "python": sys.version.split()[0],
        "sistema": sys.platform,
        "ssh_binario": ssh or "ausente",
        "ssh_versao": versao,
        "pty": TEM_PTY,
        "estrategia_ssh": ("nenhuma" if not ssh else
                           "pty" if TEM_PTY else "askpass"),
        "telnet": "nativo (socket)",
        "netmiko": "instalado" if netmiko_disponivel() else "ausente",
        "transporte_padrao": transporte_padrao(),
        "algoritmos_legados_ativos": ", ".join(legado) or "nenhum",
        "removidos_nesta_versao": ", ".join(ausentes) or "nenhum",
        "dependencias_externas": [],
    }


if __name__ == "__main__":
    for chave, valor in diagnostico().items():
        print(f"{chave:24} {valor}")
