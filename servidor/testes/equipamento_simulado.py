#!/usr/bin/env python3
"""
Roteador Junos simulado por SSH, para os testes de integração do servidor.

Atende num IP de loopback (padrão 127.0.1.18, porta 22) com usuário
"netsnap" e senha "Lab#2026!". Responde os comandos que o perfil Junos do
netsnap envia com saídas sintéticas — nenhum dado de rede real.

Uso isolado:   sudo python3 equipamento_simulado.py [ip] [porta]
Nos testes:    iniciar(ip, porta) sobe o servidor numa thread.

Porta 22 exige root (ou CAP_NET_BIND_SERVICE). Em Linux todo o 127.0.0.0/8
responde no loopback, sem configurar nada.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import logging
import socket
import sys
import threading

import paramiko

USUARIO, SENHA = "netsnap", "Lab#2026!"
NOME = "MX-LAB-A"
PROMPT = f"{USUARIO}@{NOME}> "

SAIDAS = {
    "show version": f"Hostname: {NOME}\nModel: mx204\nJunos: 23.1R1-S1.3\n"
                    "JUNOS OS Kernel 64-bit",
    "show configuration | display set": (
        f"set system host-name {NOME}\n"
        "set interfaces et-0/0/2 description BACKBONE-MX-LAB-B\n"
        "set interfaces ae1 unit 0 family inet address 10.255.0.0/31\n"
        "set interfaces xe-0/0/5 unit 0 family inet address 10.255.0.2/31\n"
        "set protocols lldp interface all\n"),
    "show lldp": "LLDP                      : Enabled\n"
                 "Advertisement interval    : 30 seconds\n",
    "show lldp neighbors": (
        "Local Interface    Parent Interface    Chassis Id          Port info"
        "          System Name\n"
        "et-0/0/2           ae1                 78:4f:9b:00:00:00   "
        "BACKBONE-MX-LAB-A  MX-LAB-B"),
    "show lldp local-information": "LLDP Local Information details\n\n"
                                   "Chassis ID   : 78:4f:9b:aa:aa:aa\n"
                                   f"System name  : {NOME}\n",
    "show interfaces descriptions": (
        "Interface       Admin Link Description\n"
        "et-0/0/2        up    up   BACKBONE-MX-LAB-B\n"
        "xe-0/0/5        up    up   PARA-MX-LAB-C"),
}

_CHAVE = None


def responder(cmd):
    if cmd.startswith("set cli screen-length"):
        return "Screen length set to 0"
    if cmd.startswith("set cli screen-width"):
        return "Screen width set to 511"
    if cmd.startswith("set cli complete-on-space"):
        return "Disabling complete-on-space"
    if cmd in SAIDAS:
        return SAIDAS[cmd]
    return "                 ^\nsyntax error, expecting <command>."


class _Autenticacao(paramiko.ServerInterface):
    def __init__(self):
        self.shell = threading.Event()

    def check_auth_password(self, usuario, senha):
        ok = usuario == USUARIO and senha == SENHA
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, usuario):
        return "password"

    def check_channel_request(self, tipo, chanid):
        if tipo == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, canal):
        self.shell.set()
        return True


def _sessao(canal):
    canal.sendall(("\r\n" + PROMPT).encode())
    buf, ultimo_cr = "", False
    while True:
        try:
            dados = canal.recv(1024)
        except (OSError, EOFError):
            return
        if not dados:
            return
        for ch in dados.decode("latin-1"):
            if ch in "\r\n":
                if ch == "\n" and not buf and ultimo_cr:
                    ultimo_cr = False
                    continue
                ultimo_cr = ch == "\r"
                cmd, buf = buf.strip(), ""
                if cmd in ("exit", "quit"):
                    return
                saida = responder(cmd) if cmd else ""
                texto = "\r\n" + (saida.replace("\n", "\r\n") + "\r\n" if saida else "")
                canal.sendall((texto + PROMPT).encode())
            elif ch in "\x08\x7f":
                buf = buf[:-1]
            elif ch == "\x03":
                buf = ""
            else:
                buf += ch
                canal.sendall(ch.encode("latin-1"))


def _atender(sock):
    transporte = paramiko.Transport(sock)
    try:
        transporte.local_version = "SSH-2.0-OpenSSH_7.5"
        transporte.add_server_key(_CHAVE)
        aut = _Autenticacao()
        transporte.start_server(server=aut)
        canal = transporte.accept(20)
        if canal is None:
            return
        if aut.shell.wait(10):
            _sessao(canal)
        canal.close()
    except (paramiko.SSHException, OSError, EOFError):
        pass
    finally:
        transporte.close()


def iniciar(ip="127.0.1.18", porta=22):
    """Abre a porta e atende em segundo plano. Levanta OSError se não puder
    abrir (porta ocupada ou sem permissão)."""
    global _CHAVE
    # O netsnap lê só o banner SSH antes de conectar de fato; o paramiko
    # registraria cada uma dessas conexões curtas como erro.
    logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
    if _CHAVE is None:
        _CHAVE = paramiko.ECDSAKey.generate(bits=256)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, porta))
    s.listen(16)

    def laco():
        while True:
            try:
                conexao, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=_atender, args=(conexao,), daemon=True).start()

    threading.Thread(target=laco, daemon=True).start()
    return s


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.1.18"
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    iniciar(ip, porta)
    print(f"{NOME} simulado em {ip}:{porta} (usuário {USUARIO}). Ctrl+C encerra.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
