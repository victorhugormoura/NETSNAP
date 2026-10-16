#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnapctl — administração do servidor netsnap (executar como root)

Sem argumentos abre um menu interativo. Comandos:

  status                         situação do serviço, certificado e banco
  inicializar                    cria o banco (usado pelo instalador)
  usuario criar|listar|senha|totp|desbloquear|ativar|desativar|remover
  chave exportar [arquivo]       cópia da chave-mestra protegida por frase
  chave importar <arquivo>       restaura a chave (servidor reinstalado)
  certificado [ca-interna|letsencrypt|importar|renovar|mostrar]
  web configurar                 (re)gera o site do Nginx ou do Apache
  systemd instalar               (re)gera as unidades do systemd
  backup criar [pasta] | backup restaurar <arquivo>
  auditoria verificar

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

import argparse
import base64
import configparser
import datetime as dt
import getpass
import io
import ipaddress
import json
import os
import pwd
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

import netsnap_cofre as cofre_mod  # noqa: E402

ETC = "/etc/netsnap"
CONF_SERVIDOR = f"{ETC}/servidor.conf"
CONF_INSTALACAO = f"{ETC}/instalacao.conf"
PASTA_CREDENCIAIS = f"{ETC}/credenciais"
CHAVE_CRED = f"{PASTA_CREDENCIAIS}/chave-mestra.cred"
CHAVE_ARQ = f"{PASTA_CREDENCIAIS}/chave-mestra"
PKI = f"{ETC}/pki"
ACME = "/var/lib/netsnap-acme"
SOCKET = "/run/netsnap/netsnap.sock"
USUARIO_SERVICO = "netsnap"
UNIDADE = "netsnap-servidor"
PYTHON = sys.executable
APP = AQUI


def erro(msg, codigo=1):
    print(f"[ERRO] {msg}", file=sys.stderr)
    raise SystemExit(codigo)


def ok(msg):
    print(f"[OK] {msg}")


def info(msg):
    print(f"[..] {msg}")


def executar(argv, entrada=None, verificar=True, capturar=True):
    r = subprocess.run(argv, input=entrada, capture_output=capturar)
    if verificar and r.returncode != 0:
        saida = (r.stderr or r.stdout or b"").decode("utf-8", "replace").strip()
        erro(f"{' '.join(argv[:3])} falhou: {saida[-600:]}")
    return r


def exigir_root():
    if os.geteuid() != 0:
        erro("execute como root (sudo netsnapctl ...)")


# ---------------------------------------------------------------------------
# Perguntas
# ---------------------------------------------------------------------------
def perguntar(texto, padrao=None, validar=None):
    while True:
        sufixo = f" [{padrao}]" if padrao not in (None, "") else ""
        try:
            r = input(f"{texto}{sufixo}: ").strip()
        except EOFError:
            erro("entrada encerrada")
        if not r and padrao is not None:
            r = str(padrao)
        if not r:
            continue
        if validar:
            problema = validar(r)
            if problema:
                print(f"  -> {problema}")
                continue
        return r


def confirmar(texto, padrao=True):
    op = "S/n" if padrao else "s/N"
    while True:
        try:
            r = input(f"{texto} [{op}]: ").strip().lower()
        except EOFError:
            erro("entrada encerrada")
        if not r:
            return padrao
        if r in ("s", "sim", "y", "yes"):
            return True
        if r in ("n", "nao", "não", "no"):
            return False


def escolher(texto, opcoes, padrao=1):
    print(texto)
    for i, (_, rotulo) in enumerate(opcoes, 1):
        print(f"  {i}) {rotulo}")
    while True:
        r = perguntar("Opção", padrao)
        if r.isdigit() and 1 <= int(r) <= len(opcoes):
            return opcoes[int(r) - 1][0]


def ler_senha_nova(rotulo="Senha", usuario="", politica=True, minimo=0):
    while True:
        s1 = getpass.getpass(f"{rotulo}: ")
        problema = cofre_mod.problema_na_senha(s1, usuario) if politica else None
        if not problema and minimo and len(s1) < minimo:
            problema = f"use pelo menos {minimo} caracteres"
        if problema:
            print(f"  -> {problema}")
            continue
        if getpass.getpass("Repita: ") != s1:
            print("  -> as senhas não conferem")
            continue
        return s1


# ---------------------------------------------------------------------------
# Configuração da instalação
# ---------------------------------------------------------------------------
def ler_instalacao():
    cp = configparser.ConfigParser()
    cp.read(CONF_INSTALACAO, encoding="utf-8")
    if not cp.has_section("instalacao"):
        erro(f"{CONF_INSTALACAO} não encontrado; rode o instalador primeiro")
    s = cp["instalacao"]
    return {
        "web": s.get("servidor_web", "nginx"),
        "nomes": [n.strip() for n in s.get("nomes", "").split(",") if n.strip()],
        "porta_https": s.getint("porta_https", 443),
        "porta_interna": s.getint("porta_interna", 8765),
        "redes": [r.strip() for r in s.get("redes_permitidas", "").split(",")
                  if r.strip()],
        "certificado": s.get("certificado", "ca-interna"),
        "email": s.get("email_letsencrypt", ""),
        "modo_chave": s.get("modo_chave", "arquivo"),
        "dados": s.get("dados", "/var/lib/netsnap"),
    }


def gravar_instalacao(**campos):
    cp = configparser.ConfigParser()
    cp.read(CONF_INSTALACAO, encoding="utf-8")
    if not cp.has_section("instalacao"):
        cp.add_section("instalacao")
    for k, v in campos.items():
        cp["instalacao"][k] = ",".join(v) if isinstance(v, list) else str(v)
    tmp = CONF_INSTALACAO + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# Gerado pelo instalador/netsnapctl. Depois de editar, rode\n"
                "# 'netsnapctl web configurar' e, se mudar nomes, "
                "'netsnapctl certificado'.\n")
        cp.write(f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, CONF_INSTALACAO)


def eh_ip(texto):
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Chave-mestra
# ---------------------------------------------------------------------------
def ler_chave():
    if os.path.exists(CHAVE_CRED):
        r = executar(["systemd-creds", "decrypt", "--name=netsnap-chave",
                      CHAVE_CRED, "-"])
        return cofre_mod._decodificar_chave(r.stdout)
    if os.path.exists(CHAVE_ARQ):
        return cofre_mod.carregar_chave_mestra(CHAVE_ARQ)
    erro("chave-mestra não encontrada em " + PASTA_CREDENCIAIS)


def gravar_chave(chave, modo):
    os.makedirs(PASTA_CREDENCIAIS, mode=0o700, exist_ok=True)
    os.chmod(PASTA_CREDENCIAIS, 0o700)
    texto = cofre_mod.chave_para_texto(chave).encode()
    if modo == "credencial":
        tmp = CHAVE_CRED + ".tmp"
        # --with-key=auto: TPM2 + chave do host quando há TPM2; só a chave do
        # host (/var/lib/systemd/credential.secret) quando não há.
        executar(["systemd-creds", "encrypt", "--name=netsnap-chave",
                  "--with-key=auto", "-", tmp], entrada=texto)
        os.chmod(tmp, 0o400)
        os.replace(tmp, CHAVE_CRED)
        if os.path.exists(CHAVE_ARQ):
            os.remove(CHAVE_ARQ)
    else:
        tmp = CHAVE_ARQ + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
        with os.fdopen(fd, "wb") as f:
            f.write(texto + b"\n")
        os.replace(tmp, CHAVE_ARQ)
        if os.path.exists(CHAVE_CRED):
            os.remove(CHAVE_CRED)


def criar_chave_se_preciso(modo):
    if os.path.exists(CHAVE_CRED) or os.path.exists(CHAVE_ARQ):
        info("chave-mestra já existe; mantida")
        return False
    gravar_chave(cofre_mod.nova_chave_mestra(), modo)
    ok("chave-mestra criada (" + ("selada pelo systemd-creds"
                                  if modo == "credencial"
                                  else "arquivo legível só pelo root") + ")")
    return True


# ---------------------------------------------------------------------------
# Banco (sempre como o usuário do serviço, para não deixar arquivos do root)
# ---------------------------------------------------------------------------
def como_servico(funcao, *args):
    """Executa `funcao` num processo filho já rebaixado para o usuário do
    serviço e devolve o código de saída.

    Tudo o que mexe dentro de /var/lib/netsnap passa por aqui. A pasta é do
    serviço: um serviço comprometido poderia trocar um arquivo por link
    simbólico, e o root, seguindo o link, sobrescreveria ou mudaria o dono de
    um arquivo do sistema (/etc/shadow, por exemplo)."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        codigo = 1
        try:
            virar_usuario_servico()
            funcao(*args)
            codigo = 0
        except SystemExit as e:
            codigo = e.code if isinstance(e.code, int) else 1
        except Exception as e:
            print(f"[ERRO] {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(codigo)
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def virar_usuario_servico():
    pw = pwd.getpwnam(USUARIO_SERVICO)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.environ["HOME"] = pw.pw_dir
    os.umask(0o077)


def abrir_banco(chave=None):
    """Lê a chave como root, depois deixa de ser root e abre o banco."""
    import netsnap_banco as banco_mod
    chave = chave or ler_chave()
    cp = configparser.ConfigParser()
    cp.read(CONF_SERVIDOR, encoding="utf-8")
    dados = cp.get("servidor", "dados", fallback="/var/lib/netsnap")
    caminho = cp.get("servidor", "banco", fallback="") or \
        os.path.join(dados, "netsnap.db")
    if os.geteuid() == 0:
        virar_usuario_servico()
    return banco_mod.Banco(caminho, cofre_mod.Cofre(chave))


# ---------------------------------------------------------------------------
# Usuários
# ---------------------------------------------------------------------------
def mostrar_qr(texto):
    exe = shutil.which("qrencode")
    if exe:
        subprocess.run([exe, "-t", "ANSIUTF8", "-m", "1"], input=texto.encode())


def cadastrar_totp_no_terminal(banco, uid, nome):
    segredo = cofre_mod.novo_segredo_totp()
    uri = cofre_mod.uri_totp(segredo, nome, "netsnap")
    print("\nNo aplicativo autenticador, leia o QR code (ou digite a chave):")
    mostrar_qr(uri)
    print("Chave:", " ".join(segredo[i:i + 4] for i in range(0, len(segredo), 4)))
    for _ in range(5):
        cont = cofre_mod.conferir_totp(segredo, perguntar("Código de 6 dígitos"))
        if cont is not None:
            codigos = banco.ativar_totp(uid, segredo, cont)
            print("\nCódigos de recuperação (cada um vale uma vez; guarde fora "
                  "deste servidor):")
            for c in codigos:
                print("  ", c)
            return True
        print("  -> código inválido; confira o relógio do celular e do servidor")
    print("TOTP não ativado; será pedido no primeiro login pelo navegador.")
    return False


def cmd_usuario(args):
    exigir_root()
    banco = None
    acao = args.acao
    if acao == "listar":
        banco = abrir_banco()
        print(f"{'usuário':<20} {'perfil':<9} {'2FA':<4} {'situação':<12} último acesso")
        for u in banco.listar_usuarios():
            situ = ("desativado" if not u["ativo"] else
                    "bloqueado" if banco.bloqueado(u) else
                    "1º acesso" if u["trocar_senha"] else "ativo")
            print(f"{u['nome']:<20} {u['papel']:<9} "
                  f"{'sim' if u['totp_ativo'] else 'não':<4} {situ:<12} "
                  f"{u['ultimo_login'] or '—'}")
        return
    if acao == "criar":
        if getattr(args, "se_necessario", False):
            pid = os.fork()
            if pid == 0:
                tem = abrir_banco().admins_ativos()
                sys.stdout.flush()
                os._exit(0 if tem else 1)
            _, st = os.waitpid(pid, 0)
            if os.waitstatus_to_exitcode(st) == 0:
                info("já existe administrador; nenhum usuário criado")
                raise SystemExit(3)
        nome = args.nome or perguntar("Nome de usuário (minúsculas)")
        nome = nome.lower()
        completo = "" if args.nome else perguntar("Nome completo", "-")
        completo = "" if completo == "-" else completo
        papel = args.papel or ("admin" if args.inicial else escolher(
            "Perfil:", [("admin", "Administrador"), ("tecnico", "Técnico"),
                        ("leitura", "Somente leitura")], 2))
        if args.inicial:
            print("Senha pessoal do administrador.")
            senha = ler_senha_nova("Senha", nome)
        else:
            if confirmar("Gerar senha provisória aleatória?", True):
                senha = gerar_senha_provisoria()
                print(f"Senha provisória: {senha}")
            else:
                senha = ler_senha_nova("Senha provisória", nome)
        banco = abrir_banco()
        uid = banco.criar_usuario(nome, senha, papel, completo,
                                  trocar_senha=not args.inicial)
        banco.auditar("netsnapctl", "local", "usuario_criado", nome,
                      f"papel {papel}")
        ok(f"usuário {nome} criado ({papel})")
        if args.inicial:
            cadastrar_totp_no_terminal(banco, uid, nome)
        else:
            print("No primeiro acesso pelo navegador ele cadastra o "
                  "autenticador e define a senha pessoal.")
        return
    nome = args.nome or perguntar("Usuário")
    banco = abrir_banco()
    u = banco.usuario(nome=nome)
    if not u:
        erro(f"usuário {nome} não existe")
    if acao == "senha":
        senha = gerar_senha_provisoria()
        banco.trocar_senha(u["id"], senha, exigir_troca=True)
        banco.encerrar_sessoes_do_usuario(u["id"])
        banco.remover_dispositivos(u["id"])
        print(f"Senha provisória de {nome}: {senha}")
        print("Ele define a senha pessoal no próximo acesso.")
    elif acao == "totp":
        banco.resetar_totp(u["id"])
        ok(f"{nome} cadastra o autenticador de novo no próximo acesso")
    elif acao == "desbloquear":
        banco.desbloquear(u["id"])
        ok(f"{nome} desbloqueado")
    elif acao in ("ativar", "desativar"):
        if acao == "desativar" and u["papel"] == "admin" and \
                banco.admins_ativos() <= 1:
            erro("não é possível desativar o último administrador ativo")
        banco.alterar_usuario(u["id"], ativo=acao == "ativar")
        banco.encerrar_sessoes_do_usuario(u["id"])
        ok(f"{nome} {'ativado' if acao == 'ativar' else 'desativado'}")
    elif acao == "remover":
        if u["papel"] == "admin" and banco.admins_ativos() <= 1:
            erro("não é possível remover o último administrador ativo")
        if not confirmar(f"Remover {nome}?", False):
            return
        banco.remover_usuario(u["id"])
        ok(f"{nome} removido")
    banco.auditar("netsnapctl", "local", f"usuario_{acao}", nome)


def gerar_senha_provisoria():
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alfabeto) for _ in range(5))
                    for _ in range(4))


# ---------------------------------------------------------------------------
# Cópia da chave
# ---------------------------------------------------------------------------
def cmd_chave(args):
    exigir_root()
    if args.acao == "criar":
        criar_chave_se_preciso(ler_instalacao()["modo_chave"])
        return
    if args.acao == "exportar":
        chave = ler_chave()
        destino = args.arquivo or (
            f"/root/netsnap-chave-{socket.gethostname()}-"
            f"{dt.date.today():%Y%m%d}.json")
        print("A frase protege a cópia. Sem ela, a cópia não serve para nada;\n"
              "com ela, qualquer um decifra o cofre de um backup do banco.\n"
              "Use 16 ou mais caracteres e guarde num cofre de senhas.")
        frase = ler_senha_nova("Frase", politica=False, minimo=16)
        texto = cofre_mod.exportar_chave(chave, frase)
        if os.path.lexists(destino):
            destino = destino.replace(".json", f"-{dt.datetime.now():%H%M%S}.json")
        with abrir_destino_novo(destino) as f:
            f.write(texto.encode())
        ok(f"cópia gravada em {destino} (impressão {cofre_mod.Cofre(chave).impressao()})")
        print("Tire este arquivo do servidor e apague-o daqui: "
              f"shred -u {destino}")
    elif args.acao == "importar":
        if not args.arquivo:
            erro("informe o arquivo da cópia")
        with open(args.arquivo, encoding="utf-8") as f:
            texto = f.read()
        frase = getpass.getpass("Frase da cópia: ")
        chave = cofre_mod.importar_chave(texto, frase)
        if (os.path.exists(CHAVE_CRED) or os.path.exists(CHAVE_ARQ)) and \
                not confirmar("Substituir a chave-mestra atual?", False):
            return
        gravar_chave(chave, ler_instalacao()["modo_chave"])
        ok("chave importada; reiniciando o serviço")
        executar(["systemctl", "restart", UNIDADE], verificar=False)


# ---------------------------------------------------------------------------
# Certificados
# ---------------------------------------------------------------------------
def _validade(cert):
    return getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def _ler_cert(caminho):
    from cryptography import x509
    with open(caminho, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _gravar(caminho, dados, modo):
    tmp = caminho + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(fd, "wb") as f:
        f.write(dados)
    os.chmod(tmp, modo)
    os.replace(tmp, caminho)


def nomes_dns_ip(nomes):
    return ([n for n in nomes if not eh_ip(n)], [n for n in nomes if eh_ip(n)])


def gerar_ca_interna(nomes, forcar=False):
    """CA própria restrita (NameConstraints) aos nomes deste servidor: mesmo
    que a chave da CA vaze, ela não emite certificado aceito para outro site."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    os.makedirs(PKI, mode=0o700, exist_ok=True)
    os.chmod(PKI, 0o700)
    ca_crt, ca_key = f"{PKI}/ca.crt", f"{PKI}/ca.key"
    nomes_ca = f"{PKI}/ca.nomes"
    # "v2": restrições completas (tipo de nome ausente também restrito). Uma
    # CA de modelo anterior é recriada.
    chave_nomes = "v2|" + ",".join(sorted(n.lower() for n in nomes))
    if os.path.exists(ca_crt) and not forcar:
        anteriores = open(nomes_ca).read().strip() if os.path.exists(nomes_ca) \
            else ""
        if anteriores == chave_nomes:
            return False
        if anteriores.startswith("v2|"):
            info("os nomes do servidor mudaram: a CA interna será recriada e "
                 "os técnicos terão de instalar a nova")
    dns, ips = nomes_dns_ip(nomes)
    chave = ec.generate_private_key(ec.SECP384R1())
    sujeito = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,
                           f"netsnap CA interna ({socket.gethostname()[:40]})"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "netsnap")])
    permitidos = [x509.DNSName(n) for n in dns] + [
        x509.IPAddress(ipaddress.ip_network(ip)) for ip in ips]
    # Tipo de nome ausente na lista fica sem restrição (RFC 5280, 4.2.1.10):
    # sem nenhum DNS, só o domínio reservado ".invalid" é permitido; sem
    # nenhum IP, todos os IPs são excluídos.
    excluidos = None
    if not dns:
        permitidos.append(x509.DNSName("invalid"))
    if not ips:
        excluidos = [x509.IPAddress(ipaddress.ip_network("0.0.0.0/0")),
                     x509.IPAddress(ipaddress.ip_network("::/0"))]
    agora = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(sujeito).issuer_name(sujeito)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(agora - dt.timedelta(minutes=5))
            .not_valid_after(agora + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), True)
            .add_extension(x509.NameConstraints(permitted_subtrees=permitidos,
                                                excluded_subtrees=excluidos),
                           True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                chave.public_key()), False)
            .sign(chave, hashes.SHA384()))
    _gravar(ca_key, chave.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()), 0o400)
    _gravar(ca_crt, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _gravar(nomes_ca, chave_nomes.encode() + b"\n", 0o644)
    return True


def emitir_certificado_servidor(nomes, dias=397):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    ca_cert = _ler_cert(f"{PKI}/ca.crt")
    with open(f"{PKI}/ca.key", "rb") as f:
        ca_chave = serialization.load_pem_private_key(f.read(), None)
    dns, ips = nomes_dns_ip(nomes)
    chave = ec.generate_private_key(ec.SECP256R1())
    agora = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(n) for n in dns] + [
        x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                        nomes[0])]))
            .issuer_name(ca_cert.subject)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(agora - dt.timedelta(minutes=5))
            .not_valid_after(agora + dt.timedelta(days=dias))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), True)
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName(san), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                chave.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_chave.public_key()), False)
            .sign(ca_chave, hashes.SHA256()))
    _gravar(f"{PKI}/servidor.key", chave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), 0o400)
    _gravar(f"{PKI}/servidor.crt",
            cert.public_bytes(serialization.Encoding.PEM) +
            ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)


def publicar_ca(dados):
    """Copia a CA para o serviço oferecer na tela de login."""
    with open(f"{PKI}/ca.crt", "rb") as f:
        conteudo = f.read()

    def gravar():
        pasta = os.path.join(dados, "publico")
        os.makedirs(pasta, mode=0o700, exist_ok=True)
        _gravar(os.path.join(pasta, "netsnap-ca.crt"), conteudo, 0o600)
    if como_servico(gravar) != 0:
        erro("não foi possível publicar a CA para a tela de login")


def despublicar_ca(dados):
    def apagar():
        try:
            os.remove(os.path.join(dados, "publico", "netsnap-ca.crt"))
        except FileNotFoundError:
            pass
    como_servico(apagar)


def impressao_sha256(caminho):
    from cryptography.hazmat.primitives import hashes
    return ":".join(f"{b:02X}" for b in _ler_cert(caminho).fingerprint(
        hashes.SHA256()))


def caminhos_certificado(inst):
    if inst["certificado"] == "letsencrypt":
        base = f"/etc/letsencrypt/live/{inst['nomes'][0]}"
        if os.path.exists(f"{base}/fullchain.pem"):
            return f"{base}/fullchain.pem", f"{base}/privkey.pem"
    return f"{PKI}/servidor.crt", f"{PKI}/servidor.key"


def certificado_ca_interna(inst, forcar=False):
    nova = gerar_ca_interna(inst["nomes"], forcar)
    emitir_certificado_servidor(inst["nomes"])
    publicar_ca(inst["dados"])
    gravar_instalacao(certificado="ca-interna")
    ok("certificado emitido pela CA interna para: " + ", ".join(inst["nomes"]))
    print(f"  Impressão SHA-256 da CA: {impressao_sha256(f'{PKI}/ca.crt')}")
    if nova:
        print("  Os técnicos instalam a CA uma vez: botão na tela de login ou "
              f"{PKI}/ca.crt\n  (Windows: certmgr.msc > Autoridades de "
              "Certificação Raiz Confiáveis > Importar).")


def certificado_letsencrypt(inst, email):
    dns, ips = nomes_dns_ip(inst["nomes"])
    if ips or not dns:
        erro("Let's Encrypt aqui exige só nomes DNS públicos (sem IP). Use a "
             "CA interna ou remova os IPs da lista de nomes.")
    if not shutil.which("certbot"):
        erro("certbot não instalado (apt install certbot)")
    # O site precisa estar no ar (com certificado provisório) para o
    # desafio HTTP-01 em /.well-known/acme-challenge/.
    if not os.path.exists(f"{PKI}/servidor.crt"):
        certificado_ca_interna(inst)
        configurar_web(inst)
    os.makedirs(ACME, mode=0o755, exist_ok=True)
    recarga = "systemctl reload " + ("nginx" if inst["web"] == "nginx"
                                     else "apache2")
    argv = ["certbot", "certonly", "--webroot", "-w", ACME,
            "--non-interactive", "--agree-tos", "--email", email,
            "--cert-name", dns[0], "--deploy-hook", recarga]
    for n in dns:
        argv += ["-d", n]
    info("pedindo o certificado ao Let's Encrypt ...")
    r = subprocess.run(argv)
    if r.returncode != 0:
        erro("o certbot não conseguiu emitir. Confira se os nomes apontam "
             "para este servidor e se a porta 80 está aberta para a internet.")
    gravar_instalacao(certificado="letsencrypt", email_letsencrypt=email)
    despublicar_ca(inst["dados"])
    inst = ler_instalacao()
    configurar_web(inst)
    ok("certificado Let's Encrypt instalado; renovação automática pelo "
       "certbot.timer")


def certificado_importar(inst, cert, chave, cadeia=None):
    from cryptography.hazmat.primitives import serialization
    c = _ler_cert(cert)
    with open(chave, "rb") as f:
        k = serialization.load_pem_private_key(f.read(), None)
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if c.public_key().public_bytes(serialization.Encoding.PEM, pub) != \
            k.public_key().public_bytes(serialization.Encoding.PEM, pub):
        erro("o certificado e a chave não formam um par")
    if _validade(c) <= dt.datetime.now(dt.timezone.utc):
        erro("certificado vencido")
    os.makedirs(PKI, mode=0o700, exist_ok=True)
    corpo = open(cert, "rb").read()
    if cadeia:
        corpo = corpo.rstrip(b"\n") + b"\n" + open(cadeia, "rb").read()
    _gravar(f"{PKI}/servidor.crt", corpo, 0o644)
    _gravar(f"{PKI}/servidor.key", k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), 0o400)
    gravar_instalacao(certificado="importado")
    despublicar_ca(inst["dados"])
    ok(f"certificado importado (vale até {_validade(c):%d/%m/%Y})")


def mostrar_certificado(inst):
    from cryptography import x509
    crt, _ = caminhos_certificado(inst)
    if not os.path.exists(crt):
        print("Nenhum certificado instalado.")
        return None
    c = _ler_cert(crt)
    try:
        san = c.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        nomes = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
            [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        nomes = []
    dias = (_validade(c) - dt.datetime.now(dt.timezone.utc)).days
    print(f"Modo: {inst['certificado']}  Arquivo: {crt}")
    print(f"Emitido por: {c.issuer.rfc4514_string()}")
    print(f"Nomes: {', '.join(nomes)}")
    print(f"Vale até: {_validade(c):%d/%m/%Y} ({dias} dias)")
    if inst["certificado"] == "ca-interna" and os.path.exists(f"{PKI}/ca.crt"):
        print(f"Impressão SHA-256 da CA: {impressao_sha256(f'{PKI}/ca.crt')}")
    return dias


def cmd_certificado(args):
    exigir_root()
    inst = ler_instalacao()
    acao = args.acao
    if not acao:
        mostrar_certificado(inst)
        acao = escolher("\nO que fazer?", [
            ("ca-interna", "Emitir pela CA interna (rede interna, nomes ou IPs)"),
            ("letsencrypt", "Let's Encrypt (nome público e porta 80 aberta)"),
            ("importar", "Importar certificado próprio (.crt/.pem e chave)"),
            ("renovar", "Renovar agora"),
            ("sair", "Sair")], 5)
        if acao == "sair":
            return
    if acao == "mostrar":
        mostrar_certificado(inst)
        return
    if acao == "ca-interna":
        certificado_ca_interna(inst, forcar=args.forcar)
    elif acao == "letsencrypt":
        email = args.email or inst["email"] or perguntar(
            "E-mail para avisos do Let's Encrypt",
            validar=lambda e: None if "@" in e else "e-mail inválido")
        certificado_letsencrypt(inst, email)
        return
    elif acao == "importar":
        cert = args.cert or perguntar("Arquivo do certificado (PEM)")
        chave = args.chave or perguntar("Arquivo da chave privada (PEM)")
        cadeia = args.cadeia
        if not args.cert:
            r = perguntar("Cadeia intermediária (PEM, vazio se já está no "
                          "certificado)", "")
            cadeia = r or None
        certificado_importar(inst, cert, chave, cadeia)
    elif acao == "renovar":
        if inst["certificado"] == "letsencrypt":
            executar(["certbot", "renew", "--quiet"], verificar=False)
            return
        if inst["certificado"] == "importado":
            dias = mostrar_certificado(inst)
            if dias is not None and dias < 30:
                print("[!] certificado importado vence em menos de 30 dias; "
                      "importe o novo com 'netsnapctl certificado importar'")
            return
        crt, _ = caminhos_certificado(inst)
        nomes_ca = f"{PKI}/ca.nomes"
        ca_antiga = not os.path.exists(nomes_ca) or \
            not open(nomes_ca).read().startswith("v2|")
        if args.se_necessario and os.path.exists(crt) and not ca_antiga:
            dias = (_validade(_ler_cert(crt)) -
                    dt.datetime.now(dt.timezone.utc)).days
            if dias > 30:
                return
        if ca_antiga:
            info("CA interna de modelo anterior: será recriada com as "
                 "restrições completas (os técnicos instalam a nova)")
        certificado_ca_interna(inst)
    configurar_web(inst)


# ---------------------------------------------------------------------------
# Nginx / Apache
# ---------------------------------------------------------------------------
CIFRAS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
          "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")

MODELO_NGINX = """# Gerado pelo netsnapctl em {data}. Não edite: é sobrescrito por
# 'netsnapctl web configurar'. Ajustes em /etc/netsnap/instalacao.conf.

# Limite de tentativas de login por IP (só POST conta).
map $request_method $netsnap_login_chave {{
    POST    $binary_remote_addr;
    default "";
}}
limit_req_zone $netsnap_login_chave zone=netsnap_login:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=netsnap_api:10m rate=30r/s;

# O serviço escuta só neste socket, acessível ao grupo do Nginx (www-data).
upstream netsnap_servidor {{
    server unix:{socket};
    keepalive 8;
}}

server {{
    listen 80;
{listen6_80}    server_name {nomes};
    server_tokens off;
{acesso}
    location ^~ /.well-known/acme-challenge/ {{
        root {acme};
        default_type text/plain;
    }}
    location / {{
        return 301 https://$host{sufixo_porta}$request_uri;
    }}
}}

server {{
    listen {porta} ssl http2;
{listen6_tls}    server_name {nomes};
    server_tokens off;

    ssl_certificate     {cert};
    ssl_certificate_key {chave};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers {cifras};
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:netsnap_tls:10m;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    client_max_body_size 2m;
    client_body_timeout 30s;
    client_header_timeout 30s;
{acesso}
    location ~ ^/api/sessao(/etapa)?$ {{
        limit_req zone=netsnap_login burst=20 nodelay;
        limit_req_status 429;
        include /etc/nginx/netsnap-proxy.conf;
    }}
    location / {{
        limit_req zone=netsnap_api burst=80 nodelay;
        limit_req_status 429;
        include /etc/nginx/netsnap-proxy.conf;
    }}
}}
"""

MODELO_NGINX_PROXY = """# Gerado pelo netsnapctl. Incluído pelo site do netsnap.
proxy_pass http://netsnap_servidor;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 300s;
proxy_send_timeout 60s;
"""

MODELO_APACHE = """# Gerado pelo netsnapctl em {data}. Não edite: é sobrescrito por
# 'netsnapctl web configurar'. Ajustes em /etc/netsnap/instalacao.conf.
{listen}
<VirtualHost *:80>
    ServerName {nome}
{aliases}
    Alias /.well-known/acme-challenge/ {acme}/.well-known/acme-challenge/
    <Directory {acme}/.well-known/acme-challenge/>
        Require all granted
    </Directory>
    RewriteEngine On
    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/
    RewriteRule ^ https://%{{SERVER_NAME}}{sufixo_porta}%{{REQUEST_URI}} [R=301,L]
</VirtualHost>

<VirtualHost *:{porta}>
    ServerName {nome}
{aliases}
    SSLEngine on
    SSLCertificateFile {cert}
    SSLCertificateKeyFile {chave}
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite {cifras}
    SSLHonorCipherOrder off
    SSLSessionTickets off

    Header always set Strict-Transport-Security "max-age=63072000"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

    LimitRequestBody 2097152
    RequestReadTimeout header=20-40,MinRate=500 body=30,MinRate=500

    ProxyRequests Off
    ProxyPreserveHost On
    RewriteEngine On
    RewriteRule .* - [E=NETSNAP_IP:%{{REMOTE_ADDR}}]
    RequestHeader set X-Real-IP "%{{NETSNAP_IP}}e"
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass        / "unix:{socket}|http://netsnap/" timeout=300
    ProxyPassReverse / "unix:{socket}|http://netsnap/"

    <Location />
{acesso_apache}
    </Location>
</VirtualHost>
"""


def caminhos_web(web):
    if web == "nginx":
        return ("/etc/nginx/sites-available/netsnap.conf",
                "/etc/nginx/sites-enabled/netsnap.conf")
    return ("/etc/apache2/sites-available/netsnap.conf",
            "/etc/apache2/sites-enabled/netsnap.conf")


def ipv6_disponivel():
    """IPv6 desativado no kernel faz o Nginx recusar 'listen [::]'."""
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
        return True
    except OSError:
        return False


def gerar_conf_web(inst):
    cert, chave = caminhos_certificado(inst)
    porta = inst["porta_https"]
    sufixo = "" if porta == 443 else f":{porta}"
    data = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    for r in inst["redes"]:
        ipaddress.ip_network(r, strict=False)  # valida antes de escrever
    if inst["web"] == "nginx":
        acesso = "".join(f"    allow {r};\n" for r in inst["redes"])
        if inst["redes"]:
            acesso += "    allow 127.0.0.1;\n    deny all;\n"
        v6 = ipv6_disponivel()
        return MODELO_NGINX.format(
            socket=SOCKET,
            listen6_80="    listen [::]:80;\n" if v6 else "",
            listen6_tls=f"    listen [::]:{porta} ssl http2;\n" if v6 else "",
            data=data, nomes=" ".join(inst["nomes"]), acesso=acesso, acme=ACME,
            sufixo_porta=sufixo, porta=porta, cert=cert, chave=chave,
            cifras=CIFRAS), MODELO_NGINX_PROXY
    acesso = ("        Require ip " + " ".join(inst["redes"] + ["127.0.0.1"])
              if inst["redes"] else "        Require all granted")
    return MODELO_APACHE.format(
        data=data, nome=inst["nomes"][0],
        aliases="".join(f"    ServerAlias {n}\n" for n in inst["nomes"][1:]),
        listen="" if porta == 443 else f"Listen {porta}\n", acme=ACME,
        sufixo_porta=sufixo, porta=porta, cert=cert, chave=chave,
        cifras=CIFRAS, socket=SOCKET, acesso_apache=acesso), None


def remover_site_do_outro(web):
    """Trocou de Nginx para Apache (ou o contrário): tira o site do netsnap
    do servidor anterior, que senão continua segurando as portas 80/443."""
    outro = "apache" if web == "nginx" else "nginx"
    disponivel, ativo = caminhos_web(outro)
    extras = ["/etc/nginx/netsnap-proxy.conf"] if outro == "nginx" else []
    if not any(os.path.lexists(c) for c in [disponivel, ativo] + extras):
        return
    for c in [ativo, disponivel] + extras:
        if os.path.lexists(c):
            os.remove(c)
    servico = "nginx" if outro == "nginx" else "apache2"
    r = subprocess.run(["systemctl", "is-active", servico], capture_output=True)
    if r.stdout.strip() == b"active":
        if confirmar(f"O {servico} não publica mais o netsnap. Parar e desativar "
                     f"o {servico} (libera as portas 80/443)?", True):
            executar(["systemctl", "disable", "--now", servico], verificar=False)
        else:
            executar(["systemctl", "reload", servico], verificar=False)
    info(f"site do netsnap removido do {servico}")


def configurar_web(inst=None):
    inst = inst or ler_instalacao()
    remover_site_do_outro(inst["web"])
    os.makedirs(ACME, mode=0o755, exist_ok=True)
    conf, extra = gerar_conf_web(inst)
    disponivel, ativo = caminhos_web(inst["web"])
    backups = []
    alvos = [(disponivel, conf)]
    if extra:
        alvos.append(("/etc/nginx/netsnap-proxy.conf", extra))
    for caminho, conteudo in alvos:
        anterior = None
        if os.path.exists(caminho):
            anterior = open(caminho, encoding="utf-8").read()
        backups.append((caminho, anterior))
        _gravar(caminho, conteudo.encode("utf-8"), 0o644)
    criado_link = False
    if not os.path.lexists(ativo):
        os.symlink(disponivel, ativo)
        criado_link = True
    if inst["web"] == "apache":
        executar(["a2enmod", "-q", "ssl", "proxy", "proxy_http", "headers",
                  "rewrite", "reqtimeout"])
        teste = ["apache2ctl", "configtest"]
        recarga = ["systemctl", "reload", "apache2"]
    else:
        teste = ["nginx", "-t"]
        recarga = ["systemctl", "reload", "nginx"]
    r = subprocess.run(teste, capture_output=True)
    if r.returncode != 0:
        for caminho, anterior in backups:
            if anterior is None:
                os.remove(caminho)
            else:
                _gravar(caminho, anterior.encode("utf-8"), 0o644)
        if criado_link:
            os.remove(ativo)
        erro("configuração recusada pelo " + inst["web"] +
             "; a anterior foi mantida:\n" +
             r.stderr.decode("utf-8", "replace")[-1500:])
    r = subprocess.run(recarga, capture_output=True)
    if r.returncode != 0:
        # Primeira vez: o serviço pode não estar rodando ainda.
        executar(["systemctl", "restart", recarga[-1]], verificar=False)
    ok(f"{inst['web']} configurado: https://{inst['nomes'][0]}"
       + ("" if inst["porta_https"] == 443 else f":{inst['porta_https']}") + "/")


def cmd_web(args):
    exigir_root()
    configurar_web()


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------
MODELO_UNIDADE = """# Gerado pelo netsnapctl. Ajustes locais: systemctl edit {unidade}
[Unit]
Description=netsnap — servidor de coletas
Documentation=file:///opt/netsnap/LEIA-ME.md
After=network-online.target {unidade}.socket
Wants=network-online.target
Requires={unidade}.socket

[Service]
Type=simple
User={usuario}
Group={usuario}
Environment=HOME={dados}
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStart={python} {app}/netsnap_servidor.py --config {conf}
{credencial}
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={dados}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ProtectProc=invisible
TasksMax=4096
MemoryMax=75%

[Install]
WantedBy=multi-user.target
"""

MODELO_SOCKET = """# Gerado pelo netsnapctl.
# O serviço não escuta em porta TCP: só o Nginx/Apache (grupo www-data) e o
# root conectam neste socket. Outro usuário da máquina não alcança a API nem
# forja o IP de origem.
[Unit]
Description=netsnap — socket do servidor

[Socket]
ListenStream={socket}
SocketUser={usuario}
SocketGroup=www-data
SocketMode=0660
DirectoryMode=0755

[Install]
WantedBy=sockets.target
"""

MODELO_RENOVA_SERVICE = """# Gerado pelo netsnapctl.
[Unit]
Description=netsnap — renovação do certificado da CA interna

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/netsnapctl certificado renovar --se-necessario
"""

MODELO_RENOVA_TIMER = """# Gerado pelo netsnapctl.
[Unit]
Description=netsnap — verifica o certificado diariamente

[Timer]
OnCalendar=daily
RandomizedDelaySec=3h
Persistent=true

[Install]
WantedBy=timers.target
"""


def instalar_systemd(inst=None):
    inst = inst or ler_instalacao()
    if os.path.exists(CHAVE_CRED):
        credencial = f"LoadCredentialEncrypted=netsnap-chave:{CHAVE_CRED}"
    else:
        credencial = f"LoadCredential=netsnap-chave:{CHAVE_ARQ}"
    unidade = MODELO_UNIDADE.format(
        unidade=UNIDADE, usuario=USUARIO_SERVICO, dados=inst["dados"],
        python=PYTHON, app=APP, conf=CONF_SERVIDOR, credencial=credencial)
    _gravar(f"/etc/systemd/system/{UNIDADE}.service", unidade.encode(), 0o644)
    _gravar(f"/etc/systemd/system/{UNIDADE}.socket", MODELO_SOCKET.format(
        socket=SOCKET, usuario=USUARIO_SERVICO).encode(), 0o644)
    _gravar("/etc/systemd/system/netsnap-certificado.service",
            MODELO_RENOVA_SERVICE.encode(), 0o644)
    _gravar("/etc/systemd/system/netsnap-certificado.timer",
            MODELO_RENOVA_TIMER.encode(), 0o644)
    executar(["systemctl", "daemon-reload"])
    executar(["systemctl", "enable", "--now", f"{UNIDADE}.socket"])
    # O serviço também sobe no boot (não só na primeira conexão): o agendador
    # precisa rodar sem ninguém acessar o painel.
    executar(["systemctl", "enable", "--now", f"{UNIDADE}.service"])
    executar(["systemctl", "enable", "--now", "netsnap-certificado.timer"])
    ok("serviço netsnap-servidor ativo e habilitado no boot")


def cmd_systemd(args):
    exigir_root()
    instalar_systemd()


# ---------------------------------------------------------------------------
# Backup cifrado (AES-256-GCM em blocos, chave derivada da frase com scrypt)
# ---------------------------------------------------------------------------
MAGICO = b"NETSNAP-BACKUP/2\n"
BLOCO = 1 << 20


def _cifrador(frase, cabecalho):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k = cabecalho["kdf"]
    chave = cofre_mod._scrypt(frase, base64.b64decode(k["sal"]),
                              int(k["n_log2"]), int(k["r"]), int(k["p"]),
                              espera=120)
    return AESGCM(chave)


def ler_bloco(f, n):
    """Lê até n bytes (menos só no fim do fluxo): pipes entregam aos pedaços."""
    partes, total = [], 0
    while total < n:
        d = f.read(n - total)
        if not d:
            break
        partes.append(d)
        total += len(d)
    return b"".join(partes)


def abrir_destino_novo(caminho):
    """Arquivo novo, nunca um existente nem através de link simbólico."""
    fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def cifrar_fluxo(entrada, saida, frase):
    """AES-256-GCM em blocos de 1 MiB. Índice e marca de último bloco vão
    no AAD: trocar a ordem, repetir ou cortar blocos é detectado."""
    cab = {"kdf": {"alg": "scrypt", "n_log2": cofre_mod.SCRYPT_N_LOG2,
                   "r": cofre_mod.SCRYPT_R, "p": cofre_mod.SCRYPT_P,
                   "sal": base64.b64encode(secrets.token_bytes(16)).decode()},
           "prefixo": base64.b64encode(secrets.token_bytes(8)).decode(),
           "bloco": BLOCO}
    linha = json.dumps(cab).encode() + b"\n"
    aead = _cifrador(frase, cab)
    prefixo = base64.b64decode(cab["prefixo"])
    saida.write(MAGICO + linha)
    indice, atual = 0, ler_bloco(entrada, BLOCO)
    while True:
        proximo = ler_bloco(entrada, BLOCO)
        final = not proximo
        aad = linha + struct.pack(">IB", indice, final)
        c = aead.encrypt(prefixo + struct.pack(">I", indice), atual, aad)
        saida.write(struct.pack(">I", len(c)) + c)
        if final:
            return
        indice, atual = indice + 1, proximo


def _ler_bloco_cifrado(entrada, linha, prefixo, aead, indice):
    """Lê e decifra um bloco. Devolve (dados, é_o_último)."""
    from cryptography.exceptions import InvalidTag
    tam = ler_bloco(entrada, 4)
    if len(tam) < 4:
        erro("backup truncado")
    n = struct.unpack(">I", tam)[0]
    if n > BLOCO + 16:
        erro("backup corrompido (bloco grande demais)")
    c = ler_bloco(entrada, n)
    if len(c) != n:
        erro("backup truncado")
    for final in (False, True):
        try:
            return aead.decrypt(prefixo + struct.pack(">I", indice), c,
                                linha + struct.pack(">IB", indice, final)), final
        except InvalidTag:
            continue
    erro("frase incorreta ou backup adulterado")


def abrir_backup(entrada, frase):
    """Lê o cabeçalho, deriva a chave e decifra o primeiro bloco. Tudo antes
    de pedir confirmação e de parar o serviço: frase errada ou arquivo
    inválido não derrubam nada."""
    if entrada.read(len(MAGICO)) != MAGICO:
        erro("arquivo não é um backup desta versão do netsnap")
    linha = entrada.readline(4096)
    try:
        cab = json.loads(linha)
        if cab.get("bloco") != BLOCO:
            raise ValueError
        prefixo = base64.b64decode(cab["prefixo"])
        if len(prefixo) != 8:
            raise ValueError
        aead = _cifrador(frase, cab)
    except (ValueError, KeyError, TypeError, cofre_mod.ErroCofre):
        erro("cabeçalho do backup inválido")
    primeiro = _ler_bloco_cifrado(entrada, linha, prefixo, aead, 0)
    return {"linha": linha, "prefixo": prefixo, "aead": aead,
            "primeiro": primeiro}


def decifrar_fluxo(entrada, saida, estado):
    dados, final = estado["primeiro"]
    saida.write(dados)
    indice = 1
    while not final:
        dados, final = _ler_bloco_cifrado(entrada, estado["linha"],
                                          estado["prefixo"], estado["aead"],
                                          indice)
        saida.write(dados)
        indice += 1


def ler_frase_arquivo(caminho):
    """Frase de backup num arquivo, para agendar pelo cron do root."""
    st = os.stat(caminho)
    if st.st_uid != 0 or st.st_mode & 0o077:
        erro(f"{caminho} precisa ser do root com permissão 600")
    with open(caminho, encoding="utf-8") as f:
        frase = f.readline().rstrip("\n")
    if len(frase) < 16:
        erro("a frase do arquivo precisa ter 16 ou mais caracteres")
    return frase


def processo_servico(funcao, *args):
    """Como como_servico, mas sem esperar: devolve o pid do filho."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        codigo = 1
        try:
            virar_usuario_servico()
            funcao(*args)
            codigo = 0
        except SystemExit as e:
            codigo = e.code if isinstance(e.code, int) else 1
        except Exception as e:
            print(f"[ERRO] {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(codigo)
    return pid


def esperar(pid):
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def _adicionar_bytes(t, nome, dados, modo=0o600):
    item = tarfile.TarInfo(nome)
    item.size, item.mode = len(dados), modo
    t.addfile(item, io.BytesIO(dados))


# Conteúdo do backup (antes da cifra):
#   8 bytes  tamanho N da parte do root
#   N bytes  tar com chave-mestra, configuração e PKI (montado pelo root)
#   resto    tar.gz com os dados do serviço (montado sem privilégio)
# As duas partes são produzidas e consumidas por processos diferentes: o
# processo sem privilégio nunca vê a chave, a frase nem a PKI.


def empacotar_dados(fd_saida, dados):
    """Filho, como usuário do serviço, criado antes de qualquer segredo ser
    lido: escreve o tar.gz dos dados no pipe."""
    with os.fdopen(fd_saida, "wb") as pipe, \
            tarfile.open(fileobj=pipe, mode="w|gz") as t:
        con = sqlite3.connect(os.path.join(dados, "netsnap.db"))
        con.execute("BEGIN")  # leitura consistente com o serviço gravando
        _adicionar_bytes(t, "netsnap.sql",
                         "\n".join(con.iterdump()).encode("utf-8"))
        con.close()
        for sub in ("snapshots", "diagnosticos", "analises", "publico",
                    ".netsnap_known_hosts"):
            c = os.path.join(dados, sub)
            if os.path.lexists(c) and not os.path.islink(c):
                t.add(c, sub)


def parte_do_root():
    """Tar em memória com chave, configuração e PKI."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        _adicionar_bytes(t, "chave-mestra",
                         cofre_mod.chave_para_texto(ler_chave()).encode())
        for c in (CONF_SERVIDOR, CONF_INSTALACAO):
            if os.path.isfile(c):
                with open(c, "rb") as f:
                    _adicionar_bytes(t, "etc/" + os.path.basename(c), f.read())
        if os.path.isdir(PKI):
            for n in sorted(os.listdir(PKI)):
                c = os.path.join(PKI, n)
                if os.path.isfile(c) and not os.path.islink(c):
                    with open(c, "rb") as f:
                        _adicionar_bytes(t, f"etc/pki/{n}", f.read())
    return buf.getvalue()


class Concatenado:
    """Leitor que entrega `inicio` e depois o conteúdo de `resto`."""

    def __init__(self, inicio, resto):
        self.inicio, self.resto = inicio, resto

    def read(self, n):
        if self.inicio:
            parte, self.inicio = self.inicio[:n], self.inicio[n:]
            return parte
        return self.resto.read(n)


class Divisor:
    """Escritor que separa o conteúdo decifrado: a parte do root fica em
    memória; o resto segue pelo pipe para o processo sem privilégio."""

    def __init__(self, destino):
        self.destino = destino
        self.cabecalho = b""
        self.raiz = bytearray()
        self.tamanho = None

    def write(self, dados):
        if self.tamanho is None:
            falta = 8 - len(self.cabecalho)
            self.cabecalho += dados[:falta]
            dados = dados[falta:]
            if len(self.cabecalho) < 8:
                return
            self.tamanho = struct.unpack(">Q", self.cabecalho)[0]
            if self.tamanho > 64 * 2 ** 20:
                raise ValueError("parte do root grande demais")
        falta = self.tamanho - len(self.raiz)
        if falta > 0:
            self.raiz += dados[:falta]
            dados = dados[falta:]
        if dados:
            self.destino.write(dados)


def nome_seguro_backup(nome):
    partes = nome.split("/")
    return not (nome.startswith("/") or ".." in partes or "" in partes)


def desempacotar_dados(fd_entrada, fd_sinal, dados):
    """Filho, como usuário do serviço: extrai o tar.gz dos dados numa pasta
    de preparo e só troca depois que o root confirmar que o backup inteiro
    foi autenticado. Saída 1: nada mudou; saída 2: a troca falhou no meio."""
    preparo = os.path.join(dados, ".restauracao")
    if os.path.islink(preparo) or os.path.isfile(preparo):
        os.remove(preparo)
    elif os.path.isdir(preparo):
        shutil.rmtree(preparo)
    os.mkdir(preparo, 0o700)
    try:
        with os.fdopen(fd_entrada, "rb") as entrada, \
                tarfile.open(fileobj=entrada, mode="r|gz") as t:
            for m in t:
                if not nome_seguro_backup(m.name) or \
                        not (m.isfile() or m.isdir()):
                    raise ValueError(f"entrada suspeita no backup: {m.name}")
                try:
                    t.extract(m, preparo, filter="data")
                except TypeError:  # Python sem o filtro de extração
                    t.extract(m, preparo)
        with os.fdopen(fd_sinal, "rb") as sinal:
            if sinal.read(2) != b"OK":
                raise EOFError
        sql = os.path.join(preparo, "netsnap.sql")
        con = sqlite3.connect(os.path.join(preparo, "netsnap.db"))
        with open(sql, encoding="utf-8") as f:
            con.executescript(f.read())
        con.close()
        os.remove(sql)
    except (tarfile.TarError, EOFError, OSError, ValueError,
            sqlite3.Error) as e:
        shutil.rmtree(preparo, ignore_errors=True)
        # Fluxo cortado porque o root parou de decifrar (frase errada,
        # adulteração): o root já explicou; aqui só o código de saída.
        if not isinstance(e, (tarfile.ReadError, EOFError, BrokenPipeError)):
            print(f"[ERRO] {type(e).__name__}: {e}", file=sys.stderr)
        raise SystemExit(1)
    try:
        for item in os.listdir(preparo):
            alvo = os.path.join(dados, item)
            if os.path.islink(alvo) or os.path.isfile(alvo):
                os.remove(alvo)
            elif os.path.isdir(alvo):
                shutil.rmtree(alvo)
            os.rename(os.path.join(preparo, item), alvo)
        os.rmdir(preparo)
        for sufixo in ("-wal", "-shm"):
            try:
                os.remove(os.path.join(dados, "netsnap.db" + sufixo))
            except FileNotFoundError:
                pass
        for raiz, pastas, arquivos in os.walk(dados):
            for n in pastas:
                os.chmod(os.path.join(raiz, n), 0o700)
            for n in arquivos:
                c = os.path.join(raiz, n)
                if not os.path.islink(c):
                    os.chmod(c, 0o600)
    except OSError as e:
        print(f"[ERRO] troca dos dados interrompida: {e}", file=sys.stderr)
        raise SystemExit(2)


def cmd_backup(args):
    exigir_root()
    inst = ler_instalacao()
    dados = inst["dados"]
    if args.acao == "criar":
        pasta = args.arquivo or "/root"
        destino = os.path.join(pasta, f"netsnap-backup-{socket.gethostname()}-"
                                      f"{dt.datetime.now():%Y%m%d_%H%M%S}.nsbk")
        # O filho nasce antes de qualquer segredo ser lido.
        r, w = os.pipe()
        pid = processo_servico(lambda: (os.close(r), empacotar_dados(w, dados)))
        os.close(w)
        entrada = os.fdopen(r, "rb")
        try:
            if args.frase_arquivo:
                frase = ler_frase_arquivo(args.frase_arquivo)
            else:
                print("O backup leva banco, snapshots, pacotes, configuração, "
                      "PKI e a chave-mestra,\ncifrados com a frase abaixo (16+ "
                      "caracteres).")
                frase = ler_senha_nova("Frase do backup", politica=False,
                                       minimo=16)
            raiz = parte_do_root()
            saida = abrir_destino_novo(destino)
        except BaseException:
            entrada.close()
            esperar(pid)
            raise
        completo = False
        try:
            with saida:
                cifrar_fluxo(Concatenado(struct.pack(">Q", len(raiz)) + raiz,
                                         entrada), saida, frase)
            completo = True
        finally:
            entrada.close()
            codigo = esperar(pid)
            if not completo or codigo != 0:
                try:
                    os.remove(destino)
                except FileNotFoundError:
                    pass
        if codigo != 0:
            erro("não foi possível ler os dados do serviço; backup descartado")
        ok(f"backup cifrado: {destino} ({os.path.getsize(destino) // 1024} KiB)")
        print("Copie para fora do servidor. Restauração: "
              "netsnapctl backup restaurar <arquivo>")
    elif args.acao == "restaurar":
        if not args.arquivo:
            erro("informe o arquivo .nsbk")
        # Tudo o que pode falhar antes de mexer no serviço vem primeiro:
        # arquivo, frase, cabeçalho e derivação da chave.
        arquivo = open(args.arquivo, "rb")
        frase = ler_frase_arquivo(args.frase_arquivo) if args.frase_arquivo \
            else getpass.getpass("Frase do backup: ")
        estado = abrir_backup(arquivo, frase)
        if not confirmar("Isto substitui banco, snapshots, chave e PKI deste "
                         "servidor. Continuar?", False):
            return
        r_dados, w_dados = os.pipe()
        r_sinal, w_sinal = os.pipe()

        def filho():
            os.close(w_dados)
            os.close(w_sinal)
            desempacotar_dados(r_dados, r_sinal, dados)
        executar(["systemctl", "stop", UNIDADE], verificar=False)
        try:
            pid = processo_servico(filho)
            os.close(r_dados)
            os.close(r_sinal)
            autenticado, divisor = False, None
            try:
                with arquivo, os.fdopen(w_dados, "wb") as pipe:
                    divisor = Divisor(pipe)
                    decifrar_fluxo(arquivo, divisor, estado)
                autenticado = divisor.tamanho is not None and \
                    len(divisor.raiz) == divisor.tamanho
            except (BrokenPipeError, SystemExit, ValueError):
                pass
            finally:
                with os.fdopen(w_sinal, "wb") as sinal:
                    try:
                        sinal.write(b"OK" if autenticado else b"NO")
                    except BrokenPipeError:
                        pass
                codigo = esperar(pid)
            if codigo == 2:
                erro("a troca dos dados falhou no meio: o servidor está "
                     "inconsistente. Restaure de novo ou use outro backup.")
            if not autenticado or codigo != 0:
                erro("restauração cancelada; os dados atuais foram mantidos")
            itens = {}
            with tarfile.open(fileobj=io.BytesIO(bytes(divisor.raiz))) as t:
                for m in t.getmembers():
                    if m.isfile() and nome_seguro_backup(m.name):
                        itens[m.name] = t.extractfile(m).read()
            if "chave-mestra" not in itens:
                erro("backup sem a chave-mestra; os dados foram restaurados, "
                     "mas a chave atual foi mantida")
            gravar_chave(cofre_mod._decodificar_chave(itens["chave-mestra"]),
                         inst["modo_chave"])
            pki = {n[len("etc/pki/"):]: v for n, v in itens.items()
                   if n.startswith("etc/pki/") and "/" not in n[len("etc/pki/"):]}
            if pki:
                shutil.rmtree(PKI, ignore_errors=True)
                os.makedirs(PKI, mode=0o700)
                for n, v in pki.items():
                    _gravar(os.path.join(PKI, n), v,
                            0o400 if n.endswith(".key") else 0o644)
        finally:
            executar(["systemctl", "start", UNIDADE], verificar=False)
        ok("backup restaurado. Se o nome do servidor mudou, rode "
           "'netsnapctl certificado' e 'netsnapctl web configurar'.")


# ---------------------------------------------------------------------------
# Status, auditoria e inicialização
# ---------------------------------------------------------------------------
def cmd_status(args):
    exigir_root()
    inst = ler_instalacao()
    r = subprocess.run(["systemctl", "is-active", UNIDADE], capture_output=True)
    print(f"Serviço: {r.stdout.decode().strip() or 'desconhecido'}")
    print(f"Endereço: https://{inst['nomes'][0]}"
          + ("" if inst["porta_https"] == 443 else f":{inst['porta_https']}"))
    print(f"Servidor web: {inst['web']}   Redes permitidas: "
          f"{', '.join(inst['redes']) or 'qualquer origem'}")
    print("Chave-mestra: " + ("selada pelo systemd-creds" if os.path.exists(
        CHAVE_CRED) else "arquivo root 0400" if os.path.exists(CHAVE_ARQ)
        else "AUSENTE"))
    print()
    mostrar_certificado(inst)
    print()
    pid = os.fork()
    if pid == 0:
        try:
            banco = abrir_banco()
            n = lambda t: banco.um(f"SELECT COUNT(*) AS n FROM {t}")["n"]  # noqa
            print(f"Usuários: {n('usuarios')}  Credenciais: {n('credenciais')}  "
                  f"Agendamentos: {n('agendamentos')}  Execuções: "
                  f"{n('execucoes')}  Pacotes: {n('analises')}")
            for a in banco.listar_agendamentos():
                print(f"  - {a['nome']}: próxima {a['proxima'] or '—'}, "
                      f"última {a['ultima'] or '—'} ({a['ultimo_estado'] or '—'})")
            sys.stdout.flush()
            os._exit(0)
        except SystemExit as e:
            os._exit(e.code if isinstance(e.code, int) else 1)
        except Exception as e:
            print(f"[!] banco: {e}")
            sys.stdout.flush()
            os._exit(1)
    os.waitpid(pid, 0)
    uso = shutil.disk_usage(inst["dados"])
    print(f"Disco em {inst['dados']}: {uso.free // 2**30} GiB livres de "
          f"{uso.total // 2**30} GiB")


def cmd_auditoria(args):
    exigir_root()
    banco = abrir_banco()
    integra, primeiro = banco.verificar_auditoria()
    if integra:
        ok("trilha de auditoria íntegra")
    else:
        erro("trilha alterada" + (f" a partir do registro {primeiro}"
                                  if primeiro else " (registros finais removidos)"))


def cmd_inicializar(args):
    exigir_root()
    banco = abrir_banco()
    ok(f"banco pronto (impressão da chave {banco.cofre.impressao()})")


def menu():
    exigir_root()
    opcoes = [("status", "Situação do servidor"),
              ("usuarios", "Usuários"),
              ("certificado", "Certificado HTTPS"),
              ("chave", "Cópia de segurança da chave-mestra"),
              ("backup", "Backup cifrado"),
              ("auditoria", "Verificar a trilha de auditoria"),
              ("sair", "Sair")]
    while True:
        print()
        op = escolher("netsnapctl — o que fazer?", opcoes, 1)
        ns = argparse.Namespace(acao=None, nome=None, papel=None, inicial=False,
                                arquivo=None, forcar=False, email=None,
                                cert=None, chave=None, cadeia=None,
                                se_necessario=False, frase_arquivo=None)
        pid = os.fork()
        if pid == 0:
            # Cada ação num processo próprio: as de banco deixam de ser root.
            try:
                if op == "status":
                    cmd_status(ns)
                elif op == "usuarios":
                    ns.acao = escolher("Usuários:", [
                        ("listar", "Listar"), ("criar", "Criar"),
                        ("senha", "Gerar senha provisória"),
                        ("totp", "Refazer verificação em 2 etapas"),
                        ("desbloquear", "Desbloquear"),
                        ("desativar", "Desativar"), ("ativar", "Reativar"),
                        ("remover", "Remover")], 1)
                    cmd_usuario(ns)
                elif op == "certificado":
                    cmd_certificado(ns)
                elif op == "chave":
                    ns.acao = "exportar"
                    cmd_chave(ns)
                elif op == "backup":
                    ns.acao = "criar"
                    cmd_backup(ns)
                elif op == "auditoria":
                    cmd_auditoria(ns)
                sys.stdout.flush()
                os._exit(0)
            except SystemExit as e:
                sys.stdout.flush()
                os._exit(e.code if isinstance(e.code, int) else 1)
            except KeyboardInterrupt:
                os._exit(130)
        if op == "sair":
            os.waitpid(pid, 0)
            return
        os.waitpid(pid, 0)


CAMINHO_SEGURO = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def main():
    # Roda como root: não herdar PATH de quem chamou (sudo -E, cron, etc.).
    os.environ["PATH"] = CAMINHO_SEGURO
    if len(sys.argv) == 1:
        try:
            menu()
        except KeyboardInterrupt:
            print()
        return
    ap = argparse.ArgumentParser(prog="netsnapctl",
                                 description="Administração do servidor netsnap")
    sub = ap.add_subparsers(dest="comando", required=True)
    sub.add_parser("status").set_defaults(f=cmd_status)
    sub.add_parser("inicializar").set_defaults(f=cmd_inicializar)
    p = sub.add_parser("usuario")
    p.add_argument("acao", choices=["criar", "listar", "senha", "totp",
                                    "desbloquear", "ativar", "desativar",
                                    "remover"])
    p.add_argument("nome", nargs="?")
    p.add_argument("--papel", choices=["admin", "tecnico", "leitura"])
    p.add_argument("--inicial", action="store_true",
                   help="administrador inicial: senha definitiva e TOTP agora")
    p.add_argument("--se-necessario", action="store_true",
                   help="com --inicial: só cria se ainda não houver administrador")
    p.set_defaults(f=cmd_usuario)
    p = sub.add_parser("chave")
    p.add_argument("acao", choices=["exportar", "importar", "criar"])
    p.add_argument("arquivo", nargs="?")
    p.set_defaults(f=cmd_chave)
    p = sub.add_parser("certificado")
    p.add_argument("acao", nargs="?", choices=["ca-interna", "letsencrypt",
                                               "importar", "renovar",
                                               "mostrar"])
    p.add_argument("--forcar", action="store_true",
                   help="recria a CA interna")
    p.add_argument("--email")
    p.add_argument("--cert")
    p.add_argument("--chave")
    p.add_argument("--cadeia")
    p.add_argument("--se-necessario", action="store_true",
                   help="renova só se faltarem 30 dias ou menos")
    p.set_defaults(f=cmd_certificado)
    p = sub.add_parser("web")
    p.add_argument("acao", choices=["configurar"])
    p.set_defaults(f=cmd_web)
    p = sub.add_parser("systemd")
    p.add_argument("acao", choices=["instalar"])
    p.set_defaults(f=cmd_systemd)
    p = sub.add_parser("backup")
    p.add_argument("acao", choices=["criar", "restaurar"])
    p.add_argument("arquivo", nargs="?")
    p.add_argument("--frase-arquivo",
                   help="lê a frase deste arquivo (root, 600), para o cron")
    p.set_defaults(f=cmd_backup)
    p = sub.add_parser("auditoria")
    p.add_argument("acao", choices=["verificar"])
    p.set_defaults(f=cmd_auditoria)
    args = ap.parse_args()
    try:
        args.f(args)
    except (cofre_mod.ErroCofre, OSError) as e:
        erro(str(e))
    except KeyboardInterrupt:
        print()
        raise SystemExit(130)
    except Exception as e:
        import netsnap_banco as banco_mod
        if isinstance(e, banco_mod.ErroBanco):
            erro(str(e))
        raise


if __name__ == "__main__":
    main()
