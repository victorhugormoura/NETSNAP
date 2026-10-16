#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap_cofre — criptografia do servidor netsnap

Tudo que é segredo no servidor passa por aqui:

  - Chave-mestra de 256 bits, que nunca fica em claro no disco do serviço. O
    systemd a entrega ao processo (LoadCredentialEncrypted, selada pelo TPM2
    quando existe, ou LoadCredential com arquivo legível só pelo root) em um
    diretório em memória visível apenas para o serviço.
  - Subchaves independentes por finalidade, derivadas da mestra com HKDF-SHA256:
    uma chave vazada para uma finalidade não abre as outras.
  - AES-256-GCM com nonce aleatório e contexto autenticado (AAD): um valor
    cifrado copiado para outro registro não decifra.
  - Hash de senha com scrypt (N=2^17, r=8, p=1, parâmetros mínimos da OWASP),
    e o próprio hash ainda é cifrado: o banco sozinho não permite ataque de
    dicionário offline.
  - TOTP (RFC 6238) com proteção contra reuso do mesmo código e códigos de
    recuperação de uso único.
  - Cópia de segurança da chave-mestra protegida por frase (scrypt + AES-GCM),
    para recuperar o cofre se o servidor for perdido.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NOME_CREDENCIAL = "netsnap-chave"
TAMANHO_CHAVE = 32
PREFIXO_CIFRA = "v1:"


class ErroCofre(Exception):
    pass


# ---------------------------------------------------------------------------
# Chave-mestra
# ---------------------------------------------------------------------------
def _decodificar_chave(bruto):
    """Aceita a chave em base64 (formato gravado pelo instalador) ou crua."""
    texto = bruto.strip()
    if len(bruto) == TAMANHO_CHAVE and len(texto) != 44:
        return bytes(bruto)
    try:
        chave = base64.b64decode(texto, validate=True)
    except (ValueError, TypeError):
        raise ErroCofre("chave-mestra em formato inválido")
    if len(chave) != TAMANHO_CHAVE:
        raise ErroCofre("chave-mestra com tamanho inválido")
    return chave


def carregar_chave_mestra(arquivo=None):
    """Lê a chave-mestra.

    Ordem: credencial entregue pelo systemd ($CREDENTIALS_DIRECTORY) e, só se
    não houver, o arquivo indicado (uso pelo netsnapctl como root e testes).
    O arquivo precisa ser legível apenas pelo dono."""
    pasta = os.environ.get("CREDENTIALS_DIRECTORY")
    if pasta:
        caminho = os.path.join(pasta, NOME_CREDENCIAL)
        if os.path.isfile(caminho):
            with open(caminho, "rb") as f:
                return _decodificar_chave(f.read())
    if not arquivo:
        raise ErroCofre(
            "chave-mestra não encontrada: o serviço deve ser iniciado pelo "
            "systemd (LoadCredential) ou com o arquivo de chave configurado")
    st = os.stat(arquivo)
    if os.name == "posix" and st.st_mode & 0o077:
        raise ErroCofre(f"{arquivo} está acessível a outros usuários "
                        f"(permissão {oct(st.st_mode & 0o777)}); use chmod 400")
    with open(arquivo, "rb") as f:
        return _decodificar_chave(f.read())


def nova_chave_mestra():
    return secrets.token_bytes(TAMANHO_CHAVE)


def chave_para_texto(chave):
    return base64.b64encode(chave).decode("ascii")


# ---------------------------------------------------------------------------
# Cofre: subchaves, cifra e HMAC
# ---------------------------------------------------------------------------
class Cofre:
    FINALIDADES = ("cifra", "sessao", "auditoria", "recuperacao", "impressao")

    def __init__(self, chave_mestra):
        if not isinstance(chave_mestra, (bytes, bytearray)) or \
                len(chave_mestra) != TAMANHO_CHAVE:
            raise ErroCofre("chave-mestra inválida")
        self._sub = {f: HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                             info=b"netsnap/" + f.encode()).derive(
                                 bytes(chave_mestra))
                     for f in self.FINALIDADES}
        self._aead = AESGCM(self._sub["cifra"])

    def impressao(self):
        """Identificador público da chave (não revela nada sobre ela).

        Gravado no banco na criação: se o serviço subir com outra chave (banco
        restaurado em outra máquina sem importar a chave), o erro é claro em
        vez de cada senha falhar ao decifrar."""
        return hmac.new(self._sub["impressao"], b"netsnap",
                        hashlib.sha256).hexdigest()[:16]

    def cifrar(self, dados, contexto):
        if isinstance(dados, str):
            dados = dados.encode("utf-8")
        nonce = secrets.token_bytes(12)
        cifra = self._aead.encrypt(nonce, dados, contexto.encode("utf-8"))
        return PREFIXO_CIFRA + base64.b64encode(nonce + cifra).decode("ascii")

    def decifrar(self, blob, contexto):
        if not isinstance(blob, str) or not blob.startswith(PREFIXO_CIFRA):
            raise ErroCofre("valor cifrado em formato desconhecido")
        try:
            bruto = base64.b64decode(blob[len(PREFIXO_CIFRA):], validate=True)
            return self._aead.decrypt(bruto[:12], bruto[12:],
                                      contexto.encode("utf-8"))
        except (InvalidTag, ValueError):
            raise ErroCofre("valor cifrado adulterado ou chave diferente")

    def cifrar_json(self, obj, contexto):
        return self.cifrar(json.dumps(obj, ensure_ascii=False), contexto)

    def decifrar_json(self, blob, contexto):
        return json.loads(self.decifrar(blob, contexto).decode("utf-8"))

    def hmac(self, finalidade, dados):
        if isinstance(dados, str):
            dados = dados.encode("utf-8")
        return hmac.new(self._sub[finalidade], dados, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Senhas dos usuários do painel
# ---------------------------------------------------------------------------
SCRYPT_N_LOG2, SCRYPT_R, SCRYPT_P = 17, 8, 1
# 128 MiB por cálculo: limita quantos rodam ao mesmo tempo para que uma
# rajada de tentativas de login não esgote a memória do servidor.
_SEMAFORO_SCRYPT = threading.BoundedSemaphore(2)


class Ocupado(ErroCofre):
    """Muitos cálculos de senha ao mesmo tempo: tente de novo em instantes."""


def _scrypt(senha, sal, n_log2=SCRYPT_N_LOG2, r=SCRYPT_R, p=SCRYPT_P,
            espera=10):
    # Parâmetros vindos de arquivo (cópia da chave, backup) são limitados
    # antes do cálculo: um arquivo forjado não esgota a memória.
    if not (14 <= n_log2 <= 20 and 1 <= r <= 16 and 1 <= p <= 4):
        raise ErroCofre("parâmetros de derivação fora do permitido")
    if not _SEMAFORO_SCRYPT.acquire(timeout=espera):
        raise Ocupado("servidor ocupado verificando senhas; tente em instantes")
    try:
        return hashlib.scrypt(senha.encode("utf-8"), salt=sal, n=2 ** n_log2,
                              r=r, p=p, maxmem=2 ** (n_log2 + 9) * r,
                              dklen=32)
    finally:
        _SEMAFORO_SCRYPT.release()


def hash_senha(senha):
    sal = secrets.token_bytes(16)
    dk = _scrypt(senha, sal)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N_LOG2, SCRYPT_R, SCRYPT_P,
        base64.b64encode(sal).decode(), base64.b64encode(dk).decode())


def conferir_senha(senha, armazenado):
    """True/False; Ocupado se o servidor estiver saturado de logins."""
    try:
        alg, n_log2, r, p, sal, dk = armazenado.split("$")
        if alg != "scrypt":
            return False
        calculado = _scrypt(senha, base64.b64decode(sal), int(n_log2), int(r),
                            int(p))
        return hmac.compare_digest(calculado, base64.b64decode(dk))
    except Ocupado:
        raise
    except (ValueError, TypeError, ErroCofre):
        return False


# Hash fixo para usuário inexistente: o login gasta o mesmo tempo com ou sem
# usuário, e o tempo de resposta não revela quais nomes existem.
_HASH_FICTICIO = None


def gastar_tempo_como_login(senha):
    global _HASH_FICTICIO
    if _HASH_FICTICIO is None:
        _HASH_FICTICIO = hash_senha(secrets.token_urlsafe(16))
    conferir_senha(senha, _HASH_FICTICIO)


def problema_na_senha(senha, usuario=""):
    """Política: 12+ caracteres com 3 tipos, ou frase de 16+. None se ok."""
    if not isinstance(senha, str):
        return "senha inválida"
    if len(senha) > 256:
        return "a senha pode ter no máximo 256 caracteres"
    if usuario and senha.lower() == usuario.lower():
        return "a senha não pode ser igual ao nome de usuário"
    tipos = sum([any(c.islower() for c in senha),
                 any(c.isupper() for c in senha),
                 any(c.isdigit() for c in senha),
                 any(not c.isalnum() for c in senha)])
    if len(senha) >= 16 and len(set(senha)) >= 6:
        return None
    if len(senha) >= 12 and tipos >= 3:
        return None
    return ("use pelo menos 12 caracteres misturando três tipos (minúsculas, "
            "maiúsculas, números, símbolos) ou uma frase com 16 ou mais")


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) e códigos de recuperação
# ---------------------------------------------------------------------------
PASSO_TOTP = 30
DIGITOS_TOTP = 6


def novo_segredo_totp():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _hotp(segredo, contador):
    chave = base64.b32decode(segredo.upper() + "=" * (-len(segredo) % 8))
    mac = hmac.new(chave, struct.pack(">Q", contador), hashlib.sha1).digest()
    pos = mac[-1] & 0x0F
    valor = struct.unpack(">I", mac[pos:pos + 4])[0] & 0x7FFFFFFF
    return str(valor % 10 ** DIGITOS_TOTP).zfill(DIGITOS_TOTP)


def codigo_totp(segredo, instante=None):
    return _hotp(segredo, int((instante or time.time()) // PASSO_TOTP))


def conferir_totp(segredo, codigo, ultimo_contador=0, instante=None):
    """Confere o código aceitando um passo de diferença de relógio.

    Devolve o contador aceito (para gravar) ou None. Um contador igual ou
    anterior ao último aceito é recusado: o mesmo código não vale duas
    vezes, nem se for capturado na tela ou na rede."""
    codigo = "".join(ch for ch in str(codigo) if ch.isdigit())
    if len(codigo) != DIGITOS_TOTP:
        return None
    atual = int((instante or time.time()) // PASSO_TOTP)
    for contador in (atual - 1, atual, atual + 1):
        if contador <= (ultimo_contador or 0):
            continue
        if hmac.compare_digest(_hotp(segredo, contador), codigo):
            return contador
    return None


def uri_totp(segredo, usuario, emissor="netsnap"):
    rotulo = quote(f"{emissor}:{usuario}", safe="")
    return (f"otpauth://totp/{rotulo}?secret={segredo}&issuer="
            f"{quote(emissor, safe='')}&algorithm=SHA1&digits="
            f"{DIGITOS_TOTP}&period={PASSO_TOTP}")


_ALFABETO_RECUPERACAO = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def novos_codigos_recuperacao(quantidade=10):
    """Códigos de 12 caracteres (60 bits), mostrados uma única vez."""
    codigos = []
    for _ in range(quantidade):
        s = "".join(secrets.choice(_ALFABETO_RECUPERACAO) for _ in range(12))
        codigos.append(f"{s[:4]}-{s[4:8]}-{s[8:]}")
    return codigos


def normalizar_codigo_recuperacao(codigo):
    return "".join(ch for ch in str(codigo).upper()
                   if ch in _ALFABETO_RECUPERACAO)


# ---------------------------------------------------------------------------
# Cópia de segurança da chave-mestra
# ---------------------------------------------------------------------------
FORMATO_COPIA = "netsnap-chave-mestra/1"


def exportar_chave(chave_mestra, frase):
    """Embala a chave-mestra com uma frase. Sem a frase o arquivo é inútil."""
    sal = secrets.token_bytes(16)
    derivada = _scrypt(frase, sal, espera=120)
    nonce = secrets.token_bytes(12)
    cifra = AESGCM(derivada).encrypt(nonce, bytes(chave_mestra),
                                     FORMATO_COPIA.encode())
    return json.dumps({
        "formato": FORMATO_COPIA,
        "kdf": {"alg": "scrypt", "n_log2": SCRYPT_N_LOG2, "r": SCRYPT_R,
                "p": SCRYPT_P, "sal": base64.b64encode(sal).decode()},
        "nonce": base64.b64encode(nonce).decode(),
        "cifra": base64.b64encode(cifra).decode(),
        "impressao": Cofre(chave_mestra).impressao(),
        "criado": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, indent=2)


def importar_chave(texto, frase):
    try:
        d = json.loads(texto)
        if d.get("formato") != FORMATO_COPIA:
            raise ErroCofre("arquivo não é uma cópia da chave do netsnap")
        k = d["kdf"]
        derivada = _scrypt(frase, base64.b64decode(k["sal"]), int(k["n_log2"]),
                           int(k["r"]), int(k["p"]), espera=120)
        chave = AESGCM(derivada).decrypt(base64.b64decode(d["nonce"]),
                                         base64.b64decode(d["cifra"]),
                                         FORMATO_COPIA.encode())
    except InvalidTag:
        raise ErroCofre("frase incorreta ou arquivo adulterado")
    except (ValueError, KeyError, TypeError):
        raise ErroCofre("arquivo de cópia da chave inválido")
    if Cofre(chave).impressao() != d.get("impressao"):
        raise ErroCofre("impressão da chave não confere")
    return chave
