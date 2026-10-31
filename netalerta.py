#!/usr/bin/env python3
"""netalerta — avisa sobre mudança de configuração e falha grave nova.

Compara coletas do netsnap e triagens do netcve entre dois instantes e
levanta alertas:
  - configuração mudou entre a coleta anterior e a atual de um equipamento;
  - CVE com exploração confirmada (CISA KEV) nova em relação à triagem anterior;
  - falha grave do catálogo (netcve) nova ou agravada.

Entrega os alertas no terminal e num arquivo, e, quando configurado, por
Telegram, webhook (JSON) ou e-mail. Só biblioteca padrão. Os destinos vêm de
variáveis de ambiente, nunca da linha de comando (não ficam no histórico nem
no 'ps'):
  NETALERTA_TELEGRAM_TOKEN, NETALERTA_TELEGRAM_CHAT
  NETALERTA_WEBHOOK            (URL https que recebe POST JSON; http só
                                para loopback)
  NETALERTA_SMTP   = host:porta  (porta 465: TLS implícito; outras: STARTTLS)
  NETALERTA_SMTP_DE, NETALERTA_SMTP_PARA   (remetente e destinatários)
  NETALERTA_SMTP_USUARIO, NETALERTA_SMTP_SENHA   (opcional; sem TLS o login
                                                  é recusado)

Uso:
  python3 netalerta.py snapshots/                 compara as duas coletas mais recentes
  python3 netalerta.py snapshots/ --estado estado.json   guarda o visto e só avisa o novo
  python3 netalerta.py snapshots/ --simular       mostra os alertas, não envia nada

Nada aqui conecta a equipamento. Lê os arquivos que o netsnap e o netcve já
geraram.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import argparse
import difflib
import ipaddress
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import urlsplit

import netsnap_md as md

# Segunda passada do sanitizador nas linhas de diferença antes do envio. O
# netsnap traz o Netmiko junto; numa estação só de análise, sem ele, vale
# apenas a exigência de "sensitive_data: redacted" dos dois snapshots.
try:
    from netsnap import sanitizar as _sanitizar
except Exception:
    _sanitizar = None

__version__ = "0.1.1"
FORMATO = "netalerta/1"
GRAVIDADE = {"critica": 3, "alta": 2, "media": 1, "info": 0}
TIMEOUT = 15


class ErroAlerta(Exception):
    pass


# ---------------------------------------------------------------------------
# Comparação de configuração entre as duas coletas de cada equipamento
# ---------------------------------------------------------------------------
# Linhas que o próprio equipamento reescreve a cada exportação (data, hora,
# relógio do NTP). Sem este filtro toda coleta acusaria "configuração mudou".
LINHAS_VOLATEIS = [re.compile(p, re.IGNORECASE) for p in (
    r"^#\s.*\bby RouterOS\b",                       # MikroTik /export
    r"^!\s*Time:",                                   # NX-OS
    r"^!\s*Running configuration last done at\b",   # NX-OS
    r"^\s*ntp clock-period\b",                       # Cisco IOS
    r"^!\s*NVRAM config last updated\b",            # Cisco IOS
    r"^!\s*Last configuration change\b",            # Cisco IOS
    r"^Current configuration\s*:",                   # Cisco IOS (bytes)
    r"^!\s*Last configuration was (updated|saved)\b",  # Huawei VRP
    r"^\s*## Last (commit|changed)\b",               # Junos
)]


def _config(snap):
    return "\n".join(c["saida"] or "" for s in snap["secoes"]
                     if s["chave"] == "config" for c in s["comandos"])


def _linhas_estaveis(texto):
    return [l for l in texto.splitlines()
            if not any(p.search(l) for p in LINHAS_VOLATEIS)]


def _diferenca(a, b):
    return [l for l in difflib.unified_diff(a, b, "anterior", "atual",
                                            lineterm="", n=0)
            if l[:1] in "+-" and not l.startswith(("+++", "---"))]


def _id_config(host, ip, coletado_em):
    # hash() do Python muda a cada processo (PYTHONHASHSEED) e o --estado
    # nunca reconheceria o alerta já dado. O instante da coleta mais recente
    # identifica a mudança: a mesma diferença numa coleta posterior (alguém
    # desfez e refez) é um evento novo e deve avisar de novo.
    return f"config|{host}|{ip}|{coletado_em}"


def duas_mais_recentes(caminhos):
    """Por (host, ip): (mais recente, anterior) quando há pelo menos duas."""
    grupos = {}
    for caminho in caminhos:
        meta = md.ler_metadados(caminho)
        chave = (meta.get("host"), meta.get("ip"))
        grupos.setdefault(chave, []).append((meta.get("collected_at") or "", caminho))
    saida = {}
    for chave, lista in grupos.items():
        lista.sort()
        saida[chave] = (lista[-1][1], lista[-2][1] if len(lista) > 1 else None)
    return saida


def alertas_de_config(pasta):
    caminhos = md.listar_snapshots(pasta)
    alertas = []
    for (host, ip), (atual, anterior) in duas_mais_recentes(caminhos).items():
        if not anterior:
            continue
        sa, sb = md.ler_snapshot(anterior), md.ler_snapshot(atual)
        # Sessão perdida no meio da coleta deixa a configuração truncada: a
        # comparação viraria centenas de linhas "-" que não são mudança.
        if any(s["meta"].get("session_lost") is True for s in (sa, sb)):
            continue
        a, b = _linhas_estaveis(_config(sa)), _linhas_estaveis(_config(sb))
        if not a or not b:
            continue
        diff = _diferenca(a, b)
        if not diff:
            continue
        mais = sum(1 for l in diff if l[0] == "+")
        menos = sum(1 for l in diff if l[0] == "-")
        coletado_em = sb["meta"].get("collected_at") or os.path.basename(atual)
        # O detalhe sai da máquina (Telegram, webhook, e-mail). Snapshot
        # coletado com dados sensíveis traria senha e comunidade SNMP no
        # texto: nesse caso vai só a contagem de linhas.
        if any(s["meta"].get("sensitive_data") != "redacted" for s in (sa, sb)):
            detalhe = ("Diferença omitida: um dos snapshots não está com "
                       "sensitive_data: redacted. Compare os arquivos localmente.")
        else:
            if _sanitizar is not None:
                diff = _diferenca(_sanitizar("\n".join(a)).splitlines(),
                                  _sanitizar("\n".join(b)).splitlines())
            detalhe = ("\n".join(diff[:40])
                       + ("\n[... diferença cortada]" if len(diff) > 40 else "")
                       if diff else
                       "Diferença apenas em trechos mascarados pelo sanitizador.")
        alertas.append({
            "tipo": "config-mudou", "severidade": "alta",
            "host": host, "ip": ip,
            "titulo": f"configuração mudou (+{mais}/-{menos} linhas)",
            "detalhe": detalhe,
            "coletado_em": coletado_em,
            "id": _id_config(host, ip, coletado_em),
        })
    return alertas


# ---------------------------------------------------------------------------
# Triagem: KEV e falha grave novas em relação à triagem anterior
# ---------------------------------------------------------------------------
def _triagens(pasta):
    nomes = sorted(n for n in os.listdir(pasta)
                   if n.startswith("_cve_triagem_") and n.endswith(".json"))
    return [os.path.join(pasta, n) for n in nomes]


def _kev_do_host(h):
    kev = set()
    for v in h.get("versoes") or []:
        for c in v.get("cves") or []:
            if c.get("kev"):
                kev.add(c["id"])
    for p in (h.get("pacotes") or {}).get("resultado") or []:
        for v in p.get("vulns") or []:
            kev.update(v.get("kev") or [])
    return kev


def _catalogo_do_host(h):
    return {a["id"]: a.get("situacao") for a in h.get("catalogo") or []}


def _por_host(triagem):
    return {(h.get("host"), h.get("ip")): h for h in triagem.get("hosts") or []}


def _triagens_validas(pasta, registrar=print, quantas=2):
    """As 'quantas' triagens legíveis mais recentes, da mais nova para a mais
    antiga. Arquivo corrompido (gravação interrompida, edição manual) é
    pulado com aviso: derrubar a execução calaria também os alertas de
    configuração."""
    validas = []
    for caminho in reversed(_triagens(pasta)):
        try:
            with open(caminho, encoding="utf-8") as f:
                dados = json.load(f)
        except (ValueError, OSError) as e:
            registrar(f"[!] Triagem ilegível ignorada: {caminho}: {e}")
            continue
        if not isinstance(dados, dict):
            registrar(f"[!] Triagem fora do formato ignorada: {caminho}")
            continue
        validas.append(dados)
        if len(validas) == quantas:
            break
    return validas


def alertas_de_triagem(pasta, registrar=print):
    validas = _triagens_validas(pasta, registrar)
    if not validas:
        return []
    atual = validas[0]
    anterior = _por_host(validas[1]) if len(validas) > 1 else {}
    alertas = []
    for (host, ip), h in _por_host(atual).items():
        antes = anterior.get((host, ip), {})
        novas_kev = _kev_do_host(h) - _kev_do_host(antes)
        for cve in sorted(novas_kev):
            alertas.append({
                "tipo": "kev-nova", "severidade": "critica", "host": host, "ip": ip,
                "titulo": f"CVE com exploração confirmada (KEV): {cve}",
                "detalhe": "Apareceu no CISA KEV para este equipamento desde a "
                           "triagem anterior.",
                "id": f"kev|{host}|{ip}|{cve}"})
        cat_antes = _catalogo_do_host(antes)
        for a in h.get("catalogo") or []:
            if a["id"] in cat_antes and cat_antes[a["id"]] == a.get("situacao"):
                continue
            estado = "nova" if a["id"] not in cat_antes else f"mudou para {a.get('situacao')}"
            alertas.append({
                "tipo": "catalogo", "severidade": "critica", "host": host, "ip": ip,
                "titulo": f"falha grave {estado}: {a.get('titulo')}",
                "detalhe": a.get("base", "") + (
                    ("\nExposição: " + "; ".join(a["exposicao"])) if a.get("exposicao") else ""),
                "id": f"catalogo|{host}|{ip}|{a['id']}|{a.get('situacao')}"})
    return alertas


# ---------------------------------------------------------------------------
# Envio
# ---------------------------------------------------------------------------
def _texto(alertas):
    linhas = [f"netalerta — {len(alertas)} alerta(s) em "
              f"{datetime.now():%Y-%m-%d %H:%M}"]
    for a in sorted(alertas, key=lambda a: -GRAVIDADE.get(a["severidade"], 0)):
        linhas.append(f"\n[{a['severidade'].upper()}] {a['host']} ({a['ip']}) — "
                      f"{a['titulo']}")
        if a.get("detalhe"):
            linhas.append("    " + a["detalhe"].replace("\n", "\n    "))
    return "\n".join(linhas)


def _post_json(url, dados):
    corpo = json.dumps(dados).encode("utf-8")
    req = urllib.request.Request(url, data=corpo, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": f"netalerta/{__version__}"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        return r.status


def enviar_telegram(texto, token, chat):
    # O token vem do ambiente e não é registrado.
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for pedaco in [texto[i:i + 3500] for i in range(0, len(texto), 3500)] or [texto]:
        _post_json(url, {"chat_id": chat, "text": pedaco,
                         "disable_web_page_preview": True})


def _url_segura(url):
    """https sempre; http só para loopback (coletor local, testes). Os
    alertas levam IP, versão e trecho de configuração da rede."""
    partes = urlsplit(url)
    if partes.scheme == "https":
        return
    if partes.scheme == "http":
        host = partes.hostname or ""
        if host == "localhost":
            return
        try:
            if ipaddress.ip_address(host).is_loopback:
                return
        except ValueError:
            pass
    raise ValueError("webhook precisa ser https (http só para loopback)")


def enviar_webhook(url, alertas):
    _url_segura(url)
    _post_json(url, {"formato": FORMATO, "gerado_em": datetime.now().isoformat(),
                     "alertas": alertas})


def enviar_email(texto, cfg):
    msg = EmailMessage()
    msg["Subject"] = "netalerta — alertas da rede"
    msg["From"] = cfg["de"]
    msg["To"] = ", ".join(cfg["para"])
    msg.set_content(texto)
    host, _, porta = cfg["servidor"].partition(":")
    porta = int(porta or 25)
    ctx = ssl.create_default_context()
    if porta == 465:
        # Porta de submissão com TLS implícito: a sessão já nasce cifrada.
        conexao = smtplib.SMTP_SSL(host, porta, timeout=TIMEOUT, context=ctx)
    else:
        conexao = smtplib.SMTP(host, porta, timeout=TIMEOUT)
    with conexao as s:
        if porta != 465:
            try:
                s.starttls(context=ctx)
            except smtplib.SMTPNotSupportedError:
                # Quem está no meio pode apagar o STARTTLS do EHLO. Sem TLS
                # a senha iria às claras: com usuário configurado, recusa.
                # Sem usuário (relay interno) segue como antes.
                if cfg.get("usuario"):
                    raise smtplib.SMTPException(
                        "servidor não ofereceu STARTTLS; login recusado "
                        "para não enviar a senha sem TLS")
        if cfg.get("usuario"):
            s.login(cfg["usuario"], cfg["senha"])
        s.send_message(msg)


def destinos_do_ambiente(env):
    destinos = {}
    if env.get("NETALERTA_TELEGRAM_TOKEN") and env.get("NETALERTA_TELEGRAM_CHAT"):
        destinos["telegram"] = {"token": env["NETALERTA_TELEGRAM_TOKEN"],
                                "chat": env["NETALERTA_TELEGRAM_CHAT"]}
    if env.get("NETALERTA_WEBHOOK"):
        destinos["webhook"] = env["NETALERTA_WEBHOOK"]
    if env.get("NETALERTA_SMTP") and env.get("NETALERTA_SMTP_DE") and \
            env.get("NETALERTA_SMTP_PARA"):
        destinos["email"] = {"servidor": env["NETALERTA_SMTP"],
                             "de": env["NETALERTA_SMTP_DE"],
                             "para": [p.strip() for p in env["NETALERTA_SMTP_PARA"].split(",")
                                      if p.strip()],
                             "usuario": env.get("NETALERTA_SMTP_USUARIO"),
                             "senha": env.get("NETALERTA_SMTP_SENHA")}
    return destinos


def enviar(alertas, destinos, registrar=print):
    texto = _texto(alertas)
    resultado = {}
    if "telegram" in destinos:
        try:
            enviar_telegram(texto, **destinos["telegram"])
            resultado["telegram"] = "ok"
        except (urllib.error.URLError, OSError, ValueError) as e:
            resultado["telegram"] = f"falha: {e}"
            registrar(f"[!] Telegram: {e}")
    if "webhook" in destinos:
        try:
            enviar_webhook(destinos["webhook"], alertas)
            resultado["webhook"] = "ok"
        except (urllib.error.URLError, OSError, ValueError) as e:
            resultado["webhook"] = f"falha: {e}"
            registrar(f"[!] Webhook: {e}")
    if "email" in destinos:
        try:
            enviar_email(texto, destinos["email"])
            resultado["email"] = "ok"
        except (smtplib.SMTPException, OSError) as e:
            resultado["email"] = f"falha: {e}"
            registrar(f"[!] E-mail: {e}")
    return resultado


# ---------------------------------------------------------------------------
# Estado: lembra o que já foi avisado
# ---------------------------------------------------------------------------
def carregar_estado(caminho):
    if caminho and os.path.isfile(caminho):
        try:
            with open(caminho, encoding="utf-8") as f:
                return set(json.load(f).get("vistos") or [])
        except (ValueError, OSError):
            return set()
    return set()


def salvar_estado(caminho, vistos):
    if not caminho:
        return
    tmp = caminho + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"formato": FORMATO, "atualizado_em": datetime.now().isoformat(),
                   "vistos": sorted(vistos)}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, caminho)


def coletar(pasta, registrar=print):
    return alertas_de_config(pasta) + alertas_de_triagem(pasta, registrar)


def rodar(pasta, estado=None, simular=False, env=None, registrar=print):
    if not os.path.isdir(pasta):
        raise ErroAlerta(f"pasta não encontrada: {pasta}")
    todos = coletar(pasta, registrar)
    vistos = carregar_estado(estado)
    novos = [a for a in todos if a["id"] not in vistos]
    agora = datetime.now()
    saida = {"formato": FORMATO, "gerado_em": agora.isoformat(timespec="seconds"),
             "pasta": pasta, "total": len(todos), "novos": len(novos),
             "alertas": novos, "envio": {}}
    base = os.path.join(pasta, f"_netalerta_{agora:%Y%m%d_%H%M%S}")
    entregue = True
    if novos:
        with open(base + ".txt", "w", encoding="utf-8") as f:
            f.write(_texto(novos))
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(saida, f, ensure_ascii=False, indent=1)
        destinos = destinos_do_ambiente(env if env is not None else os.environ)
        if simular:
            saida["envio"] = {d: "simulado" for d in destinos}
        elif destinos:
            saida["envio"] = enviar(novos, destinos, registrar)
            entregue = any(r == "ok" for r in saida["envio"].values())
        else:
            saida["envio"] = {"nenhum": "sem destino configurado (só arquivo)"}
    # Só marca como visto o que chegou a alguém: sem destino configurado, o
    # arquivo e o terminal são a entrega; com destino, basta um ter aceitado
    # (os outros falharam e o aviso já saiu por um canal). Se todos falharam,
    # a próxima execução tenta de novo. Simulação não envia nada e por isso
    # não mexe no estado.
    if estado and not simular and entregue:
        salvar_estado(estado, vistos | {a["id"] for a in todos})
    return saida, base if novos else None


def main():
    if os.name == "posix":
        os.umask(0o077)
    ap = argparse.ArgumentParser(
        description="Avisa sobre mudança de configuração e falha grave nova a "
                    "partir dos snapshots e das triagens do netcve.")
    ap.add_argument("pasta", nargs="?", default="snapshots")
    ap.add_argument("--estado", help="arquivo JSON do que já foi avisado "
                                     "(só alerta o que é novo)")
    ap.add_argument("--simular", action="store_true",
                    help="não envia: mostra e grava os alertas")
    ap.add_argument("-v", "--version", action="version", version=f"netalerta {__version__}")
    args = ap.parse_args()
    print(f"netalerta v{__version__}" + (" (simulação)" if args.simular else ""))
    try:
        saida, base = rodar(args.pasta, args.estado, args.simular)
    except ErroAlerta as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    print(f"[+] {saida['total']} alerta(s), {saida['novos']} novo(s)")
    if base:
        print(_texto(saida["alertas"]))
        print(f"\n[+] Arquivo: {base}.txt e .json")
        for destino, estado in saida["envio"].items():
            print(f"[+] {destino}: {estado}")


if __name__ == "__main__":
    main()
