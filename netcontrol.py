#!/usr/bin/env python3
"""netcontrol — planos de mudança por equipamento, em modo simulação.

Lê os snapshots do netsnap, identifica a plataforma de cada equipamento e
monta, para o pedido escolhido, o plano na sintaxe daquela plataforma:
conferência prévia, comandos, verificação, reversão e a forma segura de
aplicar (commit confirmed onde existe). Também converte os achados do
netsnap_ia (comandos propostos e de reversão) para o mesmo formato,
conferindo de novo os comandos: destrutivos saem, e o que mexe no caminho
de gerência vai para revisão.

NADA É APLICADO. O netcontrol não abre sessão com equipamento: o plano é
para revisão humana. Senhas e comunidades entram como marcadores
(<SENHA>, <COMUNIDADE>) e serão preenchidas pelo cofre do servidor na etapa
de aplicação, que ainda não existe.

Pedidos:
  usuario-leitura   cria usuário só leitura
  snmp-comunidade   cria comunidade SNMP v2c só leitura, presa a uma rede
  ntp               configura servidores NTP
  desligar-telnet   desliga o serviço Telnet
  analise           plano a partir de um _ia_analise_*.json do netsnap_ia

Uso:
  python3 netcontrol.py usuario-leitura snapshots/ --usuario noc-ro --rede 10.0.0.0/24
  python3 netcontrol.py snmp-comunidade snapshots/ --rede 10.10.0.0/24
  python3 netcontrol.py ntp snapshots/ --servidor 192.0.2.1 --servidor 192.0.2.2
  python3 netcontrol.py desligar-telnet snapshots/
  python3 netcontrol.py analise snapshots/_ia_analise_20261024_100000.json
  python3 netcontrol.py                      (pergunta o pedido e os dados)

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
from datetime import datetime

import netsnap_md as md

__version__ = "0.1.1"
FORMATO = "netcontrol-plano/1"
SENHA = "<SENHA>"
COMUNIDADE = "<COMUNIDADE>"

# Situação de cada plataforma nos modelos abaixo. Nenhum modelo foi aplicado
# em equipamento real ainda: "documentação" quer dizer conferido no manual
# do fabricante, e o plano sai marcado para validar em laboratório.
PLATAFORMAS = {
    "juniper_junos": "Juniper Junos",
    "mikrotik_routeros": "MikroTik RouterOS",
    "huawei": "Huawei VRP V5",
    "huawei_ce": "Huawei VRP V8",
    "cisco_ios": "Cisco IOS/IOS-XE",
    "cisco_nxos": "Cisco NX-OS",
    "cisco_xr": "Cisco IOS-XR",
}

# Contas que o pedido de usuário só leitura não toca: o plano trocaria a
# senha e o nível de uma conta em uso (e a reversão a apagaria).
CONTAS_CONHECIDAS = ("admin", "root", "administrator")

# Plataformas cujo modelo de comunidade SNMP usa ACL só IPv4.
SNMP_SO_IPV4 = ("huawei", "huawei_ce", "cisco_ios", "cisco_nxos", "cisco_xr")

# Os achados do netsnap_ia vêm de um arquivo que pode ter sido editado ou
# gerado por outra versão: a lista de comandos destrutivos é conferida de
# novo aqui. A cópia local só vale se o netsnap_ia não puder ser importado.
try:
    from netsnap_ia import PERIGOSOS
except ImportError:
    PERIGOSOS = re.compile(
        r"(?im)\bzeroize\b|reset-configuration|reset\s+saved-configuration|"
        r"\bwrite\s+erase\b|\berase\s+(startup|nvram|flash)|"
        r"\b(request\s+system\s+)?(reboot|halt|power-off)\b|"
        r"^\s*(do\s+)?reload\b|"
        r"/system\s+(reboot|shutdown|reset)|/file\s+remove|\bformat\s+\S+:|"
        r"\brm\s+-[a-z]*r[a-z]*f|\bmkfs\b|\bdd\s+if=|\bshutdown\s+-[hr]|"
        r"^\s*delete\s+(system|interfaces|protocols|snapshot)(\s+\S+)?\s*$|"
        r"^\s*delete\s*$|^\s*clear\s+(ip\s+)?bgp\s+\*|"
        r"^\s*no\s+router\s+(bgp|ospf|isis|eigrp)\b")

# Comandos que mexem no caminho de gerência: não destroem nada, mas um erro
# derruba o acesso ao equipamento. O achado vai para revisão.
GERENCIA = [(re.compile("(?im)" + p), motivo) for p, motivo in (
    (r"^\s*no\s+ip\s+route\s+(vrf\s+\S+\s+)?0\.0\.0\.0\s+0\.0\.0\.0\b|"
     r"^\s*no\s+ipv6\s+route\s+(vrf\s+\S+\s+)?::/0\b|"
     r"^\s*undo\s+ip\s+route-static\s+(vpn-instance\s+\S+\s+)?0\.0\.0\.0\s+0(\.0\.0\.0)?\b|"
     r"^\s*no\s+(0\.0\.0\.0/0|::/0)\b|"
     r"/ip(v6)?\s+route\s+(remove|disable)\b|"
     r"^\s*delete\s+routing-options\s+(rib\s+\S+\s+)?static\b", "rotas (padrão ou remoção)"),
    (r"^\s*shutdown\s*$|^\s*set\s+interfaces\s+\S+(\s+unit\s+\d+)?\s+disable\b|"
     r"/interface\s+(\S+\s+)?disable\b|"
     r"^\s*(no|undo)\s+ip(v6)?\s+address\b|/ip(v6)?\s+address\s+(remove|disable)\b",
     "interface ou endereço"),
    (r"^\s*line\s+(vty|con)\b|\btransport\s+input\b|^\s*user-interface\b|"
     r"^\s*(no\s+|undo\s+)?(ip\s+)?ssh\b|\bstelnet\b|/ip\s+(ssh|service)\b|"
     r"\bsystem\s+services\b|^\s*(no\s+)?feature\s+(ssh|telnet)\b|"
     r"^\s*(no\s+)?(telnet|ssh)\s+(vrf\s+\S+\s+)?(ipv4|ipv6|server)\b",
     "acesso remoto (VTY/SSH)"),
    (r"^\s*(no\s+|undo\s+)?aaa\b|\b(local-user|username|tacacs|radius|tacplus)\b|"
     r"\bsystem\s+(login|authentication-order)\b|^\s*/user\b",
     "autenticação (AAA/usuários)"),
    (r"\baccess-(list|class|group)\b|^\s*(undo\s+)?acl\b|\btraffic-filter\b|"
     r"\bfirewall\b|\bfilter\s+(input|output)\b|\bcontrol-plane\b|"
     r"\bmanagement-plane\b", "filtro ou ACL"),
)]


class ErroPedido(Exception):
    pass


# ---------------------------------------------------------------------------
# Leitura do estado atual no snapshot
# ---------------------------------------------------------------------------
def texto_secao(snap, chave):
    return "\n".join(c["saida"] or "" for s in snap["secoes"] if s["chave"] == chave
                     for c in s["comandos"])


def versao_routeros(snap):
    m = re.search(r"(?m)^\s*version:\s*(\d+)\.", texto_secao(snap, "inventario")
                  + "\n" + texto_secao(snap, "basico"))
    return int(m.group(1)) if m else None


def tem_usuario(plataforma, config, basico, usuario):
    u = re.escape(usuario)
    padroes = {
        "juniper_junos": rf"(?m)^set system login user {u}(\s|$)",
        "huawei": rf"(?m)^\s*local-user {u}\s",
        "huawei_ce": rf"(?m)^\s*local-user {u}\s",
        "cisco_ios": rf"(?m)^username {u}\s",
        "cisco_nxos": rf"(?m)^username {u}\s",
        "cisco_xr": rf"(?m)^username {u}\s*$",
    }
    if plataforma == "mikrotik_routeros":
        # O export não traz usuários: vem do '/user print' (Estado).
        return bool(re.search(rf"(?m)^\s*\d+\s+[A-Z;]*\s*{u}\s+\w", basico))
    return bool(padroes.get(plataforma) and re.search(padroes[plataforma], config))


def bloco_routeros(config, cabecalho):
    """Linhas do bloco '/<cabecalho>' do export (todas as ocorrências)."""
    # O export quebra linha longa com '\' no fim; junta antes de procurar.
    texto = re.sub(r"\\\r?\n[ \t]*", "", config)
    return "\n".join(re.findall(rf"(?m)^{re.escape(cabecalho)}[ \t]*$((?:\n(?!/).*)*)",
                                texto))


def ntp_routeros6(config):
    """Campos do '/system ntp client' do RouterOS 6 ('' quando ausente)."""
    bloco = bloco_routeros(config, "/system ntp client")
    campos = {}
    for k in ("enabled", "primary-ntp", "secondary-ntp"):
        m = re.search(rf"(?:^|\s){k}=(\S+)", bloco)
        v = m.group(1) if m else ""
        campos[k] = "" if v in ("0.0.0.0", "::") else v
    return campos


def servidores_ntp(plataforma, config):
    if plataforma == "mikrotik_routeros":
        # Só o bloco do cliente NTP: 'address=' também aparece em /ip address.
        bloco = (bloco_routeros(config, "/system ntp client") + "\n"
                 + bloco_routeros(config, "/system ntp client servers"))
        achados = re.findall(r"(?:^|\s)(?:primary-ntp|secondary-ntp|address)=([\w.:-]+)",
                             bloco)
        for lista in re.findall(r"(?:^|\s)(?:servers|server-dns-names)=([\w.:,-]+)", bloco):
            achados += lista.split(",")
        return sorted({a for a in achados if a and a not in ("0.0.0.0", "::")})
    if plataforma == "cisco_xr":
        # Só o bloco 'ntp': 'server' também abre linha de TACACS e RADIUS.
        bloco = "\n".join(re.findall(r"(?m)^ntp[ \t]*$((?:\n[ \t]+.*)*)", config))
        return sorted(set(re.findall(r"(?m)^[ \t]+server (?:vrf \S+ )?(\S+)", bloco)))
    padroes = {
        "juniper_junos": r"(?m)^set system ntp server (\S+)",
        "huawei": r"(?m)^\s*ntp-service unicast-server (\S+)",
        "huawei_ce": r"(?m)^\s*ntp-service unicast-server (?:ipv6 )?(\S+)",
        "cisco_ios": r"(?m)^ntp server (?:vrf \S+ )?(\S+)",
        "cisco_nxos": r"(?m)^ntp server (\S+)",
    }
    p = padroes.get(plataforma)
    return sorted(set(re.findall(p, config))) if p else []


def telnet_ligado(plataforma, config, basico):
    if plataforma == "mikrotik_routeros":
        # '/ip service print': serviço desligado traz a flag X.
        return bool(re.search(r"(?m)^\s*\d+\s+telnet\s+\d+", basico))
    padroes = {
        "juniper_junos": r"(?m)^set system services telnet",
        "huawei": r"(?m)^\s*telnet server enable",
        "huawei_ce": r"(?m)^\s*telnet server enable",
        "cisco_ios": r"(?m)^\s*transport input (?:\S+\s+)*?(?:all|telnet)\b",
        "cisco_nxos": r"(?m)^feature telnet",
        "cisco_xr": r"(?m)^telnet (?:vrf \S+ )?ipv[46] server",
    }
    p = padroes.get(plataforma)
    return bool(p and re.search(p, config))


def comunidades_existentes(plataforma, config):
    padroes = {
        "juniper_junos": r"(?m)^set snmp community (\S+)",
        "mikrotik_routeros": r"(?m)^(?:add|set)\b[^\n]*\bname=(\S+)",
        "huawei": r"(?m)^\s*snmp-agent community (?:read|write) ",
        "huawei_ce": r"(?m)^\s*snmp-agent community (?:read|write) ",
        "cisco_ios": r"(?m)^snmp-server community ",
        "cisco_nxos": r"(?m)^snmp-server community ",
        "cisco_xr": r"(?m)^snmp-server community ",
    }
    p = padroes.get(plataforma)
    if not p:
        return 0
    alvo = config
    if plataforma == "mikrotik_routeros":
        m = re.search(r"(?m)^/snmp community\s*$((?:\n(?!/).*)*)", config)
        alvo = m.group(1) if m else ""
    return len(re.findall(p, alvo))


# ---------------------------------------------------------------------------
# Modelos por plataforma
# ---------------------------------------------------------------------------
def _wildcard(rede):
    return str(rede.hostmask)


def plano_usuario(plataforma, usuario, rede, snap):
    """(comandos, verificacao, reversao, observacoes)"""
    if plataforma == "juniper_junos":
        return ([f"set system login user {usuario} class read-only "
                 f"authentication encrypted-password \"<HASH-SHA512 de {SENHA}>\""],
                [f"show configuration system login user {usuario}"],
                [f"delete system login user {usuario}"],
                ["Classe predefinida read-only (permissão view). O hash sai de "
                 "'openssl passwd -6' ou do próprio Junos; plain-text-password "
                 "pede a senha de forma interativa e não serve em lote.",
                 "Restringir a origem por filtro de lo0 (o Junos não prende "
                 "usuário a endereço)." if rede else ""])
    if plataforma == "mikrotik_routeros":
        origem = f" address={rede}" if rede else ""
        return ([f"/user add name={usuario} group=read password=\"{SENHA}\"{origem}"],
                [f"/user print detail where name={usuario}"],
                [f"/user remove [find name={usuario}]"],
                ["Grupo predefinido read (sem write, policy, password, sensitive)."])
    if plataforma in ("huawei", "huawei_ce"):
        nivel = ("privilege level 1" if plataforma == "huawei" else "level 1")
        cmds = ["aaa",
                f" local-user {usuario} password irreversible-cipher {SENHA}",
                f" local-user {usuario} {nivel}",
                f" local-user {usuario} service-type ssh",
                "quit",
                f"ssh user {usuario} authentication-type password",
                f"ssh user {usuario} service-type stelnet"]
        rev = ["aaa", f" undo local-user {usuario}", "quit", f"undo ssh user {usuario}"]
        if plataforma == "huawei_ce":
            cmds.append("commit")
            rev.append("commit")
        return (cmds, [f"display local-user username {usuario}"], rev,
                ["Nível 1 (monitoração). No VRP V8 a mudança só vale após "
                 "'commit'; no V5 vale ao ser digitada."])
    if plataforma == "cisco_ios":
        return ([f"username {usuario} privilege 1 secret {SENHA}"],
                [f"show running-config | include ^username {usuario}"],
                [f"no username {usuario}"],
                ["Privilégio 1 não mostra a configuração; para leitura completa, "
                 "usar uma 'parser view' ou AAA com autorização por comando.",
                 "Gravar com 'write memory' só depois da verificação."])
    if plataforma == "cisco_nxos":
        return ([f"username {usuario} password {SENHA} role network-operator"],
                [f"show user-account {usuario}"],
                [f"no username {usuario}"],
                ["Papel predefinido network-operator (só leitura). Gravar com "
                 "'copy running-config startup-config' depois da verificação."])
    if plataforma == "cisco_xr":
        return (["username " + usuario, " group read-only-tg", f" secret {SENHA}"],
                [f"show running-config username {usuario}"],
                [f"no username {usuario}"],
                ["Grupo predefinido read-only-tg."])
    return None


def plano_comunidade(plataforma, rede, snap):
    if not rede:
        raise ErroPedido("informe --rede: comunidade SNMP sem restrição de origem "
                         "não entra em plano")
    r = rede
    if r.version == 6 and plataforma in SNMP_SO_IPV4:
        return ([], [], [], [], [f"rede IPv6 ({r}): o modelo desta plataforma usa ACL "
                                 "só IPv4; escreva a ACL IPv6 e a comunidade presa a "
                                 "ela na revisão"])
    if plataforma == "juniper_junos":
        return ([f"set snmp community {COMUNIDADE} authorization read-only",
                 f"set snmp community {COMUNIDADE} clients {r}"],
                ["show configuration snmp"],
                [f"delete snmp community {COMUNIDADE}"], [])
    if plataforma == "mikrotik_routeros":
        return (["/snmp set enabled=yes",
                 f"/snmp community add name={COMUNIDADE} addresses={r} "
                 "read-access=yes write-access=no"],
                ["/snmp community print detail"],
                [f"/snmp community remove [find name={COMUNIDADE}]"],
                ["Se o SNMP estava desligado, a reversão também precisa de "
                 "'/snmp set enabled=no'."])
    if plataforma in ("huawei", "huawei_ce"):
        cmds = ["acl number 2990",
                f" rule 5 permit source {r.network_address} {_wildcard(r)}",
                "quit",
                "snmp-agent sys-info version v2c",
                f"snmp-agent community read cipher {COMUNIDADE} acl 2990"]
        rev = [f"undo snmp-agent community {COMUNIDADE}", "undo acl number 2990"]
        if plataforma == "huawei_ce":
            cmds.append("commit")
            rev.append("commit")
        return (cmds, ["display snmp-agent community", "display acl 2990"], rev,
                ["Confira se a ACL 2990 está livre no equipamento antes."])
    if plataforma == "cisco_ios":
        return (["ip access-list standard NETSNAP-SNMP",
                 f" permit {r.network_address} {_wildcard(r)}",
                 f"snmp-server community {COMUNIDADE} RO NETSNAP-SNMP"],
                ["show snmp community"],
                [f"no snmp-server community {COMUNIDADE}",
                 "no ip access-list standard NETSNAP-SNMP"], [])
    if plataforma == "cisco_nxos":
        return (["ip access-list NETSNAP-SNMP",
                 f" permit ip {r} any",
                 f"snmp-server community {COMUNIDADE} group network-operator",
                 f"snmp-server community {COMUNIDADE} use-ipv4acl NETSNAP-SNMP"],
                ["show snmp community"],
                [f"no snmp-server community {COMUNIDADE}",
                 "no ip access-list NETSNAP-SNMP"], [])
    if plataforma == "cisco_xr":
        return (["ipv4 access-list NETSNAP-SNMP",
                 f" 10 permit ipv4 {r} any",
                 f"snmp-server community {COMUNIDADE} RO IPv4 NETSNAP-SNMP"],
                ["show snmp"],
                [f"no snmp-server community {COMUNIDADE}",
                 "no ipv4 access-list NETSNAP-SNMP"], [])
    return None


def plano_ntp(plataforma, servidores, snap):
    if plataforma == "juniper_junos":
        return ([f"set system ntp server {s}" for s in servidores],
                ["show ntp associations no-resolve"],
                [f"delete system ntp server {s}" for s in servidores], [])
    if plataforma == "mikrotik_routeros":
        config = texto_secao(snap, "config")
        if versao_routeros(snap) == 6:
            return _ntp_routeros6(servidores, config)
        cmd = ["/system ntp client set enabled=yes"] + [
            f"/system ntp client servers add address={s}" for s in servidores]
        rev = [f"/system ntp client servers remove [find address={s}]"
               for s in servidores]
        if not re.search(r"(?:^|\s)enabled=yes\b",
                         bloco_routeros(config, "/system ntp client")):
            rev.append("/system ntp client set enabled=no")
        return cmd, ["/system ntp client print"], rev, []
    if plataforma in ("huawei", "huawei_ce"):
        cmds = [f"ntp-service unicast-server {s}" for s in servidores]
        rev = [f"undo ntp-service unicast-server {s}" for s in servidores]
        if plataforma == "huawei_ce":
            cmds.append("commit")
            rev.append("commit")
        return cmds, ["display ntp-service sessions"], rev, []
    if plataforma in ("cisco_ios", "cisco_nxos"):
        return ([f"ntp server {s}" for s in servidores],
                ["show ntp associations" if plataforma == "cisco_ios" else "show ntp peers"],
                [f"no ntp server {s}" for s in servidores], [])
    if plataforma == "cisco_xr":
        return (["ntp"] + [f" server {s}" for s in servidores],
                ["show ntp associations"],
                ["ntp"] + [f" no server {s}" for s in servidores], [])
    return None


def _ntp_routeros6(servidores, config):
    """RouterOS 6 tem só primary-ntp e secondary-ntp (endereço IP). Os
    servidores atuais ficam; os pedidos ocupam o que estiver livre."""
    atual = ntp_routeros6(config)
    ips, nomes = [], []
    for s in servidores:
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            nomes.append(s)
    novos = {}
    for campo in ("primary-ntp", "secondary-ntp"):
        if not atual[campo] and ips:
            novos[campo] = ips.pop(0)
    obs = ["RouterOS 6 aceita dois servidores (primary-ntp e secondary-ntp); "
           "os que já estavam configurados foram mantidos."]
    if ips:
        obs.append("Não couberam (os dois campos já estão em uso): "
                   + ", ".join(ips) + ". Trocar um servidor atual é decisão "
                   "a tomar na revisão.")
    if nomes:
        obs.append("primary-ntp e secondary-ntp só aceitam endereço IP; nomes ("
                   + ", ".join(nomes) + ") vão em server-dns-names, fora deste plano.")
    verif = ["/system ntp client print"]
    if not novos:
        return [], verif, [], obs, ["nenhum servidor pedido coube no cliente NTP"]
    cmd = ["/system ntp client set enabled=yes "
           + " ".join(f"{k}={v}" for k, v in novos.items())]
    # A reversão devolve exatamente o que estava (0.0.0.0 é o campo vazio).
    antes = ([] if atual["enabled"] == "yes" else ["enabled=no"]) + [
        f"{k}={atual[k] or '0.0.0.0'}" for k in novos]
    return cmd, verif, ["/system ntp client set " + " ".join(antes)], obs


def plano_telnet(plataforma, snap):
    if plataforma == "juniper_junos":
        return (["delete system services telnet"], ["show configuration system services"],
                ["set system services telnet"], [])
    if plataforma == "mikrotik_routeros":
        return (["/ip service disable telnet"], ["/ip service print"],
                ["/ip service enable telnet"], [])
    if plataforma in ("huawei", "huawei_ce"):
        cmds = ["undo telnet server enable"]
        rev = ["telnet server enable"]
        if plataforma == "huawei_ce":
            cmds.append("commit")
            rev.append("commit")
        return (cmds, ["display telnet server status"], rev,
                ["Confirme antes que a sessão de gerência é SSH: a mudança "
                 "derruba quem está conectado por Telnet."])
    config = texto_secao(snap, "config")
    if plataforma == "cisco_ios":
        return _telnet_ios(config, snap["meta"])
    if plataforma == "cisco_nxos":
        return (["no feature telnet"], ["show feature | include telnet"],
                ["feature telnet"], [])
    if plataforma == "cisco_xr":
        # Uma linha por VRF e família: desliga e devolve cada uma como estava.
        linhas = [m.group(0).rstrip() for m in re.finditer(
            r"(?m)^(telnet (?:vrf \S+ )?ipv[46] server)\b.*$", config)]
        if not linhas:
            return ([], ["show running-config telnet"], [], [],
                    ["linha 'telnet ... server' não identificada na configuração"])
        return (["no " + re.match(r"telnet (?:vrf \S+ )?ipv[46] server", lin).group(0)
                 for lin in linhas],
                ["show running-config telnet"], linhas, [])
    return None


def _telnet_ios(config, meta):
    """Tira o telnet de cada bloco 'line vty' como ele está na configuração:
    um 'line vty 0 15' único sobrescreveria faixas com ajustes diferentes."""
    cmds, rev, sem_transporte, revisar = [], [], [], []
    for cab, corpo in re.findall(r"(?m)^(line vty \d+(?: \d+)?)[ \t]*$((?:\n[ \t]+.*)*)",
                                 config):
        m = re.search(r"(?m)^[ \t]+transport input (.+?)[ \t]*$", corpo)
        if not m:
            sem_transporte.append(cab)
            continue
        atual = m.group(1).split()
        if "telnet" not in atual and "all" not in atual:
            continue
        novo = [t for t in atual if t not in ("telnet", "all", "none")]
        if "ssh" not in novo:
            novo.append("ssh")
        cmds += [cab, " transport input " + " ".join(novo)]
        rev += [cab, " transport input " + " ".join(atual)]
    obs = ["Rede de segurança antes de aplicar: 'reload in 10' sem gravar a "
           "configuração ('reload cancel' depois de entrar de novo por SSH) ou, "
           "com archive configurado, 'configure replace <cópia> time 600' / "
           "'configure terminal revert timer 10'."]
    if sem_transporte:
        revisar.append("bloco(s) sem 'transport input' explícito ("
                       + ", ".join(sem_transporte) + "): o padrão muda com a versão")
    if not cmds:
        revisar.append("telnet habilitado fora dos blocos 'line vty' identificados")
    if revisar:
        capturadas = re.findall(r"(?m)^line \S+.*$|^[ \t]+transport input .*$", config)
        if capturadas:
            obs.append("Linhas capturadas: " + " | ".join(c.strip() for c in capturadas))
    # SSH em uso: coleta feita por SSH ou configuração de 'ip ssh'/'crypto key'.
    # Sem isso, só SSH nas VTY pode trancar o acesso.
    if (str(meta.get("transport") or "").lower() != "ssh"
            and not re.search(r"(?m)^(ip ssh|crypto key)\b", config)):
        revisar.append("sem sinal de SSH configurado ('ip ssh' ou 'crypto key') "
                       "nem coleta por SSH: deixar só SSH nas VTY pode trancar o acesso")
    return cmds, ["show line vty 0 15 | include Allowed"], rev, obs, revisar


# Como aplicar com segurança, por plataforma: commit confirmado onde existe
# (volta sozinho se a sessão cair), Safe Mode no RouterOS.
def como_aplicar(plataforma):
    if plataforma == "juniper_junos":
        return ["configure private", "<comandos>", "show | compare", "commit check",
                "commit confirmed 5", "<verificação>", "commit"]
    if plataforma == "cisco_xr":
        return ["configure", "<comandos>", "show commit changes diff",
                "commit confirmed 300", "<verificação>", "commit"]
    if plataforma == "huawei_ce":
        return ["system-view", "<comandos (o commit já está no fim)>",
                "<verificação>"]
    if plataforma == "mikrotik_routeros":
        return ["Abrir o Safe Mode (Ctrl+X) numa sessão interativa", "<comandos>",
                "<verificação>", "Ctrl+X de novo para confirmar"]
    if plataforma == "huawei":
        return ["system-view", "<comandos>", "<verificação>", "quit", "save"]
    if plataforma in ("cisco_ios", "cisco_nxos"):
        return ["configure terminal", "<comandos>", "end", "<verificação>",
                "copy running-config startup-config"]
    return []


# ---------------------------------------------------------------------------
# Montagem do plano
# ---------------------------------------------------------------------------
def _validar_usuario(nome):
    if not nome or not re.fullmatch(r"[A-Za-z][\w.-]{0,30}", nome):
        raise ErroPedido("usuário: letra seguida de letras, números, '.', '_' ou "
                         "'-' (até 31 caracteres)")
    return nome


def _validar_rede(texto):
    if not texto:
        return None
    try:
        rede = ipaddress.ip_network(texto, strict=False)
    except ValueError:
        raise ErroPedido(f"rede inválida: {texto}")
    if rede.prefixlen == 0:
        raise ErroPedido("0.0.0.0/0 não é restrição de origem")
    return rede


def _validar_servidores(lista):
    saida = []
    for s in lista or []:
        try:
            saida.append(str(ipaddress.ip_address(s)))
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", s):
                raise ErroPedido(f"servidor NTP inválido: {s}")
            saida.append(s)
    if not saida:
        raise ErroPedido("informe ao menos um --servidor")
    return saida


def contas_reservadas(meta):
    """Contas conhecidas mais a usada na coleta, quando o snapshot a traz."""
    contas = set(CONTAS_CONHECIDAS)
    for chave in ("username", "user"):
        if meta.get(chave):
            contas.add(str(meta[chave]).lower())
    return contas


def plano_do_host(pedido, snap):
    meta = snap["meta"]
    plataforma = meta.get("platform_key") or ""
    config = texto_secao(snap, "config")
    basico = texto_secao(snap, "basico")
    item = {"host": meta.get("host"), "ip": meta.get("ip"),
            "plataforma": plataforma,
            "plataforma_nome": meta.get("platform_name") or plataforma,
            "coletado_em": meta.get("collected_at"),
            "situacao": "aplicar", "estado_atual": [], "comandos": [],
            "verificacao": [], "reversao": [], "observacoes": [],
            "como_aplicar": [], "validacao": "documentação; validar em laboratório"}
    if plataforma not in PLATAFORMAS:
        item.update(situacao="nao-suportado",
                    observacoes=["Plataforma ainda sem modelo no netcontrol."])
        return item
    # Sem a configuração, "não achei" não quer dizer "não existe": nenhum
    # plano sai como aplicar e nenhum 'ja-existe' se apoia na ausência.
    sem_config = not config.strip()
    revisar = []
    if sem_config:
        revisar.append("snapshot sem a seção Configuração: o estado atual não "
                       "pôde ser conferido")
    tipo, p = pedido["tipo"], pedido["parametros"]
    if tipo == "usuario-leitura":
        if p["usuario"].lower() in contas_reservadas(meta):
            item["situacao"] = "revisar"
            item["observacoes"].append(
                f"'{p['usuario']}' é conta conhecida ou a usada na coleta: o plano "
                "trocaria a senha e o nível dessa conta e a reversão a apagaria. "
                "Escolha outro nome.")
            return item
        if tem_usuario(plataforma, config, basico, p["usuario"]):
            item["situacao"] = "ja-existe"
            item["estado_atual"].append(f"usuário {p['usuario']} já existe")
            return item
        r = plano_usuario(plataforma, p["usuario"], p.get("rede"), snap)
        if p.get("rede") and plataforma not in ("mikrotik_routeros", "juniper_junos"):
            item["observacoes"].append(
                f"A rede {p['rede']} não entra neste modelo: a origem se restringe "
                "pela ACL das linhas de acesso (VTY/user-interface).")
    elif tipo == "snmp-comunidade":
        n = comunidades_existentes(plataforma, config)
        item["estado_atual"].append(f"{n} comunidade(s) SNMP configurada(s) "
                                    "(valores mascarados no snapshot)")
        r = plano_comunidade(plataforma, p.get("rede"), snap)
    elif tipo == "ntp":
        atuais = servidores_ntp(plataforma, config)
        item["estado_atual"].append("NTP atual: " + (", ".join(atuais) or "nenhum"))
        faltam = [s for s in p["servidores"] if s not in atuais]
        if not faltam:
            item["situacao"] = "ja-existe"
            return item
        r = plano_ntp(plataforma, faltam, snap)
    elif tipo == "desligar-telnet":
        if plataforma == "mikrotik_routeros":
            evidencia = re.search(r"(?m)^\s*\d+\s+(?:[A-Z]+\s+)?telnet\s", basico)
        else:
            evidencia = not sem_config
        if not telnet_ligado(plataforma, config, basico):
            if evidencia:
                item["situacao"] = "ja-existe"
                item["estado_atual"].append("Telnet não aparece habilitado")
                return item
            revisar.append("o snapshot não mostra se o Telnet está ligado")
        else:
            item["estado_atual"].append("Telnet habilitado")
        if str(meta.get("transport") or "").lower() == "telnet":
            revisar.append("o snapshot foi coletado por Telnet: a gerência deste "
                           "equipamento pode depender dele, e desligá-lo sem SSH "
                           "validado tranca o acesso")
        r = plano_telnet(plataforma, snap)
    else:
        raise ErroPedido(f"pedido desconhecido: {tipo}")
    if r is None:
        item.update(situacao="nao-suportado",
                    observacoes=["Plataforma sem modelo para este pedido."])
        return item
    item["comandos"], item["verificacao"], item["reversao"], obs = r[:4]
    revisar += list(r[4]) if len(r) > 4 else []
    item["observacoes"] += [o for o in obs if o]
    if revisar:
        item["situacao"] = "revisar"
        item["observacoes"].insert(0, "Revisar: " + "; ".join(revisar) + ".")
    item["como_aplicar"] = como_aplicar(plataforma)
    return item


def _lista_comandos(valor):
    if isinstance(valor, str):
        valor = valor.splitlines()
    if not isinstance(valor, list):
        return []
    return [str(c) for c in valor if str(c).strip()]


def conferir_comandos(propostos, reversao):
    """Confere de novo os comandos vindos da análise.

    Retorno: (propostos, reversao, motivos de revisão). Destrutivos saem da
    lista; os que mexem no caminho de gerência ficam, mas levam à revisão."""
    retirados = [c for c in propostos + reversao if PERIGOSOS.search(c)]
    propostos = [c for c in propostos if not PERIGOSOS.search(c)]
    reversao = [c for c in reversao if not PERIGOSOS.search(c)]
    motivos = []
    if retirados:
        motivos.append(f"{len(retirados)} comando(s) destrutivo(s) retirado(s): "
                       + "; ".join(retirados))
    gerencia = []
    for padrao, motivo in GERENCIA:
        if motivo not in gerencia and any(padrao.search(c) for c in propostos + reversao):
            gerencia.append(motivo)
    if gerencia:
        motivos.append("mexe no caminho de gerência (" + ", ".join(gerencia)
                       + "): aplicar com acesso fora de banda e janela")
    return propostos, reversao, motivos


def plano_de_analise(caminho):
    """Converte o _ia_analise_*.json do netsnap_ia: um item por achado com
    comandos propostos. O arquivo pode ter sido editado depois da análise:
    comandos destrutivos são retirados de novo aqui, e o achado só sai como
    'aplicar' se nada mexer no caminho de gerência, houver reversão e a
    confiança não for baixa; o resto vai para revisão."""
    with open(caminho, encoding="utf-8") as f:
        analise = json.load(f)
    if analise.get("formato") != "netanalytic-achados/1":
        raise ErroPedido("arquivo não é um resultado do netsnap_ia")
    itens = []
    for h in analise.get("hosts", []):
        for a in h.get("achados", []):
            propostos = _lista_comandos(a.get("comandos_propostos"))
            if not propostos:
                continue
            propostos, reversao, motivos = conferir_comandos(
                propostos, _lista_comandos(a.get("comandos_reversao")))
            if not propostos:
                motivos.append("nenhum comando proposto sobrou depois da conferência")
            if not reversao:
                motivos.append("a análise não trouxe reversão: escreva antes de aplicar")
            if a.get("confianca") not in ("alta", "media"):
                motivos.append("confiança baixa ou não informada na análise: "
                               "revise a evidência")
            itens.append({
                "host": h.get("host"), "ip": h.get("ip"),
                "plataforma": h.get("plataforma") or "",
                "plataforma_nome": h.get("plataforma") or "",
                "situacao": "revisar" if motivos else "aplicar",
                "titulo": a.get("titulo"), "severidade": a.get("severidade"),
                "estado_atual": [],
                "evidencia": [{"comando": str(e.get("comando") or "")[:200],
                               "trecho": str(e.get("trecho") or "")[:2000]}
                              for e in a.get("evidencia", []) if isinstance(e, dict)],
                "comandos": propostos,
                "verificacao": [],
                "reversao": reversao,
                "observacoes": (["Revisar: " + "; ".join(motivos) + "."]
                                if motivos else []),
                "como_aplicar": como_aplicar(h.get("plataforma") or ""),
                "validacao": "proposto por IA; revisar e validar em laboratório",
            })
    return itens


def _linha(texto):
    """Texto livre numa linha só: quebra de linha ou crase no título e nas
    observações abririam bloco novo no Markdown (um 'Comandos:' falso)."""
    texto = re.sub(r"\s*[\r\n\v\f\x85\u2028\u2029]+\s*", " ", str(texto))
    return texto.replace("\\", "\\\\").replace("`", "\\`")


def _cerca(corpo):
    return "`" * max(3, max((len(m) for m in re.findall(r"`+", corpo)), default=0) + 1)


def gerar_md(plano):
    linhas = [f"# Plano de mudança — {_linha(plano['pedido']['descricao'])}", "",
              f"Gerado em {plano['gerado_em'][:16].replace('T', ' ')} pelo netcontrol "
              f"{__version__}. **Simulação: nada foi aplicado.** Senhas e "
              "comunidades aparecem como marcadores.", ""]
    cont = {}
    for h in plano["hosts"]:
        cont[h["situacao"]] = cont.get(h["situacao"], 0) + 1
    linhas.append(" · ".join(f"{k}: {v}" for k, v in sorted(cont.items())) + "\n")
    for h in plano["hosts"]:
        titulo = f"{h['host']} ({h['ip']}) — {h['plataforma_nome']}"
        if h.get("titulo"):
            titulo += f" — [{str(h.get('severidade', '')).upper()}] {h['titulo']}"
        linhas += ["## " + _linha(titulo), "",
                   f"Situação: **{h['situacao']}** · validação: {h['validacao']}", ""]
        for e in h["estado_atual"]:
            linhas.append(f"- Estado atual: {_linha(e)}")
        for o in h["observacoes"]:
            linhas.append(f"- Observação: {_linha(o)}")
        for e in h.get("evidencia", []):
            trecho = e["trecho"]
            cerca = _cerca(trecho)
            linhas += ["", f"Evidência ({_linha(e['comando'])}):", "", cerca, trecho, cerca]
        for rotulo, chave in (("Comandos", "comandos"), ("Verificação", "verificacao"),
                              ("Reversão", "reversao"), ("Como aplicar", "como_aplicar")):
            if h.get(chave):
                corpo = "\n".join(h[chave])
                cerca = _cerca(corpo)
                linhas += ["", f"{rotulo}:", "", cerca, corpo, cerca]
        linhas.append("")
    return "\n".join(linhas)


def gerar_plano(pedido, entrada, saida=None):
    if pedido["tipo"] == "analise":
        hosts = plano_de_analise(entrada)
        pasta = saida or os.path.dirname(os.path.abspath(entrada))
    else:
        if not os.path.isdir(entrada):
            raise ErroPedido(f"pasta de snapshots não encontrada: {entrada}")
        caminhos = md.listar_snapshots(entrada)
        if not caminhos:
            raise ErroPedido(f"nenhum snapshot em {entrada}")
        hosts = [plano_do_host(pedido, md.ler_snapshot(c))
                 for c, _ in sorted(md.mais_recentes(caminhos))]
        pasta = saida or entrada
    agora = datetime.now()
    plano = {"formato": FORMATO, "gerado_em": agora.isoformat(timespec="seconds"),
             "simulacao": True, "pedido": pedido, "hosts": hosts}
    os.makedirs(pasta, exist_ok=True)
    base = os.path.join(pasta, f"_netcontrol_plano_{agora:%Y%m%d_%H%M%S}")
    n = 2
    while os.path.exists(base + ".json"):  # dois planos no mesmo segundo
        base = os.path.join(pasta, f"_netcontrol_plano_{agora:%Y%m%d_%H%M%S}_{n}")
        n += 1
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(plano, f, ensure_ascii=False, indent=1, default=str)
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(gerar_md(plano))
    return plano, base


def montar_pedido(args):
    tipo = args.pedido
    if tipo == "usuario-leitura":
        usuario = _validar_usuario(args.usuario)
        rede = _validar_rede(args.rede)
        desc = f"usuário só leitura {usuario}" + (f" (origem {rede})" if rede else "")
        par = {"usuario": usuario, "rede": rede}
    elif tipo == "snmp-comunidade":
        rede = _validar_rede(args.rede)
        if not rede:
            raise ErroPedido("informe --rede (origem permitida)")
        desc = f"comunidade SNMP só leitura para {rede}"
        par = {"rede": rede}
    elif tipo == "ntp":
        servidores = _validar_servidores(args.servidor)
        desc = "NTP " + ", ".join(servidores)
        par = {"servidores": servidores}
    elif tipo == "desligar-telnet":
        desc, par = "desligar Telnet", {}
    elif tipo == "analise":
        desc, par = f"achados do netsnap_ia ({os.path.basename(args.entrada)})", {}
    else:
        raise ErroPedido(f"pedido desconhecido: {tipo}")
    return {"tipo": tipo, "descricao": desc, "parametros": par}


def perguntar(args):
    """Modo interativo: o operador escolhe o pedido e informa os dados."""
    opcoes = ["usuario-leitura", "snmp-comunidade", "ntp", "desligar-telnet", "analise"]
    print("Pedido:")
    for i, o in enumerate(opcoes, 1):
        print(f"  {i}) {o}")
    while True:
        r = input("Escolha [1-5]: ").strip()
        if r in {"1", "2", "3", "4", "5"}:
            args.pedido = opcoes[int(r) - 1]
            break
    rotulo = ("arquivo _ia_analise_*.json" if args.pedido == "analise"
              else "pasta de snapshots")
    args.entrada = input(f"{rotulo.capitalize()} [snapshots]: ").strip() or "snapshots"
    if args.pedido == "usuario-leitura":
        args.usuario = input("Usuário: ").strip()
        args.rede = input("Rede de origem (opcional): ").strip() or None
    elif args.pedido == "snmp-comunidade":
        args.rede = input("Rede de origem permitida: ").strip()
    elif args.pedido == "ntp":
        args.servidor = input("Servidores NTP (separados por espaço): ").split()
    return args


def main():
    if os.name == "posix":
        os.umask(0o077)
    ap = argparse.ArgumentParser(
        description="Planos de mudança por equipamento a partir dos snapshots do "
                    "netsnap. Simulação: nada é aplicado.")
    ap.add_argument("pedido", nargs="?",
                    choices=["usuario-leitura", "snmp-comunidade", "ntp",
                             "desligar-telnet", "analise"])
    ap.add_argument("entrada", nargs="?", default="snapshots",
                    help="pasta de snapshots (ou o _ia_analise_*.json no pedido analise)")
    ap.add_argument("--usuario")
    ap.add_argument("--rede", help="rede de origem permitida (CIDR)")
    ap.add_argument("--servidor", action="append", help="servidor NTP (repita)")
    ap.add_argument("--saida", help="pasta do plano (padrão: a da entrada)")
    ap.add_argument("-v", "--version", action="version",
                    version=f"netcontrol {__version__}")
    args = ap.parse_args()
    print(f"netcontrol v{__version__} — simulação (nada é aplicado)")
    try:
        if not args.pedido:
            args = perguntar(args)
        pedido = montar_pedido(args)
        plano, base = gerar_plano(pedido, args.entrada, args.saida)
    except (ErroPedido, OSError, ValueError) as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    cont = {}
    for h in plano["hosts"]:
        cont[h["situacao"]] = cont.get(h["situacao"], 0) + 1
    print("[+] " + ", ".join(f"{v} {k}" for k, v in sorted(cont.items())))
    print(f"[+] Plano: {base}.md e .json")


if __name__ == "__main__":
    main()
