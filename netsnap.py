#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netsnap — Extrator de snapshot multi-vendor via SSH (somente leitura)

Coleta configuração, logs, dados operacionais, vizinhança L2 e inventário de
versões/licenças de equipamentos de rede e servidores, gerando um arquivo
Markdown por host, estruturado para leitura por humanos e por sistemas de IA.

Plataformas: Juniper Junos, Huawei VRP V5 (campus), Huawei VRP V8
(CloudEngine/NE), Huawei SmartAX (OLT), FiberHome OLT, Cisco NX-OS,
Cisco IOS/IOS-XE, Cisco IOS-XR, MikroTik RouterOS e Linux.
Módulos de aplicação em Linux: ISP-Stack, WANGuard, BIRD, SmokePing,
Zabbix, Grafana e BIND9
(este último com verificação do bloqueio por RPZ ou por zona-sinkhole).

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.15.1"

import os
import re
import sys
import time
import json
import shutil
import socket
import getpass
import logging
import platform
import ipaddress
import subprocess
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect
from netmiko.terminal_server import TerminalServerTelnet
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Suprime tracebacks da thread de transporte do Paramiko no console;
# falhas de conexão são reportadas pelo próprio netsnap de forma resumida.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

PASTA_SAIDA = "snapshots"
PRINT_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Depuração: registra em arquivo próprio cada etapa da identificação e cada
# comando enviado ao equipamento, com tempo e volume de retorno. O arquivo é
# independente do snapshot e destina-se a diagnóstico da própria coleta.
# ---------------------------------------------------------------------------
DEBUG = False
ARQUIVO_DEBUG = None
DEBUG_LOCK = threading.Lock()
DEBUG_LIMITE_AMOSTRA = 1200  # caracteres de retorno registrados por comando
# Valor alto de propósito: o log de depuração é a via pela qual se
# descobre a estrutura real de um serviço (nomes de tabela, colunas,
# sintaxe aceita). Amostras curtas demais escondem justamente o que
# permitiria corrigir o perfil.


def iniciar_debug(pasta):
    global ARQUIVO_DEBUG
    ARQUIVO_DEBUG = os.path.join(
        pasta, f"_debug_{datetime.now():%Y%m%d_%H%M%S}.log")
    with open(ARQUIVO_DEBUG, "w", encoding="utf-8") as f:
        f.write(f"# netsnap {__version__} — log de depuração\n")
        f.write(f"# iniciado em {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"# python {platform.python_version()} em "
                f"{platform.system()} {platform.release()}\n")
        f.write("# formato: hora | host | evento | detalhe\n\n")
    return ARQUIVO_DEBUG


def depurar(host, evento, detalhe=""):
    """Registra um evento no log de depuração (sem efeito se DEBUG=False)."""
    if not DEBUG or not ARQUIVO_DEBUG:
        return
    linha = (f"{datetime.now():%H:%M:%S.%f}"[:-3] +
             f" | {host:<18} | {evento:<22} | {detalhe}")
    with DEBUG_LOCK:
        try:
            with open(ARQUIVO_DEBUG, "a", encoding="utf-8") as f:
                f.write(linha + "\n")
        except OSError:
            pass


def resumir_saida(texto, limite=DEBUG_LIMITE_AMOSTRA):
    """Compacta um retorno para registro no log, preservando o essencial.

    A amostra passa sempre pelo sanitizador: o log de depuração costuma ser
    enviado para análise de terceiros, e a opção de incluir dados sensíveis
    vale para o snapshot, não para o diagnóstico da coleta."""
    t = sanitizar(PADRAO_ANSI.sub("", texto or ""))
    t = " ".join(t.split())
    return t[:limite] + (" [...]" if len(t) > limite else "")

SECOES = ["config", "logs", "basico", "optica", "vizinhanca", "inventario"]
TITULOS = {
    "config": "Configuração",
    "logs": "Logs",
    "basico": "Estado do equipamento (CPU, memória, alarmes, protocolos)",
    "optica": "Interfaces e ópticas (módulo, sinal, velocidade, tráfego, erros)",
    "vizinhanca": "Vizinhança L2 (LLDP / CDP)",
    "inventario": "Inventário (versões, software e licenças)",
}

# Conjuntos de seções oferecidos no menu inicial.
MAPA_MODOS = {
    "1": (["config"], "Configuração"),
    "2": (["logs"], "Logs"),
    "3": (["basico"], "Estado do equipamento"),
    "4": (["optica"], "Interfaces e ópticas"),
    "5": (["vizinhanca"], "Vizinhança L2"),
    "6": (["inventario"], "Inventário"),
    "7": (["config", "optica", "vizinhanca", "inventario"],
          "Mapa da rede (configuração + ópticas + vizinhança + inventário)"),
    "8": (list(SECOES), "Extração total"),
}


def log(ip, msg):
    with PRINT_LOCK:
        print(f"[{ip}] {msg}")


def preparar_ambiente() -> str:
    """Cria a pasta de saída sem exigir privilégios elevados.
    Tenta ao lado do script; sem permissão de escrita, usa a home do usuário."""
    global PASTA_SAIDA
    candidatos = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots"),
        os.path.join(os.path.expanduser("~"), "netsnap_snapshots"),
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
    print("[ERRO] Sem permissão de escrita em nenhuma pasta candidata:")
    for p in candidatos:
        print(f"       - {p}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Perfis por plataforma — exclusivamente comandos de leitura.
#
# Campos opcionais por perfil:
#   fabricante : usado nos metadados do relatório
#   driver     : device_type do Netmiko quando difere da chave
#   prep       : comandos executados após o login (paginação, contexto);
#                falhas são ignoradas e o retorno não entra no relatório
#   timing     : leitura por temporização, para CLIs com prompt fora do padrão
#   contexto   : True quando a plataforma exige contexto privilegiado/config
#                para executar comandos show (documentado no relatório)
#   sair       : comandos de saída de contexto executados ao final
# ---------------------------------------------------------------------------
PERFIS = {
    "juniper_junos": {
        "nome": "Juniper Junos (MX)",
        "fabricante": "Juniper",
        "config": ["show configuration | display set"],
        "logs": ["show log messages | last 300"],
        "basico": [
            "show chassis routing-engine",
            "show system alarms",
            "show chassis environment",
            "show bgp summary",
            "show ospf neighbor",
            "show route summary",
            # Em BNG, o essencial é a contagem e a distribuição de sessões,
            # não a lista de assinantes — que muda a cada minuto e chega a
            # milhares de linhas.
            "show subscribers summary",
            "show pppoe statistics",
        ],
        "optica": [
            # Filtro positivo pelas interfaces de infraestrutura. Um filtro
            # negativo ('| except pp0\\.') não serviria: a saída do terse usa
            # linhas de continuação para famílias adicionais (inet6), e
            # remover apenas a linha do nome deixaria milhares de linhas
            # órfãs, sem indicação de a que interface pertencem.
            "show interfaces terse | match "
            "\"^(ge-|xe-|et-|fe-|ae|irb|lo0|em0|fxp|si-|demux0 |lc-|pfe|pfh)\"",
            # Sessões de assinante são efêmeras e chegam a milhares num BNG:
            # entram como contagem, não como lista.
            "show interfaces terse | match \"pp0\\.\" | count",
            "show interfaces terse | match \"demux0\\.[0-9]\" | count",
            "show interfaces descriptions",
            # DOM completo: Rx/Tx, temperatura, bias e limiares de alarme
            "show interfaces diagnostics optics",
            # Modelo/PN do transceiver (base para inferir alcance do módulo)
            "show chassis hardware detail",
            # Velocidade, modo de enlace e contadores por interface física
            "show interfaces media",
            # 'show interfaces extensive' foi retirado: mede-se 52 s de
            # média por equipamento (91 s no pior caso), porque o Junos
            # gera a saída completa antes de aplicar o filtro. O
            # 'show interfaces media' acima já traz Speed, Description,
            # Input/Output rate, last flapped, alarmes e estatísticas PCS.
        ],
        "vizinhanca": [
            "show lldp neighbors",
            # Distingue "sem vizinho" de "LLDP desabilitado": retorno vazio
            # em 'show lldp neighbors' não diz qual dos dois é o caso.
            "show lldp",
            "show configuration protocols lldp",
            "show lldp local-information",
        ],
        "inventario": [
            # 'show version detail' custa mais de 20 s por equipamento e
            # acrescenta a lista de pacotes internos, de pouco proveito para
            # inventário e triagem: a release vem em 'show version'.
            "show version",
            "show chassis hardware detail",
            "show chassis firmware",
            "show system license",
            "show system license usage",
        ],
    },
    "huawei": {
        # VRP V5 — linha campus/agregação (S5700, S6720, S6730, S9700).
        # Distingue-se do CloudEngine pelo 'display version': V5 reporta
        # "Version 5.x", o CloudEngine reporta "Version 8.x".
        "nome": "Huawei VRP V5 (S6730/S5700/S9700)",
        "fabricante": "Huawei",
        "config": ["display current-configuration"],
        "logs": ["display logbuffer"],
        "basico": [
            "display cpu-usage",
            "display memory-usage",
            "display device",
            "display alarm active",
            "display bgp peer",
            "display ospf peer brief",
            "display temperature all",
        ],
        "optica": [
            # Traz utilização (InUti/OutUti) e contadores de erro por porta
            "display interface brief",
            "display interface description",
            # DOM completo: inclui 'Transfer Distance', wavelength, vendor/PN
            "display transceiver verbose",
            "display transceiver diagnosis interface",
            "display interface",
            # Em VRP V5 'display interface counters errors' é recusado com
            # "Wrong parameter"; a forma aceita não leva o qualificador.
            "display interface counters",
        ],
        "vizinhanca": [
            "display lldp neighbor brief",
            "display lldp neighbor",
        ],
        "inventario": [
            "display version",
            "display device",
            "display device manufacture-info",
            "display esn",
            "display patch-information",
            "display license",
            "display startup",
        ],
    },
    "huawei_ce": {
        # VRP V8 — CloudEngine (CE6800/CE6860/CE8800) e NE. A sintaxe diverge
        # da linha campus: não há 'display cpu-usage' nem 'display memory-usage'
        # (ambos recusados com "Unrecognized command"); o estado de hardware
        # vem agregado em 'display health'.
        "nome": "Huawei VRP V8 (CloudEngine CE/NE)",
        "fabricante": "Huawei",
        # 'huawei_ce' é chave interna do netsnap, não um device_type do
        # Netmiko: o driver da linha V8 chama-se huawei_vrpv8.
        "driver": "huawei_vrpv8",
        "config": ["display current-configuration"],
        "logs": ["display logbuffer"],
        "basico": [
            "display health",
            "display device",
            "display alarm active",
            "display bgp peer",
            "display ospf peer brief",
            "display fan",
            "display power",
        ],
        "optica": [
            "display interface brief",
            "display interface description",
            # Em VRP V8 a forma com 'verbose' é recusada; as variantes
            # abaixo cobrem as sub-versões encontradas em campo.
            "display transceiver",
            "display transceiver diagnosis",
            "display interface transceiver",
            "display interface",
            "display interface counters errors",
        ],
        "vizinhanca": [
            "display lldp neighbor brief",
            "display lldp neighbor",
        ],
        "inventario": [
            "display version",
            "display device",
            "display device manufacture-info",
            "display esn",
            "display patch-information",
            "display license",
            "display startup",
        ],
    },
    "huawei_smartax": {
        "nome": "Huawei SmartAX (OLT MA5800)",
        "fabricante": "Huawei",
        # O login cai no modo usuário (">"), onde 'display
        # current-configuration' é recusado. 'enable' apenas eleva o
        # privilégio da sessão; não entra em modo de configuração.
        "prep": ["enable"],
        "config": ["display current-configuration"],
        "logs": ["display log"],
        "basico": [
            "display board 0",
            "display cpu 0",
            "display mem 0",
            "display alarm active alarmtype all",
            "display temperature 0",
        ],
        "optica": [
            "display port state all",
            "display interface brief",
            # Ópticas dos uplinks; a sintaxe varia entre placas de controle
            "display transceiver verbose",
            "display port optical-info all",
            "display statistics port all",
        ],
        "vizinhanca": [
            "display lldp neighbor",
            "display lldp neighbor brief",
        ],
        "inventario": [
            "display version",
            "display board 0",
            "display patch all",
            "display license",
            "display license resource usage",
            "display sysman service state",
        ],
    },
    "fiberhome": {
        "nome": "FiberHome OLT (AN55xx/AN6000)",
        "fabricante": "FiberHome",
        "driver": "generic",
        "timing": True,
        "contexto": True,
        # A CLI FiberHome exige contexto privilegiado (e, em várias famílias,
        # o contexto 'config') mesmo para comandos show. Somente comandos de
        # leitura são executados dentro do contexto; nada é gravado.
        "prep": [
            "enable",
            "terminal length 0",
            "screen-rows per-page 0",
            "config",
        ],
        "sair": ["quit", "exit"],
        "config": [
            "show running-config",
            "show current-configuration",
        ],
        "logs": [
            "show log",
            "show alarm active",
            "show alarm history",
        ],
        "basico": [
            "show card",
            "show device",
            "show fan",
            "show power",
            "show temperature",
            "show sys-time",
        ],
        # A nomenclatura FiberHome varia bastante entre AN55xx e AN6000;
        # os comandos não suportados são marcados e não poluem o relatório.
        "optica": [
            "show interface brief",
            "show port statistics",
            "show optical-module-info",
            "show optic-module-info",
            "show transceiver information",
            "show interface optical-info",
            "show port description",
        ],
        "vizinhanca": [
            "show lldp neighbor",
            "show lldp remote-info",
        ],
        "inventario": [
            "show version",
            "show card",
            "show system-info",
            "show patch",
            "show license",
        ],
    },
    "cisco_nxos": {
        "nome": "Cisco Nexus (NX-OS)",
        "fabricante": "Cisco",
        "config": ["show running-config"],
        "logs": ["show logging last 300"],
        "basico": [
            "show environment",
            "show system resources",
            "show module",
            "show bgp sessions",
        ],
        "optica": [
            "show interface status",
            "show interface brief",
            "show interface description",
            # DOM com limiares de alarme/aviso por porta
            "show interface transceiver details",
            "show interface counters errors",
            "show interface counters",
            "show interface counters detailed",
        ],
        "vizinhanca": [
            "show cdp neighbors detail",
            "show lldp neighbors detail",
        ],
        "inventario": [
            "show version",
            "show inventory",
            "show module",
            "show feature",
            "show license usage",
            "show license host-id",
        ],
    },
    "cisco_ios": {
        "nome": "Cisco IOS/IOS-XE (ASR 1000)",
        "fabricante": "Cisco",
        "config": ["show running-config"],
        "logs": ["show logging"],
        "basico": [
            "show processes cpu sorted | exclude 0.00",
            "show memory statistics",
            "show environment all",
            "show ip bgp summary",
        ],
        "optica": [
            "show ip interface brief",
            "show interfaces status",
            "show interfaces description",
            # DOM: potência Rx/Tx, temperatura, bias e limiares
            "show interfaces transceiver detail",
            "show interfaces transceiver",
            "show interfaces counters errors",
            "show interfaces",
        ],
        "vizinhanca": [
            "show cdp neighbors detail",
            "show lldp neighbors detail",
        ],
        "inventario": [
            "show version",
            "show inventory",
            "show license summary",
            "show license udi",
            "show platform",
        ],
    },
    "cisco_xr": {
        "nome": "Cisco IOS-XR (ASR 9000)",
        "fabricante": "Cisco",
        "config": ["show running-config"],
        "logs": ["show logging last 300"],
        "basico": [
            "show processes cpu",
            "show memory summary",
            "show environment all",
            "show bgp summary",
            "show redundancy summary",
        ],
        "optica": [
            "show interfaces brief",
            "show interfaces description",
            # Em IOS-XR o DOM fica em 'controllers optics'; sem o resumo
            # global em todas as releases, os candidatos são tentados
            "show controllers optics summary",
            "show controllers optics brief",
            "show inventory all",
            "show interfaces accounting brief",
            "show interfaces",
        ],
        "vizinhanca": [
            "show lldp neighbors detail",
            "show cdp neighbors detail",
        ],
        "inventario": [
            "show version",
            "show inventory",
            "show install active summary",
            "show license all",
        ],
    },
    "mikrotik_routeros": {
        "nome": "MikroTik RouterOS",
        "fabricante": "MikroTik",
        "config": ["/export show-sensitive"],
        "logs": ["/log print without-paging"],
        "basico": [
            "/system resource print",
            "/system health print",
            "/routing bgp session print brief without-paging",
            # Serviços de gerência (telnet, ftp, www, api) e origens
            # permitidas: habilitado é o padrão e não aparece no export.
            "/ip service print without-paging",
        ],
        "optica": [
            "/interface print stats without-paging",
            "/interface ethernet print without-paging",
            "/ip address print without-paging",
            # monitor once em todas as ethernet: para portas SFP retorna
            # vendor/PN, wavelength, sfp-link-length (alcance), temperatura
            # e potências Rx/Tx do módulo
            "/interface ethernet monitor [find] once",
            "/interface ethernet print stats without-paging",
            "/interface print detail without-paging",
        ],
        "vizinhanca": [
            "/ip neighbor print detail without-paging",
        ],
        "inventario": [
            "/system resource print",
            "/system routerboard print",
            "/system license print",
            "/system package print without-paging",
            "/system package update print",
        ],
    },
    "linux": {
        "nome": "Servidor Linux",
        "fabricante": "Linux",
        # A coleta busca o necessário para reconstruir o servidor: identidade,
        # rede completa (endereços, rotas de todas as tabelas, regras, firewall),
        # serviços habilitados, agendamentos, repositórios e usuários.
        "config": [
            "cat /etc/os-release",
            "cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null",
            "ip -br address",
            "ip -d address",
            "ip route show table all",
            "ip rule show",
            # O BIND abre um socket UDP por worker thread por interface (832
            # sockets em 14 endereços num servidor de 32 núcleos). A remoção
            # do descritor de arquivo colapsa as repetições sem perder
            # nenhuma combinação de endereço, porta e processo.
            "ss -tulpn 2>/dev/null | tr -s ' ' | sed 's/,fd=[0-9]*//g' | "
            "sort -u | head -n 150",
            # Firewall: as três implementações possíveis
            "{S}iptables-save 2>/dev/null | head -n 300",
            "{S}nft list ruleset 2>/dev/null | head -n 300",
            "{S}ufw status verbose 2>/dev/null",
            # Serviços: habilitados no boot é o que reconstrói o servidor;
            # 'running' mostra o estado atual
            "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend",
            "systemctl list-units --type=service --state=running --no-pager --no-legend",
            "systemctl list-timers --all --no-pager --no-legend",
            "systemctl --failed --no-pager",
            # Agendamentos
            "{S}ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null",
            "{S}crontab -l 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do "
            "c=$({S}crontab -u \"$u\" -l 2>/dev/null); [ -n \"$c\" ] && "
            "{ echo \"===== crontab de $u\"; echo \"$c\"; }; done",
            # Montagens e repositórios
            "cat /etc/fstab 2>/dev/null",
            "findmnt -t ext4,xfs,btrfs,nfs,nfs4,vfat --noheadings 2>/dev/null "
            "|| mount | grep -v -E 'cgroup|proc|sysfs|tmpfs'",
            "cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list "
            "/etc/apt/sources.list.d/*.sources 2>/dev/null | "
            "grep -v -E '^[[:space:]]*#|^[[:space:]]*$'",
            "cat /etc/yum.repos.d/*.repo 2>/dev/null | "
            "grep -v -E '^[[:space:]]*#|^[[:space:]]*$'",
            # Usuários e acesso
            "getent passwd | awk -F: '$3>=1000 || $3==0 {print $1\":\"$3\":\"$6\":\"$7}'",
            "getent group | grep -E 'sudo|wheel|adm|docker'",
            "{S}grep -v -E '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config "
            "2>/dev/null; {S}cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null",
            "{S}ls -la /etc/sudoers.d/ 2>/dev/null",
            # Parâmetros de rede alterados em relação ao padrão
            "{S}cat /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | "
            "grep -v -E '^[[:space:]]*#|^[[:space:]]*$'",
        ],
        "logs": ["journalctl -n 300 --no-pager"],
        "basico": [
            "hostname -f",
            "uname -a",
            "uptime",
            "free -h",
            "df -h",
            "ss -s",
            "ps aux --sort=-%cpu | head -n 25",
        ],
        "optica": [
            "ip -br link",
            # Contadores de erro/descarte por interface
            "ip -s -s link",
            # Velocidade, duplex e meio de cada interface física
            "for i in $(ls /sys/class/net | grep -v -E '^(lo|docker|veth|br-|virbr)'); "
            "do echo \"===== $i\"; {S}ethtool \"$i\" 2>&1 | "
            "grep -E 'Speed|Duplex|Port|Link detected|Auto-negotiation'; done",
            # EEPROM do módulo (SFF-8472): tipo, vendor/PN, wavelength,
            # alcance suportado, potências Rx/Tx e temperatura
            "for i in $(ls /sys/class/net | grep -v -E '^(lo|docker|veth|br-|virbr)'); "
            "do o=$({S}ethtool -m \"$i\" 2>/dev/null); [ -n \"$o\" ] && "
            "{ echo \"===== $i\"; echo \"$o\" | grep -E "
            "'Identifier|Connector|Vendor|Transceiver type|Laser wavelength|"
            "Length|Temperature|Voltage|power|Bias'; }; done",
            "for i in $(ls /sys/class/net | grep -v -E '^(lo|docker|veth|br-|virbr)'); "
            "do echo \"===== $i\"; {S}ethtool -S \"$i\" 2>/dev/null | "
            "grep -i -E 'err|drop|discard|crc|fail' | grep -v ': 0$'; done",
        ],
        "vizinhanca": [
            "lldpcli show neighbors detail",
            "lldpctl",
        ],
        "inventario": [
            "cat /etc/os-release",
            "uname -a",
            "lsmod 2>/dev/null | head -n 60",
            "{S}dmidecode -s system-manufacturer -s system-product-name "
            "2>/dev/null; {S}systemd-detect-virt 2>/dev/null",
            # Apenas estado, nome, versão e arquitetura: a coluna de descrição
            # responde por 40 dos 51 KB medidos e nada acrescenta ao
            # inventário.
            "(dpkg-query -W -f '${db:Status-Abbrev}\\t${Package}\\t"
            "${Version}\\t${Architecture}\\n' 2>/dev/null | "
            "grep '^ii' | cut -f2-) || (rpm -qa --qf '%{NAME}\\t"
            "%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' 2>/dev/null)",
            "{S}ls -1 /etc/apt/sources.list.d/ 2>/dev/null; "
            "apt list --upgradable 2>/dev/null | head -n 40",
            "(command -v docker >/dev/null && {S}docker ps -a --format "
            "'{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}') 2>/dev/null",
            "{S}find /opt /srv /root /home -maxdepth 3 "
            "\\( -name 'docker-compose.y*ml' -o -name 'compose.y*ml' \\) "
            "2>/dev/null | head -n 10",
            "ls -la /etc/*licen* /opt/*/licen* /opt/*/etc/*licen* 2>/dev/null",
        ],
    },
}

# ---------------------------------------------------------------------------
# Telnet
#
# Boa parte do parque de OLTs não oferece SSH: MA5800 e AN551x costumam sair
# de fábrica apenas com Telnet, e em muitos provedores continuam assim. A
# coleta suporta esses equipamentos, com duas ressalvas registradas no
# relatório: o protocolo trafega usuário e senha em texto claro, e a sessão
# inteira é legível por quem estiver no caminho.
#
# O Netmiko expõe um driver distinto por protocolo; a chave do perfil não
# muda, apenas o device_type usado na conexão.
DRIVER_TELNET = {
    "juniper_junos": "juniper_junos_telnet",
    "huawei": "huawei_telnet",
    "huawei_ce": "huawei_telnet",
    "huawei_smartax": "huawei_olt_telnet",
    "fiberhome": "generic_telnet",
    "cisco_nxos": "cisco_nxos_telnet",
    "cisco_ios": "cisco_ios_telnet",
    "cisco_xr": "cisco_xr_telnet",
    "mikrotik_routeros": "generic_telnet",
    "linux": "generic_telnet",
}
PORTA_TELNET_PADRAO = 23

# Identificação pelo prompt de login do Telnet. Sem banner SSH para ler, a
# própria solicitação de credencial distingue as plataformas: o SmartAX pede
# ">>User name:", o VRP de switch pede "Username:", e a maioria das OLTs
# FiberHome apresenta "Login:".
# O banner do equipamento antecede o pedido de credencial, portanto a âncora
# de início precisa valer por linha (re.M): sem isso, "Login:" ao final de um
# banner de várias linhas nunca é reconhecido e a identificação degenera em
# tentativas sucessivas de login.
PROMPT_TELNET = [
    (re.compile(r"(?i)>>\s*User\s*name"), ["huawei_smartax", "huawei"], "media"),
    (re.compile(r"(?i)MA5[68]\d\d|SmartAX"), ["huawei_smartax"], "media"),
    (re.compile(r"(?i)AN[56]\d{3}|FiberHome|GEPON|EPON"), ["fiberhome"], "media"),
    (re.compile(r"(?im)^\s*Username\s*:\s*$"), ["huawei", "cisco_ios"], "media"),
    (re.compile(r"(?im)^\s*Login\s*:\s*$"), ["fiberhome", "linux"], "media"),
    (re.compile(r"(?i)(Login|User\s*name)\s*:\s*$"), ["fiberhome", "huawei"],
     "media"),
]

# Equipamentos que exigem uma tecla após a autenticação, antes de liberar a
# CLI. A OLT FiberHome apresenta "--Press any key to continue Ctrl+c to
# stop--": sem enviar a tecla, find_prompt() captura esse texto como se fosse
# o prompt e o primeiro comando derruba a sessão.
PADRAO_TECLA = re.compile(
    r"(?i)press\s+any\s+key|pressione\s+qualquer|hit\s+enter|"
    r"--\s*more\s*--|any\s+key\s+to\s+continue"
)

# Pedidos de credencial e recusa de login, avaliados sobre o final do texto
# recebido. A âncora no fim evita confundir "Last login: ..." de um banner
# com um pedido de usuário.
PADRAO_PEDE_USUARIO = re.compile(r"(?i)(?:^|\n)[^\n]*(?:login|user\s*name)\s*:\s*$")
PADRAO_PEDE_SENHA = re.compile(r"(?i)(?:^|\n)[^\n]*pass\s*word\s*:\s*$")
PADRAO_LOGIN_RECUSADO = re.compile(
    r"(?i)login incorrect|authentication fail|access denied|"
    r"authentication is rejected|invalid (?:user|password|login)|"
    r"bad password|login failed|user.*locked"
)
PADRAO_FIM_PROMPT = re.compile(r"[#>$\]]\s*$")


class TelnetComLogin(TerminalServerTelnet):
    """Telnet genérico com autenticação.

    O driver 'generic_telnet' do Netmiko é o de servidor de terminal: por
    projeto, ele não envia usuário nem senha. Foi essa a causa da falha
    registrada na OLT FiberHome: o pedido de login ficava sem resposta, os
    comandos preparatórios eram digitados no campo de usuário e o equipamento
    encerrava a sessão.

    Esta classe faz o login com duas proteções contra bloqueio de conta, comum
    em OLT: as credenciais são enviadas uma única vez — um novo pedido de
    usuário ou senha depois disso é tratado como recusa, sem nova tentativa — e
    o aviso "--Press any key--" exibido após o login é respondido aqui mesmo.
    A preparação de sessão não altera nada no equipamento: apenas registra o
    prompt para que send_command reconheça o fim de cada saída."""

    def telnet_login(self, *args, **kwargs) -> str:
        recebido, janela = "", ""
        enviou_usuario = enviou_senha = False
        teclas = 0
        cutucou = False
        inicio = time.time()
        limite_apos_senha = None
        while time.time() - inicio < 45:
            dados = self.read_channel()
            if dados:
                recebido += dados
                janela = (janela + PADRAO_ANSI.sub("", dados))[-400:]
            trecho = janela.rstrip("\x00")

            if (enviou_usuario or enviou_senha) and \
                    PADRAO_LOGIN_RECUSADO.search(trecho):
                raise NetmikoAuthenticationException(
                    f"login recusado: {self.host}")
            if PADRAO_PEDE_USUARIO.search(trecho):
                if enviou_senha or enviou_usuario:
                    raise NetmikoAuthenticationException(
                        f"credenciais recusadas: {self.host}")
                self.write_channel(self.username + "\r")
                enviou_usuario, janela = True, ""
                time.sleep(1)
                continue
            if PADRAO_PEDE_SENHA.search(trecho):
                if enviou_senha:
                    raise NetmikoAuthenticationException(
                        f"credenciais recusadas: {self.host}")
                self.write_channel(self.password + "\r")
                enviou_senha, janela = True, ""
                limite_apos_senha = time.time() + 20
                time.sleep(1.5)
                continue
            if enviou_senha:
                if PADRAO_TECLA.search(trecho) and teclas < 3:
                    self.write_channel("\r")
                    teclas, janela = teclas + 1, ""
                    time.sleep(1.5)
                    continue
                if PADRAO_FIM_PROMPT.search(trecho):
                    return recebido
                if time.time() > limite_apos_senha:
                    # Sem recusa explícita: devolve e deixa o prompt ser
                    # determinado por find_prompt().
                    return recebido
            elif not dados and not cutucou and time.time() - inicio > 4:
                # Alguns equipamentos só exibem o pedido de login após
                # receber uma tecla.
                self.write_channel("\r")
                cutucou = True
            time.sleep(0.3)
        raise NetmikoTimeoutException(
            f"pedido de login não reconhecido em {self.host}: "
            f"{' '.join(janela.split())[-80:]!r}")

    def session_preparation(self) -> None:
        try:
            prompt = self.find_prompt().strip()
            if prompt and not PADRAO_TECLA.search(prompt):
                self.base_prompt = prompt[:-1] if PADRAO_FIM_PROMPT.search(
                    prompt) else prompt
        except Exception:
            pass


def abrir_conexao(**dispositivo):
    """ConnectHandler, com o login Telnet genérico corrigido."""
    if dispositivo.get("device_type") == "generic_telnet":
        return TelnetComLogin(**dispositivo)
    return ConnectHandler(**dispositivo)


def ler_prompt_telnet(ip: str, porta: int, tempo: int = 6):
    """Lê o texto inicial de uma sessão Telnet, sem autenticar.

    Descarta a negociação de opções (IAC, RFC 854) e devolve apenas o texto
    legível — normalmente o banner do equipamento e o pedido de usuário."""
    IAC, SB, SE = 0xFF, 0xFA, 0xF0
    WILL, WONT, DO, DONT = 0xFB, 0xFC, 0xFD, 0xFE
    limpo = bytearray()
    try:
        with socket.create_connection((ip, porta), timeout=tempo) as s:
            s.settimeout(tempo)
            pendente = b""
            fim = time.time() + tempo
            while len(limpo) < 2048 and time.time() < fim:
                try:
                    pedaco = s.recv(512)
                except socket.timeout:
                    break
                if not pedaco:
                    break
                dados, pendente = pendente + pedaco, b""
                i = 0
                while i < len(dados):
                    b = dados[i]
                    if b != IAC:
                        limpo.append(b)
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
                        # Recusa toda opção. Vários equipamentos só exibem o
                        # pedido de login depois que o cliente responde à
                        # negociação; sem resposta, a leitura não traria
                        # texto algum.
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

    texto = limpo.decode("utf-8", "replace")
    texto = PADRAO_ANSI.sub("", texto).replace("\x00", "")
    # Conectou mas não recebeu texto: devolve vazio (e não None, que
    # significa porta sem resposta).
    return texto.strip()


def plataforma_por_prompt_telnet(texto: str):
    """Retorna (candidatos, confianca) a partir do prompt de login."""
    if not texto:
        return [], None
    for padrao, candidatos, confianca in PROMPT_TELNET:
        if padrao.search(texto):
            return list(candidatos), confianca
    return [], None


ORDEM_MENU = list(PERFIS.keys())

# ---------------------------------------------------------------------------
# Módulos de aplicação detectados em hosts Linux.
# O marcador {S} é substituído por 'sudo -n ' quando o usuário possui sudo
# não interativo, ou por string vazia caso contrário.
# ---------------------------------------------------------------------------
# Helpers SQL usados pelos módulos Zabbix e Grafana.
# São definidos uma única vez por sessão SSH (a sessão do Netmiko é
# persistente) e apenas executam SELECT — nenhuma escrita é emitida.
# As credenciais são lidas em tempo de execução do arquivo de configuração
# local e ficam apenas em variável de ambiente do processo cliente, de modo
# que não aparecem na linha de comando (ps) nem no relatório gerado.
DEF_Q_WANGUARD = (
    # Wanguard 9 guarda host e senha do banco em arquivos separados, cada um
    # contendo apenas o valor. O usuário e o banco chamam-se "andrisoft" por
    # padrão; o nome real é confirmado com SHOW DATABASES.
    #
    # W()  executa uma consulta.
    # WT() despeja uma tabela a partir do DESCRIBE, aplicando três
    #      transformações indispensáveis para que a saída seja analisável:
    #        - colunas de segredo são excluídas na origem (a saída do mysql
    #          é tabular, e um valor sob a coluna "password" não seria
    #          detectado pelo sanitizador, que procura par chave=valor);
    #        - colunas binárias recebem INET6_NTOA, pois o Wanguard grava
    #          endereços como VARBINARY e o despejo cru produz bytes nulos
    #          ilegíveis em vez do IP;
    #        - marcas de tempo Unix recebem FROM_UNIXTIME.
    #      O terceiro parâmetro, opcional, é uma regex de colunas a manter.
    r"WH=$({S}cat /opt/andrisoft/etc/dbhost.conf 2>/dev/null | tr -d "
    r"' \r\n'); "
    r"WP=$({S}cat /opt/andrisoft/etc/dbpass.conf 2>/dev/null | tr -d "
    r"' \r\n'); "
    r"WU=andrisoft; "
    r'WD=$(MYSQL_PWD="$WP" mysql -h "${WH:-localhost}" -u "$WU" -N -B '
    r"-e 'SHOW DATABASES' 2>/dev/null | grep -i -m1 -E 'andrisoft|wanguard'); "
    r'W(){ if [ -z "$WP" ]; then echo '
    r"'(credenciais do banco inacessiveis - requer sudo)'; "
    r"elif ! command -v mysql >/dev/null 2>&1; then echo "
    r"'(cliente mysql ausente no servidor)'; "
    r'elif [ -z "$WD" ]; then echo '
    r"'(banco do Wanguard nao localizado)'; "
    r'else MYSQL_PWD="$WP" mysql -h "${WH:-localhost}" -u "$WU" -D "$WD" '
    r'-B -e "$1" 2>&1; fi; }; '
    r'WT(){ C=$(W "DESCRIBE \`$1\`" 2>/dev/null | tail -n +2 | '
    'awk -v F="${3:-}" \'{ n=tolower($1); t=tolower($2) } '
    r"n ~ /pass|secret|_key$|^key$|token|community|credential|hash|salt|^license$|^prev_license$/ { next } "
    r'F != "" && n !~ F { next } '
    r't ~ /binary|blob/ { printf "INET6_NTOA(`%s`) AS `%s`,", $1, $1; next } '
    r"n ~ /^(first|last|sensor_last|update_time|start_time|last_run|expire|expires)$/ && t ~ /int/ "
    r'{ printf "FROM_UNIXTIME(`%s`) AS `%s`,", $1, $1; next } '
    '{ printf "`%s`,", $1 }\' | sed \'s/,$//\'); '
    r'[ -z "$C" ] && { echo "(tabela $1 sem colunas acessiveis)"; return; }; '
    r'W "SELECT $C FROM \`$1\` ${2:-LIMIT 50}"; }; '
    r'echo "banco: ${WD:-nao identificado} em ${WH:-localhost}"'
)

DEF_Q_ZABBIX = (
    "C=$(ls /etc/zabbix/zabbix_server.conf /usr/local/etc/zabbix_server.conf "
    "2>/dev/null | head -n1); CONF=$({S}cat \"$C\" 2>/dev/null); "
    "DBN=$(echo \"$CONF\" | awk -F= '/^DBName=/{print $2}' | tr -d ' \\r'); "
    "DBU=$(echo \"$CONF\" | awk -F= '/^DBUser=/{print $2}' | tr -d ' \\r'); "
    "DBP=$(echo \"$CONF\" | awk -F= '/^DBPassword=/{print $2}' | tr -d ' \\r'); "
    "DBH=$(echo \"$CONF\" | awk -F= '/^DBHost=/{print $2}' | tr -d ' \\r'); "
    "Q(){ if [ -z \"$DBN\" ]; then echo '(nao foi possivel ler as credenciais "
    "em zabbix_server.conf - requer sudo)'; "
    "elif command -v mysql >/dev/null 2>&1; then MYSQL_PWD=\"$DBP\" mysql "
    "-h \"${DBH:-localhost}\" -u \"$DBU\" -D \"$DBN\" -B -e \"$1\" 2>&1; "
    "elif command -v psql >/dev/null 2>&1; then PGPASSWORD=\"$DBP\" psql "
    "-h \"${DBH:-localhost}\" -U \"$DBU\" -d \"$DBN\" -A -F'\\t' -c \"$1\" 2>&1; "
    "else echo '(cliente mysql/psql ausente no servidor)'; fi; }; "
    "echo \"backend: ${DBN:-nao identificado}\""
)

DEF_Q_GRAFANA = (
    "GI=$(ls /etc/grafana/grafana.ini 2>/dev/null | head -n1); "
    "SEC=$({S}sed -n '/^\\[database\\]/,/^\\[/p' \"$GI\" 2>/dev/null); "
    "GT=$(echo \"$SEC\" | awk -F= '/^[ \\t]*type[ \\t]*=/{gsub(/[ \\t]/,\"\",$2);"
    "print $2;exit}'); "
    "GP=$(echo \"$SEC\" | awk -F= '/^[ \\t]*path[ \\t]*=/{gsub(/[ \\t]/,\"\",$2);"
    "print $2;exit}'); GP=${GP:-/var/lib/grafana/grafana.db}; "
    "case \"$GP\" in /*) ;; *) GP=/var/lib/grafana/$GP;; esac; "
    "GH=$(echo \"$SEC\" | awk -F= '/^[ \\t]*host[ \\t]*=/{gsub(/[ \\t]/,\"\",$2);"
    "print $2;exit}'); "
    "GN=$(echo \"$SEC\" | awk -F= '/^[ \\t]*name[ \\t]*=/{gsub(/[ \\t]/,\"\",$2);"
    "print $2;exit}'); "
    "GU=$(echo \"$SEC\" | awk -F= '/^[ \\t]*user[ \\t]*=/{gsub(/[ \\t]/,\"\",$2);"
    "print $2;exit}'); "
    "GW=$(echo \"$SEC\" | awk -F= '/^[ \\t]*password[ \\t]*=/{sub(/^[^=]*=/,\"\");"
    "gsub(/[ \\t\"\\x27]/,\"\");print;exit}'); "
    "G(){ case \"${GT:-sqlite3}\" in "
    "mysql) MYSQL_PWD=\"$GW\" mysql -h \"${GH%%:*}\" -u \"$GU\" "
    "-D \"${GN:-grafana}\" -B -e \"$1\" 2>&1;; "
    "postgres) PGPASSWORD=\"$GW\" psql -h \"${GH%%:*}\" -U \"$GU\" "
    "-d \"${GN:-grafana}\" -A -F'\\t' -c \"$1\" 2>&1;; "
    "*) if command -v sqlite3 >/dev/null 2>&1; then "
    "{S}sqlite3 -readonly -separator '|' \"$GP\" \"$1\" 2>&1; "
    "else echo '(binario sqlite3 ausente - instale sqlite3 para ler o "
    "banco do Grafana)'; fi;; esac; }; "
    "echo \"backend: ${GT:-sqlite3} / ${GP}\""
)

APPS_LINUX = {
    "wanguard": {
        "nome": "WANGuard (detecção e mitigação DDoS)",
        # A detecção não depende de um nome de arquivo específico: o layout
        # muda entre versões (wanguard.conf, WANsupervisor.conf, etc.).
        "deteccao": "{ test -d /opt/andrisoft || test -f /etc/wanguard.conf || "
                    "ls /etc/wanguard* >/dev/null 2>&1; } && echo PRESENTE",
        "config": [
            # Inventário do diretório antes de ler: mostra o que existe de fato
            "{S}ls -la /opt/andrisoft/ /opt/andrisoft/etc/ /etc/wanguard* "
            "2>/dev/null",
            # Leitura por glob, pulando arquivos que contêm apenas segredo
            # (dbpass.conf e similares) e limitando o volume por arquivo:
            # a partir do Wanguard 9 o etc/ traz influxdb.conf com centenas
            # de linhas de comentário que nada acrescentam ao diagnóstico.
            "for f in /opt/andrisoft/etc/*.conf /opt/andrisoft/etc/*.cfg "
            "/etc/wanguard*.conf /etc/wanguard.conf; do [ -f \"$f\" ] || continue; "
            "case \"$f\" in *pass*|*secret*|*key*|*cred*) "
            "echo \"===== $f (omitido: arquivo de credencial)\"; continue;; esac; "
            "echo \"===== $f\"; {S}grep -v -E '^[[:space:]]*#|^[[:space:]]*$' "
            "\"$f\" | head -n 120; done",
            # Unidades descobertas por padrão de nome, não por lista fixa
            "systemctl list-units --no-pager --all --plain 2>/dev/null | "
            "grep -i -E 'wanguard|andrisoft|wansupervisor|wanflow|wanfilter'",
            # Console web: o diretório é 'webroot' a partir do Wanguard 9
            "{S}ls -la /opt/andrisoft/webroot/ /opt/andrisoft/web/ "
            "/opt/andrisoft/api/ 2>/dev/null | head -n 30",
        ],
        "logs": [
            # Só executa journalctl se houver unit correspondente; sem a
            # guarda, a expansão vazia despejaria o journal inteiro do
            # sistema rotulado como log do WANGuard.
            "U=$(systemctl list-units --no-pager --plain --no-legend 2>/dev/null "
            "| awk '/wanguard|andrisoft|WANsupervisor|WANflow|WANfilter/"
            "{printf \" -u \"$1}'); "
            "if [ -n \"$U\" ]; then {S}journalctl $U -n 300 --no-pager 2>&1; "
            "else echo '(nenhuma unit systemd do WANGuard encontrada)'; fi",
            # Filtra pelo processo do WANGuard: procurar apenas por palavras
            # como 'mitigation' traz mitigações de CPU do kernel (Spectre,
            # MMIO) e nada de DDoS.
            "{S}grep -h -i -E '(wanguard|andrisoft|WAN(supervisor|flow|filter|"
            "sensor))' /var/log/syslog /var/log/messages 2>/dev/null | "
            "grep -i -E 'anomal|attack|mitigat|blackhole|flowspec|threshold|"
            "decision' | tail -n 200",
            # Caminho de log descoberto, não presumido
            "{S}find /opt/andrisoft /var/log -maxdepth 3 "
            "\\( -iname '*wanguard*' -o -iname '*andrisoft*' -o -iname 'WAN*' \\) "
            "-name '*.log' 2>/dev/null | head -n 20",
        ],
        "basico": [
            # Estado dos serviços realmente presentes, descobertos acima
            "U=$(systemctl list-units --no-pager --plain --no-legend 2>/dev/null "
            "| awk '/wanguard|andrisoft|WANsupervisor|WANflow|WANfilter/"
            "{printf \" \"$1}'); "
            "if [ -n \"$U\" ]; then systemctl status --no-pager $U 2>&1 | "
            "head -n 80; else echo '(nenhuma unit systemd do WANGuard)'; fi",
            "{S}ps -eo pid,etime,pcpu,pmem,comm,args --sort=-pcpu 2>/dev/null | "
            "grep -i -E 'wanguard|andrisoft|WANsupervisor|WANflow|WANfilter|"
            "WANsensor' | grep -v grep",
            "ip -br address",
            # Mitigação ativa: regras de filtro em uso
            "{S}iptables -L -n -v 2>/dev/null | head -n 120",
            "{S}nft list ruleset 2>/dev/null | head -n 120",
            "{S}ipset list -t 2>/dev/null | head -n 80",
            # Anúncios de blackhole/flowspec normalmente saem por BGP
            "for b in birdc birdcl vtysh exabgpcli; do command -v $b "
            ">/dev/null 2>&1 && { echo \"===== $b\"; case $b in "
            "birdc|birdcl) {S}$b show protocols 2>&1 | head -n 30;; "
            "vtysh) {S}$b -c 'show bgp summary' 2>&1 | head -n 30; "
            "{S}$b -c 'show run' 2>&1 | head -n 60;; "
            "exabgpcli) {S}$b show neighbor summary 2>&1 | head -n 30;; "
            "esac; }; done",
            # Os processos chamam-se WANflow/WANsupervisor: filtrar por
            # 'wanguard' não os encontra. Portas de flow são configuráveis.
            "{S}ss -tulpn 2>/dev/null | grep -i -E "
            "'WAN[a-z]+|andrisoft|:179|:161|:2055|:4739|:6343|:9996'",
        ],
        "inventario": [
            # Binários apenas listados; a execução com -v usa timeout para
            # não travar a coleta caso o binário seja um daemon.
            "{S}ls -la /opt/andrisoft/bin/ 2>/dev/null | head -n 40",
            # Todos os binários reportam a mesma versão: uma amostra basta.
            "for p in /opt/andrisoft/bin/WANsupervisor "
            "/opt/andrisoft/bin/WANflow /opt/andrisoft/bin/WANfilter "
            "/opt/andrisoft/bin/WANsensor; do [ -x \"$p\" ] && "
            "{ echo \"===== $(basename \"$p\")\"; "
            "timeout 5 \"$p\" -v 2>&1 | head -n 3; }; done",
            "for f in /opt/andrisoft/etc/license* /opt/andrisoft/etc/*.lic "
            "/etc/wanguard*licen*; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}head -n 25 \"$f\"; }; done",
            "(dpkg -l 2>/dev/null | grep -i -E 'wanguard|andrisoft') "
            "|| (rpm -qa 2>/dev/null | grep -i -E 'wanguard|andrisoft')",
        ],
        # A partir do Wanguard 9 a configuração operacional (sensores,
        # grupos de IP, filtros, respostas, anomalias e licença) fica no
        # MariaDB, não em arquivo: o etc/ contém apenas Apache, InfluxDB e
        # as credenciais do banco. Sem esta seção, a coleta não registra
        # nada do que o WANGuard realmente monitora.
        # A configuração operacional do Wanguard 9 fica integralmente no
        # MariaDB: o diretório etc/ contém apenas Apache, InfluxDB e as
        # credenciais do banco. As tabelas abaixo foram confirmadas em uma
        # instalação 9.0-3 (143 tabelas de configuração e 2.424 de
        # accounting diário). São deliberadamente omitidas:
        #   - tabelas de autenticação de operador (company_staff, httpauth,
        #     ldapauth, radiusauth, samlauth), por conterem credenciais;
        #   - séries temporais e dados de fluxo (top_bin_*, top_live_*,
        #     sensorstats, events, as_numbers, ipacct*, allstats), que somam
        #     dezenas de gigabytes e alimentam gráficos;
        #   - tabelas de integração com credencial (ldap, email, telco), que
        #     guardam usuário de bind LDAP, login SMTP e usuário RADIUS;
        #   - referência estática (country_code, ip_protocols, protocols) e
        #     estado de interface (widget, dashboard, bookmark, graphs), que
        #     são ruído para análise de configuração.
        "extra": {
            "titulo": "Configuração operacional no banco (componentes, zonas, "
                      "detecção, respostas, BGP/Flowspec e anomalias)",
            "comandos": [
                DEF_Q_WANGUARD,
                # ----- Identificação da instalação -----
                "echo '===== version'; WT version; "
                "echo '===== maintenance (retencao por tipo de dado)'; "
                "WT maintenance; echo '===== defaults'; WT defaults",
                # A coluna 'license' guarda a chave do contrato e é excluída
                # pelo WT; aqui ficam apenas os metadados de validade.
                "echo '===== license (metadados)'; "
                "W \"SELECT id, filename, FROM_UNIXTIME(update_time) AS "
                "update_time, LENGTH(license) AS tamanho_chave FROM license\"",
                # ----- Componentes configurados -----
                "for t in wanserver wansensor wansensor_virtual wanflow "
                "wansniff wansnmp wanfilter wanconsole wanwatcher wanbgp; do "
                "echo \"===== $t\"; WT $t \"LIMIT 100\"; done",
                # Interfaces monitoradas: tipo (Upstream/Peering), velocidade
                # contratada, fronteira e provedor de cada enlace
                "for t in wanserver_interfaces wanflow_interfaces "
                "wansnmp_interfaces wansniff_interfaces; do "
                "echo \"===== $t\"; WT $t \"LIMIT 200\"; done",
                # ----- Zonas de IP e prefixos monitorados -----
                # Sem INET6_NTOA estas tabelas saem como bytes nulos: o
                # endereço é gravado em VARBINARY.
                "echo '===== ipaddr (zonas e prefixos)'; "
                "WT ipaddr \"ORDER BY ipzone, id LIMIT 1000\"",
                "for t in ipaddrdesc ipaddrrules ipzone ipgroups; do "
                "echo \"===== $t\"; WT $t \"LIMIT 500\"; done",
                # ----- Detecção: perfis, limiares e gatilhos -----
                "for t in anomalies templates templatesrules; do "
                "echo \"===== $t\"; WT $t \"LIMIT 300\"; done",
                "for t in profiling_templates profiling_templatesrules "
                "profiling_ipaddrrules profiling_profiles baseline_profiles; "
                "do echo \"===== $t\"; WT $t \"LIMIT 300\"; done",
                # ----- Respostas automáticas -----
                # Cada ação é uma linha em 'actions' com as etapas
                # distribuídas nas tabelas actions_*; todas vazias significa
                # detecção sem mitigação automática.
                "echo '===== actions'; WT actions \"LIMIT 200\"; "
                "for t in actions_bgp actions_filters actions_reconfigure "
                "actions_snmp actions_syslog actions_notify actions_emails "
                "actions_webhook actions_reports actions_scripts "
                "actions_dumps; do echo \"===== $t\"; WT $t \"LIMIT 200\"; "
                "done",
                # ----- BGP, blackhole e Flowspec -----
                # A configuração de Flowspec não tem tabela própria: vive nas
                # colunas exa_flowspec, max_flowspec, flowspec_counters,
                # exa_nexthop, exa_localpref, exa_rd, exa_direction e srtbh
                # da tabela 'router'.
                "echo '===== router (BGP / blackhole / Flowspec)'; "
                "WT router \"LIMIT 100\"",
                "for t in quagga scrubber_tunnels scrubber_tunnel_settings "
                "bgp_communities flowspec_rules; do echo \"===== $t\"; "
                "WT $t \"LIMIT 200\"; done",
                # ----- Filtragem, listas e exceções -----
                "for t in whitelists exceptions blacklist_settings "
                "blacklist_ds fr_settings fr_list fw_custom_fr fw_settings; "
                "do echo \"===== $t\"; WT $t \"LIMIT 300\"; done",
                # ----- Mitigação em vigor neste instante -----
                "echo '===== active_fw_rules (mitigacao ativa agora)'; "
                "WT active_fw_rules \"LIMIT 500\"",
                "echo '===== squeue / squeue_archive (fila de filtros)'; "
                "WT squeue \"LIMIT 100\"; "
                "WT squeue_archive \"ORDER BY 1 DESC LIMIT 100\"",
                # ----- Últimas anomalias detectadas -----
                # A tabela 'attacks' chega a milhões de registros; o recorte
                # por colunas mantém o volume compatível com leitura por
                # modelo de linguagem sem perder o que caracteriza o evento.
                "echo '===== attacks (1000 mais recentes)'; "
                "WT attacks \"ORDER BY attack_id DESC LIMIT 1000\" "
                "\"^(attack_id|attack_type|status|ip|mask|first|last|"
                "rule_|value$|computed_value|latest_value|sum_value|"
                "anomaly_|total_|sensor|ipgroup|prefix|comment|action|"
                "duration|packets|bytes|direction|protocol|port)\"",
                # Restrito aos últimos 90 dias: sem a janela, o agrupamento
                # varre os 2,6 milhões de registros da tabela e leva 12 s.
                "echo '===== attacks: distribuicao por tipo (90 dias)'; "
                "W \"SELECT attack_type, COUNT(*) AS ocorrencias, "
                "MAX(FROM_UNIXTIME(last)) AS mais_recente FROM attacks "
                "WHERE first > UNIX_TIMESTAMP() - 7776000 "
                "GROUP BY attack_type ORDER BY ocorrencias DESC LIMIT 40\"",
                "W \"SELECT DATE(FROM_UNIXTIME(first)) AS dia, "
                "COUNT(*) AS anomalias FROM attacks WHERE first > "
                "UNIX_TIMESTAMP() - 2592000 GROUP BY dia ORDER BY dia DESC\"",
                "echo '===== attacks_logs (100 mais recentes)'; "
                "WT attacks_logs \"ORDER BY 1 DESC LIMIT 100\"",
                # ----- Agendamentos e saúde -----
                "for t in schedule_reports wanhealth_check chronos; "
                "do echo \"===== $t\"; WT $t \"LIMIT 200\"; done",
                # ----- Descoberta: tabelas de configuração não previstas -----
                # Garante que uma versão diferente do Wanguard não deixe
                # configuração de fora por não constar das listas acima.
                "echo '===== tabelas de configuracao ainda nao despejadas'; "
                "W \"SELECT table_name, table_rows FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name NOT LIKE 'acct%' AND table_name NOT LIKE "
                "'top\\_%' AND table_name NOT LIKE '%\\_archive' AND "
                "table_name NOT REGEXP "
                "'^(attacks|events|sensorstats|as_numbers|squeue|ipacct|"
                "ports|protocols|tops_|company_staff|httpauth|ldapauth|"
                "radiusauth|samlauth|ldap|email|telco|country_code|"
                "ip_protocols|graphs|allstats|bookmark|widget|dashboard)' "
                "AND table_rows < 5000 "
                "ORDER BY table_name\"",
                "for t in $(W \"SELECT table_name FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name NOT LIKE 'acct%' AND table_name NOT LIKE "
                "'top\\_%' AND table_name NOT LIKE '%\\_archive' AND "
                "table_name NOT REGEXP "
                "'^(attacks|events|sensorstats|as_numbers|squeue|ipacct|"
                "ports|protocols|tops_|company_staff|httpauth|ldapauth|"
                "radiusauth|samlauth|ldap|email|telco|country_code|"
                "ip_protocols|graphs|allstats|bookmark|baseline|"
                "wan|ipaddr|action|profiling|template|"
                "router|quagga|scrubber|whitelist|exception|blacklist|fr_|"
                "fw_|active_fw|anomalies|license|version|maintenance|"
                "defaults|schedule|widget|dashboard|ipzone|ipgroups)' "
                "AND table_rows > 0 AND table_rows < 2000 "
                "ORDER BY table_name\" 2>/dev/null | tail -n +2); do "
                "echo \"===== $t\"; WT $t \"LIMIT 100\"; done",
                # ----- Dimensionamento, sem despejar séries temporais -----
                "echo '===== volume das tabelas (nao despejadas)'; "
                "W \"SELECT table_name, table_rows, "
                "ROUND(data_length/1024/1024) AS mb FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name NOT LIKE 'acct%' ORDER BY data_length DESC "
                "LIMIT 30\"",
                "W \"SELECT COUNT(*) AS tabelas_de_accounting_diario FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name LIKE 'acct%'\"",
            ],
        },
    },
    "zabbix": {
        "nome": "Zabbix (servidor/proxy de monitoramento)",
        "deteccao": "{ test -f /etc/zabbix/zabbix_server.conf || "
                    "test -f /etc/zabbix/zabbix_proxy.conf || "
                    "command -v zabbix_server >/dev/null 2>&1; } && echo PRESENTE",
        "config": [
            # Configuração sem comentários: o zabbix_server.conf tem
            # centenas de linhas comentadas que só ruído acrescentam
            "for f in /etc/zabbix/zabbix_server.conf /etc/zabbix/zabbix_proxy.conf "
            "/etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agent2.conf; do "
            "[ -f \"$f\" ] && { echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\"; }; done",
            "{S}ls -la /etc/zabbix/ /etc/zabbix/zabbix_server.conf.d/ "
            "/etc/zabbix/web/ 2>/dev/null",
            "for f in /etc/zabbix/zabbix_server.conf.d/*.conf; do "
            "[ -f \"$f\" ] && { echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\"; }; done",
            "for f in /etc/zabbix/web/zabbix.conf.php /etc/zabbix/nginx.conf "
            "/etc/zabbix/apache.conf; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}ls -la /usr/lib/zabbix/externalscripts/ /usr/lib/zabbix/alertscripts/ "
            "2>/dev/null",
        ],
        "logs": [
            "U=$(systemctl list-units --no-pager --plain --no-legend 2>/dev/null "
            "| awk '/zabbix/{printf \" -u \"$1}'); if [ -n \"$U\" ]; then "
            "{S}journalctl $U -n 300 --no-pager 2>&1; else "
            "echo '(nenhuma unit systemd do Zabbix encontrada)'; fi",
            "for f in /var/log/zabbix/zabbix_server.log "
            "/var/log/zabbix/zabbix_proxy.log; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}tail -n 200 \"$f\"; }; done",
            "{S}grep -h -i -E 'error|cannot|failed|slow query' "
            "/var/log/zabbix/zabbix_server.log 2>/dev/null | tail -n 80",
        ],
        "basico": [
            "systemctl status --no-pager zabbix-server zabbix-proxy zabbix-agent "
            "zabbix-agent2 2>&1 | head -n 60",
            "{S}ss -tulpn 2>/dev/null | tr -s ' ' | sed 's/,fd=[0-9]*//g' | "
            "grep -E ':10050|:10051|:80|:443' | sort -u",
            "{S}ps -eo pid,etime,pcpu,pmem,args --sort=-pcpu 2>/dev/null | "
            "grep -i zabbix | grep -v grep | head -n 20",
            "{S}du -sh /var/lib/mysql/zabbix /var/lib/pgsql/data 2>/dev/null",
        ],
        "inventario": [
            "for b in zabbix_server zabbix_proxy zabbix_agentd zabbix_agent2 "
            "zabbix_get zabbix_sender; do command -v $b >/dev/null 2>&1 && "
            "{ echo \"===== $b\"; timeout 5 $b -V 2>&1 | head -n 3; }; done",
            "(dpkg -l 2>/dev/null | grep -i zabbix) || "
            "(rpm -qa 2>/dev/null | grep -i zabbix)",
            "{S}ls -la /usr/share/zabbix/ 2>/dev/null | head -n 15",
        ],
        # Conteúdo monitorado: vive no banco, não em arquivo de configuração
        "extra": {
            "titulo": "Inventário monitorado (hosts, grupos, templates, "
                      "problemas, ações e dashboards)",
            "comandos": [
                DEF_Q_ZABBIX,
                "Q \"SELECT 'hosts monitorados', COUNT(*) FROM hosts WHERE status=0 "
                "UNION ALL SELECT 'hosts desabilitados', COUNT(*) FROM hosts WHERE status=1 "
                "UNION ALL SELECT 'templates', COUNT(*) FROM hosts WHERE status=3 "
                "UNION ALL SELECT 'itens ativos', COUNT(*) FROM items WHERE status=0 "
                "UNION ALL SELECT 'triggers ativas', COUNT(*) FROM triggers WHERE status=0\"",
                "Q \"SELECT h.host, h.name, CASE h.status WHEN 0 THEN 'monitorado' "
                "WHEN 1 THEN 'desabilitado' END AS estado, i.ip, i.dns, i.port "
                "FROM hosts h LEFT JOIN interface i ON i.hostid=h.hostid AND i.main=1 "
                "WHERE h.status IN (0,1) AND h.flags IN (0,4) ORDER BY h.name\"",
                "Q \"SELECT g.name AS grupo, COUNT(h.hostid) AS hosts FROM hstgrp g "
                "LEFT JOIN hosts_groups hg ON hg.groupid=g.groupid "
                "LEFT JOIN hosts h ON h.hostid=hg.hostid AND h.status IN (0,1) "
                "GROUP BY g.name ORDER BY g.name\"",
                "Q \"SELECT host AS template FROM hosts WHERE status=3 ORDER BY host\"",
                "Q \"SELECT p.clock, CASE p.severity WHEN 0 THEN 'nao classificado' "
                "WHEN 1 THEN 'informacao' WHEN 2 THEN 'atencao' WHEN 3 THEN 'media' "
                "WHEN 4 THEN 'alta' WHEN 5 THEN 'desastre' END AS severidade, "
                "h.host, p.name FROM problem p JOIN triggers t ON t.triggerid=p.objectid "
                "JOIN functions f ON f.triggerid=t.triggerid JOIN items i ON i.itemid=f.itemid "
                "JOIN hosts h ON h.hostid=i.hostid WHERE p.source=0 AND p.object=0 "
                "GROUP BY p.eventid, p.clock, p.severity, h.host, p.name "
                "ORDER BY p.severity DESC, p.clock DESC LIMIT 200\"",
                "Q \"SELECT name AS acao, CASE status WHEN 0 THEN 'ativa' "
                "ELSE 'desativada' END AS estado FROM actions ORDER BY name\"",
                "Q \"SELECT name AS midia, type, CASE status WHEN 0 THEN 'ativo' "
                "ELSE 'desativado' END AS estado FROM media_type ORDER BY name\"",
                "Q \"SELECT name AS dashboard FROM dashboard ORDER BY name\"",
                "Q \"SELECT host AS proxy FROM hosts WHERE status IN (5,6) ORDER BY host\"",
            ],
        },
    },
    "grafana": {
        "nome": "Grafana (visualização e alertas)",
        "deteccao": "{ test -f /etc/grafana/grafana.ini || "
                    "command -v grafana-server >/dev/null 2>&1 || "
                    "command -v grafana >/dev/null 2>&1; } && echo PRESENTE",
        "config": [
            "[ -f /etc/grafana/grafana.ini ] && { echo '===== /etc/grafana/grafana.ini'; "
            "{S}grep -v -E '^[[:space:]]*[;#]|^[[:space:]]*$' "
            "/etc/grafana/grafana.ini; }",
            "{S}ls -la /etc/grafana/ /etc/grafana/provisioning/ "
            "/etc/grafana/provisioning/datasources/ "
            "/etc/grafana/provisioning/dashboards/ "
            "/etc/grafana/provisioning/alerting/ 2>/dev/null",
            # Provisionamento declarativo: datasources, dashboards e alertas
            "for f in /etc/grafana/provisioning/*/*.y*ml; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}ls -la /var/lib/grafana/dashboards/ 2>/dev/null | head -n 40",
        ],
        "logs": [
            "U=$(systemctl list-units --no-pager --plain --no-legend 2>/dev/null "
            "| awk '/grafana/{printf \" -u \"$1}'); if [ -n \"$U\" ]; then "
            "{S}journalctl $U -n 300 --no-pager 2>&1; else "
            "echo '(nenhuma unit systemd do Grafana encontrada)'; fi",
            "[ -f /var/log/grafana/grafana.log ] && "
            "{S}tail -n 200 /var/log/grafana/grafana.log",
        ],
        "basico": [
            "systemctl status --no-pager grafana-server grafana 2>&1 | head -n 40",
            "{S}ss -tulpn 2>/dev/null | tr -s ' ' | sed 's/,fd=[0-9]*//g' | "
            "grep -E ':3000|:3001' | sort -u",
            # /api/health não exige autenticação
            "curl -s -m 5 http://127.0.0.1:3000/api/health 2>&1 | head -n 20",
        ],
        "inventario": [
            "for b in grafana-server grafana grafana-cli; do "
            "command -v $b >/dev/null 2>&1 && { echo \"===== $b\"; "
            "timeout 5 $b -v 2>&1 | head -n 3; }; done",
            "(dpkg -l 2>/dev/null | grep -i grafana) || "
            "(rpm -qa 2>/dev/null | grep -i grafana)",
            "{S}ls -1 /var/lib/grafana/plugins/ 2>/dev/null",
        ],
        "extra": {
            "titulo": "Conteúdo do Grafana (dashboards, datasources, "
                      "regras de alerta e usuários)",
            "comandos": [
                DEF_Q_GRAFANA,
                "G \"SELECT 'dashboards', COUNT(*) FROM dashboard WHERE is_folder=0 "
                "UNION ALL SELECT 'pastas', COUNT(*) FROM dashboard WHERE is_folder=1 "
                "UNION ALL SELECT 'datasources', COUNT(*) FROM data_source "
                "UNION ALL SELECT 'usuarios', COUNT(*) FROM user\"",
                "G \"SELECT CASE d.is_folder WHEN 1 THEN 'pasta' ELSE 'dashboard' END, "
                "d.title, d.uid, d.version, d.updated FROM dashboard d "
                "ORDER BY d.is_folder DESC, d.title\"",
                "G \"SELECT name, type, url, CASE is_default WHEN 1 THEN 'padrao' "
                "ELSE '' END, CASE basic_auth WHEN 1 THEN 'basic-auth' ELSE '' END "
                "FROM data_source ORDER BY name\"",
                "G \"SELECT rule_group, title, CASE is_paused WHEN 1 THEN 'pausada' "
                "ELSE 'ativa' END, updated FROM alert_rule ORDER BY rule_group, title\"",
                "G \"SELECT name, state FROM alert ORDER BY name\"",
                "G \"SELECT dp.name, d.title FROM dashboard_provisioning dp "
                "JOIN dashboard d ON d.id=dp.dashboard_id ORDER BY dp.name\"",
                "G \"SELECT login, CASE is_admin WHEN 1 THEN 'admin' ELSE 'usuario' END, "
                "CASE is_disabled WHEN 1 THEN 'desabilitado' ELSE 'ativo' END "
                "FROM user ORDER BY login\"",
            ],
        },
    },
    "bird": {
        # Daemon de roteamento. Num provedor costuma manter as sessões BGP de
        # trânsito, PTT e clientes, e em servidores auxiliares participa de
        # anúncios de blackhole. A partir do BIRD 2 o binário de controle é
        # 'birdc'; o BIRD 1 usa 'birdc' e 'birdc6' separados por família.
        "nome": "BIRD (daemon de roteamento BGP/OSPF)",
        "deteccao": "{ command -v bird >/dev/null 2>&1 || "
                    "test -f /etc/bird/bird.conf || test -f /etc/bird.conf; } "
                    "&& echo PRESENTE",
        "config": [
            "for f in /etc/bird/bird.conf /etc/bird.conf /etc/bird/bird6.conf; "
            "do [ -f \"$f\" ] && { echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\"; }; done",
            "{S}ls -la /etc/bird/ /etc/bird/conf.d/ 2>/dev/null",
            "for f in /etc/bird/conf.d/*.conf /etc/bird/*.conf; do "
            "[ -f \"$f\" ] && case \"$f\" in */bird.conf|*/bird6.conf) ;; *) "
            "echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\";; esac; done",
            "for b in birdc birdcl birdc6; do command -v $b >/dev/null 2>&1 && "
            "{ echo \"===== $b show status\"; "
            "timeout 15 {S}$b show status 2>&1 | head -n 15; }; done",
        ],
        "logs": [
            "U=$(systemctl list-units --no-pager --plain --no-legend "
            "2>/dev/null | awk '/bird/{printf \" -u \"$1}'); "
            "if [ -n \"$U\" ]; then {S}journalctl $U -n 250 --no-pager 2>&1; "
            "else echo '(nenhuma unit systemd do BIRD encontrada)'; fi",
            "[ -f /var/log/bird.log ] && {S}tail -n 200 /var/log/bird.log",
        ],
        "basico": [
            "systemctl status --no-pager bird bird6 2>&1 | head -n 40",
            # Estado das sessões: 'show protocols all' traz, por vizinho,
            # estado, tempo de sessão, rotas importadas/exportadas e o motivo
            # da última queda — o que caracteriza a saúde do peering.
            "for b in birdc birdcl; do command -v $b >/dev/null 2>&1 && "
            "{ echo \"===== $b show protocols\"; "
            "timeout 20 {S}$b show protocols 2>&1 | head -n 80; "
            "echo \"===== $b show protocols all\"; "
            "timeout 30 {S}$b show protocols all 2>&1 | head -n 400; "
            "break; }; done",
            "for b in birdc birdcl; do command -v $b >/dev/null 2>&1 && "
            "{ echo \"===== memoria e contagem de rotas\"; "
            "timeout 15 {S}$b show memory 2>&1 | head -n 15; "
            "timeout 20 {S}$b show route count 2>&1 | head -n 10; "
            "timeout 20 {S}$b show symbols 2>&1 | head -n 60; break; }; done",
            "{S}ss -tnp 2>/dev/null | tr -s ' ' | grep ':179' | head -n 40",
        ],
        "inventario": [
            # Somente o daemon aceita --version; birdc e birdcl respondem
            # "invalid option -- '-'" e imprimem o uso.
            "command -v bird >/dev/null 2>&1 && "
            "timeout 5 bird --version 2>&1 | head -n 3",
            "(dpkg -l 2>/dev/null | grep -i -E '^ii +bird') || "
            "(rpm -qa 2>/dev/null | grep -i '^bird')",
        ],
    },
    "smokeping": {
        "nome": "SmokePing (medição de latência e perda)",
        "deteccao": "{ test -d /etc/smokeping || "
                    "command -v smokeping >/dev/null 2>&1; } && echo PRESENTE",
        "config": [
            "{S}ls -la /etc/smokeping/ /etc/smokeping/config.d/ 2>/dev/null",
            # A configuração é fatiada em config.d; Targets costuma ser o
            # maior arquivo e descreve toda a topologia medida.
            "for f in /etc/smokeping/config.d/*; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\" | head -n 400; }; done",
            "[ -f /etc/smokeping/config ] && { echo '===== /etc/smokeping/config'; "
            "{S}grep -v -E '^[[:space:]]*#|^[[:space:]]*$' "
            "/etc/smokeping/config | head -n 200; }",
            "echo \"alvos monitorados: $({S}grep -c '^+' "
            "/etc/smokeping/config.d/Targets 2>/dev/null)\"",
        ],
        "logs": [
            "U=$(systemctl list-units --no-pager --plain --no-legend "
            "2>/dev/null | awk '/smokeping/{printf \" -u \"$1}'); "
            "if [ -n \"$U\" ]; then {S}journalctl $U -n 200 --no-pager 2>&1; "
            "else echo '(nenhuma unit systemd do SmokePing)'; fi",
        ],
        "basico": [
            "systemctl status --no-pager smokeping 2>&1 | head -n 30",
            "{S}du -sh /var/lib/smokeping 2>/dev/null; "
            "{S}find /var/lib/smokeping -name '*.rrd' 2>/dev/null | wc -l",
        ],
        "inventario": [
            "command -v smokeping >/dev/null 2>&1 && "
            "timeout 5 smokeping --version 2>&1 | head -n 3",
            "(dpkg -l 2>/dev/null | grep -i -E '^ii +smokeping') || "
            "(rpm -qa 2>/dev/null | grep -i '^smokeping')",
        ],
    },
    "isp_stack": {
        "nome": "ISP-Stack (suite de serviços para provedor)",
        # O estado persistente fica em /etc/isp-stack: provider.conf com a
        # identificação do provedor e um arquivo por módulo instalado em
        # state/, o que torna a detecção e o inventário determinísticos.
        "deteccao": "{ test -d /etc/isp-stack || test -f /etc/isp-stack/"
                    "provider.conf; } && echo PRESENTE",
        "config": [
            # Identidade do provedor e módulos efetivamente instalados
            "echo '===== versao e estado'; {S}cat /etc/isp-stack/VERSION "
            "2>/dev/null; {S}ls -la /etc/isp-stack/ /etc/isp-stack/state/ "
            "2>/dev/null",
            "[ -f /etc/isp-stack/provider.conf ] && "
            "{ echo '===== provider.conf'; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' /etc/isp-stack/provider.conf; }",
            "for f in /etc/isp-stack/unattended.conf "
            "/etc/isp-stack/secondary.conf /etc/isp-stack/jumphost; do "
            "[ -e \"$f\" ] && { echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\" 2>/dev/null || "
            "{S}ls -la \"$f\"; }; done",
            # DNS recursivo (Unbound) — o módulo dns.sh usa Unbound com
            # adblock; o BIND9 é coberto pelo módulo bind9 do netsnap.
            "for f in /etc/unbound/unbound.conf.d/isp-stack.conf "
            "/etc/unbound/unbound.conf.d/adblock.conf; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\" | head -n 120; }; done",
            # NTP, SNMP e coleta
            "for f in /etc/chrony/chrony.conf /etc/snmp/snmpd.conf; do "
            "[ -f \"$f\" ] && { echo \"===== $f\"; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' \"$f\"; }; done",
            # Stack de monitoramento
            "for f in /etc/prometheus/prometheus.yml "
            "/etc/alertmanager/alertmanager.yml "
            "/etc/blackbox_exporter/blackbox.yml; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}ls -la /etc/prometheus/targets/ 2>/dev/null; "
            "for f in /etc/prometheus/targets/*.yml; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}ls -la /etc/prometheus/rules/ /etc/prometheus/*.rules "
            "2>/dev/null",
            # RPKI
            "[ -f /etc/routinator/routinator.conf ] && "
            "{ echo '===== routinator.conf'; {S}grep -v -E "
            "'^[[:space:]]*#|^[[:space:]]*$' /etc/routinator/routinator.conf; }",
            # Serviços web publicados pelo stack
            "{S}ls -la /etc/apache2/sites-enabled/ 2>/dev/null",
            "for f in /etc/apache2/sites-available/isp-*.conf "
            "/etc/apache2/sites-available/lookingglass.conf "
            "/etc/apache2/sites-available/librespeed.conf "
            "/etc/apache2/sites-available/dokuwiki.conf; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}grep -h -E '^Listen' /etc/apache2/ports.conf 2>/dev/null",
            # Jump host e acesso web ao terminal
            "[ -f /etc/ssh/sshd_config.d/60-isp-jumphost.conf ] && "
            "{ echo '===== 60-isp-jumphost.conf'; {S}cat "
            "/etc/ssh/sshd_config.d/60-isp-jumphost.conf; }",
            "for u in /etc/systemd/system/isp-*.service "
            "/etc/systemd/system/isp-*.timer; do [ -f \"$u\" ] && "
            "{ echo \"===== $u\"; {S}cat \"$u\"; }; done",
            # Endurecimento
            "for f in /etc/fail2ban/jail.d/isp-stack.conf "
            "/etc/apt/apt.conf.d/51isp-unattended "
            "/etc/audit/rules.d/isp-stack.rules; do [ -f \"$f\" ] && "
            "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
        ],
        "logs": [
            "{S}ls -la /var/log/isp-stack/ 2>/dev/null | tail -n 15",
            "for f in $({S}ls -1t /var/log/isp-stack/install-*.log "
            "2>/dev/null | head -n 1); do echo \"===== $f (ultimas linhas)\"; "
            "{S}tail -n 150 \"$f\"; done",
            "U=$(systemctl list-units --no-pager --plain --no-legend "
            "2>/dev/null | awk '/isp-|routinator|prometheus|alertmanager|"
            "blackbox|node_exporter|unbound|chrony/{printf \" -u \"$1}'); "
            "if [ -n \"$U\" ]; then {S}journalctl $U -n 250 --no-pager "
            "2>&1; else echo '(nenhuma unit do ISP-Stack encontrada)'; fi",
        ],
        "basico": [
            # Estado de cada serviço do stack, sem lista fixa de nomes
            "systemctl list-units --no-pager --all --plain 2>/dev/null | "
            "grep -E 'isp-|routinator|prometheus|alertmanager|blackbox|"
            "node_exporter|unbound|chrony|snmpd|grafana|apache2|named|bind9|"
            "gvmd|ospd|fail2ban'",
            "systemctl list-timers --all --no-pager 2>/dev/null | "
            "grep -E 'isp-|certbot|unbound|logrotate'",
            # Portas do stack: 3000 Grafana, 7681 ttyd, 8088/8090/8095 web,
            # 8323 Routinator, 9090 Prometheus, 9093 Alertmanager,
            # 9100 node_exporter, 9115 blackbox, 9392 OpenVAS
            "{S}ss -tulpn 2>/dev/null | tr -s ' ' | sed 's/,fd=[0-9]*//g' | "
            "grep -E ':(53|123|161|443|2048|3000|7681|8088|8090|8095|8323|"
            "9090|9093|9100|9115|9392)\\b' | sort -u",
            # Saúde dos serviços de rede do provedor
            "command -v unbound-control >/dev/null 2>&1 && "
            "{ {S}unbound-control status 2>&1 | head -n 12; "
            "{S}unbound-control stats_noreset 2>/dev/null | "
            "grep -E 'total\\.(num|requestlist)|num\\.query\\.type\\.A=|"
            "num\\.answer\\.rcode\\.NXDOMAIN' | head -n 12; }",
            "command -v chronyc >/dev/null 2>&1 && "
            "{ chronyc tracking 2>&1 | head -n 12; "
            "chronyc sources 2>&1 | head -n 15; }",
            # Estado da validação RPKI, sem disparar validação completa
            "curl -s -m 8 http://127.0.0.1:8323/status 2>/dev/null | "
            "head -n 25 || echo '(Routinator nao respondeu em 127.0.0.1:8323)'",
            "curl -s -m 8 http://127.0.0.1:8323/metrics 2>/dev/null | "
            "grep -E '^routinator_(vrps_final|last_update|serial)' | "
            "head -n 12",
            # Prometheus: alvos e alertas ativos
            "curl -s -m 8 'http://127.0.0.1:9090/api/v1/targets?state=active' "
            "2>/dev/null | head -c 4000",
            "curl -s -m 8 http://127.0.0.1:9090/api/v1/alerts 2>/dev/null "
            "| head -c 3000",
            "curl -s -m 8 http://127.0.0.1:9093/api/v2/status 2>/dev/null "
            "| head -c 1500",
            # Backup: última execução e volume
            "systemctl status --no-pager isp-backup.timer isp-backup.service "
            "2>&1 | head -n 25",
            "{S}find /var/backups /opt/isp-backup /srv/backup -maxdepth 2 "
            "-name '*.tar*' -o -maxdepth 2 -name '*isp*' 2>/dev/null | "
            "head -n 15",
            # Certificados emitidos pelo certbot
            "command -v certbot >/dev/null 2>&1 && "
            "{S}certbot certificates 2>&1 | head -n 40",
        ],
        "inventario": [
            "{S}cat /etc/isp-stack/VERSION 2>/dev/null; "
            "{S}ls -1 /etc/isp-stack/state/ 2>/dev/null",
            "for b in prometheus alertmanager node_exporter blackbox_exporter "
            "routinator unbound named chronyd snmpd grafana-server ttyd; do "
            "command -v $b >/dev/null 2>&1 && { echo \"===== $b\"; "
            "timeout 5 $b --version 2>&1 | head -n 2; }; done",
            "(dpkg -l 2>/dev/null | grep -i -E 'unbound|chrony|snmpd|"
            "prometheus|grafana|routinator|apache2|fail2ban|certbot|"
            "dokuwiki') || (rpm -qa 2>/dev/null | grep -i -E "
            "'unbound|chrony|prometheus|grafana|routinator')",
            "{S}ls -la /var/www/ 2>/dev/null",
            "command -v gvmd >/dev/null 2>&1 && "
            "{ timeout 10 {S}gvmd --version 2>&1 | head -n 3; "
            "timeout 10 {S}gvm-check-setup 2>&1 | tail -n 15; }",
        ],
        # O ISP-Stack instala módulos de forma seletiva. Sem esta seção, o
        # relatório não distingue "módulo ausente" de "módulo com falha".
        "extra": {
            "titulo": "Módulos instalados e conformidade da instalação",
            "comandos": [
                "echo '===== modulos com estado registrado'; "
                "for f in /etc/isp-stack/state/*; do [ -e \"$f\" ] && "
                "echo \"  $(basename \"$f\")\"; done 2>/dev/null",
                # O próprio stack traz verificadores. Eles são invocados
                # exclusivamente por 'install.sh --audit' e '--verify', que
                # são as entradas NÃO interativas: executar 'audit.sh' direto
                # abre um menu e chega a perguntar se deve gravar o relatório
                # em /var/log/isp-stack, o que gravaria no servidor. Pelas
                # flags, o install.sh chama audit_executar_sem_perguntar e
                # verify_executar, que apenas leem e imprimem.
                "I=$({S}find /opt /root /usr/local/share /srv -maxdepth 4 "
                "-name install.sh -path '*ISP-Stack*' 2>/dev/null | head -n1); "
                "echo \"install.sh: ${I:-nao localizado}\"",
                "I=$({S}find /opt /root /usr/local/share /srv -maxdepth 4 "
                "-name install.sh -path '*ISP-Stack*' 2>/dev/null | head -n1); "
                # A flag é conferida no próprio script antes da chamada: um
                # install.sh antigo, sem '--audit', poderia ignorar o
                # argumento e seguir o fluxo de instalação.
                "[ -n \"$I\" ] && if {S}grep -q -e '--audit)' -e '\"--audit\"' "
                "\"$I\"; then echo '===== install.sh --audit'; "
                "timeout 180 {S}bash \"$I\" --audit </dev/null 2>&1 | "
                "tail -n 200; else echo 'install.sh sem modo --audit: nao "
                "executado'; fi",
                "I=$({S}find /opt /root /usr/local/share /srv -maxdepth 4 "
                "-name install.sh -path '*ISP-Stack*' 2>/dev/null | head -n1); "
                "[ -n \"$I\" ] && if {S}grep -q -e '--verify)' -e '\"--verify\"' "
                "\"$I\"; then echo '===== install.sh --verify'; "
                "timeout 180 {S}bash \"$I\" --verify </dev/null 2>&1 | "
                "tail -n 150; else echo 'install.sh sem modo --verify: nao "
                "executado'; fi",
            ],
        },
    },
    "bind9": {
        "nome": "BIND9 (DNS autoritativo/recursivo)",
        "deteccao": "command -v named >/dev/null 2>&1 || test -d /etc/bind "
                    "&& echo PRESENTE",
        "config": [
            # Em servidor de bloqueio DNS a configuração efetiva chega a
            # centenas de milhares de linhas (84 mil zonas observadas em
            # produção). O despejo integral inviabiliza a leitura, então a
            # coleta separa a configuração global das declarações de zona,
            # que são resumidas e amostradas logo abaixo.
            # O awk conta chaves para suprimir apenas os blocos de zona
            # completos. Linhas como 'zone "rpz.anablock";' dentro de
            # response-policy não abrem bloco e são preservadas — são
            # exatamente as que interessam.
            "{S}named-checkconf -p 2>/dev/null | awk '"
            "/^[[:space:]]*zone[[:space:]]+\"/ && /{/ "
            "{d=gsub(/{/,\"{\")-gsub(/}/,\"}\"); if(d>0) z=1; next} "
            "z {d+=gsub(/{/,\"{\")-gsub(/}/,\"}\"); if(d<=0) z=0; next} "
            "{print}' | head -n 400",
            "echo \"total de zonas declaradas: $({S}named-checkconf -p "
            "2>/dev/null | grep -c '^[[:space:]]*zone[[:space:]]*\"')\"",
            "{S}named-checkconf -p 2>/dev/null | "
            "sed -n 's/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
            "| head -n 100",
            "for f in /etc/bind/named.conf /etc/named.conf "
            "/etc/bind/named.conf.options /etc/bind/named.conf.local; do "
            "[ -f \"$f\" ] && { echo \"===== $f\"; {S}cat \"$f\"; }; done",
            "{S}ls -la /etc/bind/ /var/named/ /var/cache/bind/ "
            "/etc/bind/zones/ 2>/dev/null",
            "{S}rndc status 2>&1",
        ],
        "logs": [
            "{S}journalctl -u named -u bind9 -n 300 --no-pager 2>&1",
            "{S}ls -la /var/log/named* /var/log/bind* 2>/dev/null",
        ],
        "basico": [
            # Amostra e contagem: a lista completa de zonas pode ter
            # dezenas de milhares de entradas e não cabe no documento.
            "{S}named-checkconf -p 2>/dev/null | "
            "sed -n 's/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
            "| sort -u | head -n 150",
            "echo \"zonas distintas: $({S}named-checkconf -p 2>/dev/null | "
            "sed -n 's/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
            "| sort -u | wc -l)\"",
            # rndc status traz a contagem que o próprio BIND reconhece
            "{S}rndc status 2>&1 | head -n 20",
            "dig @127.0.0.1 . SOA +time=3 +tries=1 2>&1 | head -n 20",
            "{S}ss -lnup 2>/dev/null | tr -s ' ' | sed 's/,fd=[0-9]*//g' | "
            "grep :53 | sort -u | head -n 40",
        ],
        "inventario": [
            "named -v 2>&1; named -V 2>&1 | head -n 20",
            "(dpkg -l 2>/dev/null | grep -i -E 'bind9|bind-') "
            "|| (rpm -qa 2>/dev/null | grep -i '^bind')",
        ],
        # Verificação do bloqueio DNS. Existem dois mecanismos distintos em
        # uso no mercado brasileiro, e a coleta identifica qual está ativo:
        #
        #   RPZ (Response Policy Zone) — bloco 'response-policy' em named.conf
        #   apontando para zonas de política; o BIND reescreve a resposta.
        #
        #   Sinkhole por zona — usado pelo AnaBlock: declara cada domínio
        #   bloqueado como zona master apontando para um arquivo único
        #   (tipicamente db.local), de modo que o recursor passa a responder
        #   como autoritativo pelo domínio. Não há bloco 'response-policy'.
        #
        # A efetividade é comprovada por consulta real ao próprio resolvedor,
        # não pela presença da configuração.
        "extra": {
            "titulo": "Bloqueio DNS (RPZ / AnaBlock) — mecanismo, "
                      "abrangência e prova de efetividade",
            "comandos": [
                # 1. Qual mecanismo está em uso
                "R=$({S}named-checkconf -p 2>/dev/null | "
                "awk '/response-policy/,/};/'); "
                "if [ -n \"$R\" ]; then echo 'mecanismo: RPZ (response-policy)'; "
                "echo \"$R\"; else echo 'mecanismo: sem bloco response-policy "
                "— bloqueio por zona-sinkhole (padrao AnaBlock) ou ausente'; fi",
                # 2. Arquivo de listas e volume
                "{S}find /etc/bind /var/named /etc/anablock /opt/anablock "
                "-maxdepth 3 \\( -iname '*anablock*' -o -iname '*rpz*' \\) "
                "2>/dev/null | head -n 20",
                "for f in $({S}find /etc/bind /etc/anablock /opt/anablock "
                "-maxdepth 2 -iname '*anablock*.conf' -o -maxdepth 2 "
                "-iname '*rpz*.conf' 2>/dev/null | head -n 3); do "
                "echo \"===== $f: $({S}grep -c '' \"$f\" 2>/dev/null) linhas, "
                "$({S}grep -c '^[[:space:]]*zone' \"$f\" 2>/dev/null) zona(s)\"; "
                "{S}head -n 5 \"$f\"; done",
                # 3. Zonas de política declaradas (filtro ancorado: evita
                # domínios bloqueados que apenas contenham 'block' no nome)
                "{S}named-checkconf -p 2>/dev/null | "
                "sed -n 's/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
                "| grep -i -E '(^|\\.)(rpz|anablock)([.-]|$)|\\.rpz\\.|^rpz' "
                "| sort -u | head -n 20",
                # 4. Alvo do sinkhole: para onde os domínios bloqueados apontam
                "for f in /etc/bind/db.local /etc/bind/db.blocked "
                "/etc/bind/db.anablock; do [ -f \"$f\" ] && "
                "{ echo \"===== $f\"; {S}cat \"$f\"; }; done",
                # 5. PROVA DE EFETIVIDADE — consulta real ao resolvedor local.
                # O AnaBlock publica domínios de teste próprios; a resposta
                # deles demonstra se o bloqueio está de fato atuando.
                "for d in block-test.anablock.net.br blocktest.anablock.net.br; "
                "do echo \"===== teste oficial: $d\"; "
                "dig @127.0.0.1 \"$d\" A +short +time=3 +tries=1 2>&1 | "
                "head -n 5; done",
                # Amostra tirada da própria lista instalada
                "F=$({S}find /etc/bind /etc/anablock -maxdepth 2 "
                "-iname '*anablock*.conf' 2>/dev/null | head -n1); "
                "if [ -n \"$F\" ]; then for d in $({S}sed -n "
                "'s/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
                "\"$F\" | head -n 3); do echo \"===== bloqueado (amostra): $d\"; "
                "dig @127.0.0.1 \"$d\" A +short +time=3 +tries=1 2>&1 | "
                "head -n 3; done; fi",
                # Controle: domínio fora da lista deve resolver normalmente
                "echo '===== controle (nao bloqueado): iana.org'; "
                "dig @127.0.0.1 iana.org A +short +time=3 +tries=1 2>&1 | "
                "head -n 3",
                # 6. Estado das zonas de política no BIND (carregadas?)
                "for z in $({S}named-checkconf -p 2>/dev/null | "
                "sed -n 's/^[[:space:]]*zone[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' "
                "| grep -i -E '(^|\\.)(rpz|anablock)([.-]|$)' | sort -u "
                "| head -n 5); do echo \"===== zonestatus: $z\"; "
                "{S}rndc zonestatus \"$z\" 2>&1 | head -n 8; done",
                # 7. Atualização da lista: serviço, cron e script
                "systemctl list-units --no-pager --all 2>/dev/null | "
                "grep -i -E 'anablock|rpz'; systemctl list-timers --all "
                "--no-pager 2>/dev/null | grep -i -E 'anablock|rpz'",
                "{S}crontab -l 2>/dev/null | grep -i -E 'anablock|rpz'; "
                "{S}grep -r -h -i -E 'anablock|rpz' /etc/crontab "
                "/etc/cron.d/ 2>/dev/null | head -n 10",
                "for s in $({S}find /etc/bind /etc/anablock /opt/anablock "
                "-maxdepth 2 \\( -iname '*anablock*.sh' -o -iname '*rpz*.sh' \\) "
                "2>/dev/null | head -n 3); do echo \"===== $s\"; "
                "{S}head -n 60 \"$s\"; done",
                # 8. Dimensão do bloqueio frente ao total de zonas
                "echo \"zonas totais no BIND: $({S}rndc status 2>/dev/null | "
                "sed -n 's/.*number of zones: *\\([0-9]*\\).*/\\1/p')\"; "
                "echo \"zonas em arquivos de bloqueio: $({S}find /etc/bind "
                "/etc/anablock -maxdepth 2 -iname '*anablock*.conf' -o "
                "-maxdepth 2 -iname '*rpz*.conf' 2>/dev/null | "
                "xargs -r {S}grep -h -c '^[[:space:]]*zone' 2>/dev/null | "
                "paste -sd+ - | bc 2>/dev/null)\"",
                # A lista pode estar presente e atualizada pelo cron sem
                # estar referenciada em named.conf: nesse caso o arquivo
                # cresce todo dia e nada é bloqueado. A verificação do
                # include distingue "lista ausente" de "lista não carregada".
                "for f in $({S}find /etc/bind /etc/anablock -maxdepth 2 "
                "\\( -iname '*anablock*.conf' -o -iname '*rpz*.conf' \\) "
                "2>/dev/null); do "
                "if {S}grep -rqs -F \"$f\" /etc/bind/named.conf* "
                "/etc/named.conf 2>/dev/null; then "
                "echo \"incluido em named.conf: $f\"; else "
                "echo \"NAO INCLUIDO em named.conf: $f "
                "(a lista existe mas o BIND nao a carrega)\"; fi; done",
                "{S}rndc status 2>&1 | grep -i -E 'zones|recursive|server is up'",
            ],
        },
    },
}

# ---------------------------------------------------------------------------
# Remoção de dados sensíveis
# ---------------------------------------------------------------------------
_CHAVES = (
    r"password|passwd|pwd|secret(?:[_-]?key)?|pre-shared-key|"
    r"authentication-key|auth-key|key-string|hello-password|cipher|"
    r"irreversible-cipher|shared-secret|wpa2?-pre-shared-key|private-key|"
    r"privatekey|presharedkey|tcp-md5-key|bindpw|"
    r"dbpass|db_pass|api[_-]?key|access[_-]?key|auth[_-]?token|token"
)
# Palavras que, entre a chave e o valor, qualificam o segredo sem sê-lo:
# "password irreversible-cipher $1c$...", "enable secret 9 $9$...",
# "authentication-key 1 type md5 value "$9$..."". Sem saltá-las, a
# qualificação era mascarada e o hash seguia visível logo depois.
_QUALIFICADOR = (
    r"(?:(?:irreversible-cipher|cipher|simple|encrypted|plain(?:text)?|"
    r"ascii-text|hexadecimal|hex|value|md5|sha\d*|aes(?:[ \t]*\d+)?|3?des|"
    r"type[ \t]+\S+|level[ \t]+\d+|\d{1,2})[ \t]+)*"
)
# Cifras Huawei (%^%#...%^%#, $1c$...$) e hashes crypt ($6$, $9$) contêm
# vírgula, ponto e vírgula e aspas; vão até o próximo espaço. Encontrado em
# campo: "password irreversible-cipher $1c$...,7A%8:M$..." deixava visível
# tudo após a vírgula.
_VALOR = (r"(%\^%#\S*|\$\d[a-z]?\$\S*|\"[^\"\n]*\"|'[^'\n]*'|[^\s;,]+)")
PADROES_SENSIVEIS = [
    # chave=valor e chave: valor. O trecho ["']?\]?["']? cobre formatos como
    # $DB['PASSWORD'] = '...' (frontend PHP do Zabbix) e "password": "..."
    # (JSON/YAML). 'community' entra apenas nesta forma: como palavra solta
    # ela nomeia também comunidades BGP ("policy-options community X
    # members ..."), que não são segredo e são indispensáveis para ler as
    # políticas.
    re.compile(r"(?i)((?:" + _CHAVES + r"|community)[\"']?\]?[\"']?[ \t]*[:=][ \t]*)"
               + _VALOR),
    # SNMP: a comunidade é a própria credencial.
    re.compile(r"(?i)(snmp(?:-server|-agent)?[ \t]+community[ \t]+"
               r"(?:(?:read|write)[ \t]+)?(?:(?:cipher|simple)[ \t]+)?)(\S+)"),
    re.compile(r"(?im)^([ \t]*r[ow]community6?[ \t]+)(\S+)"),
    re.compile(r"(?im)^([ \t]*com2sec6?[ \t]+\S+[ \t]+\S+[ \t]+)(\S+)"),
    # SNMPv3: "auth sha X priv aes 128 Y".
    re.compile(r"(?i)(\b(?:auth|priv)[ \t]+(?:md5|sha\d*|aes(?:[ \t]*\d+)?|3?des)"
               r"[ \t]+(?:encrypted[ \t]+)?)(\S+)"),
    # "key" isolado só quando seguido de tipo numérico (Cisco: "tacacs-server
    # key 7 X") ou de valor entre aspas/cifrado (Junos: 'key "$9$..."').
    re.compile(r"(?i)((?<![\w-])key[ \t]+\d{1,2}[ \t]+)(\S+)"),
    re.compile(r"(?i)((?<![\w-])key[ \t]+)(\"[^\"\n]*\"|\$\S+)"),
    # chave valor, na mesma linha, com qualificadores opcionais.
    # Não tomam o lugar do valor: verbos de menu do RouterOS ("/ppp secret
    # add") e nomes de algoritmo ("ssh server cipher aes256_ctr").
    re.compile(r"(?i)((?:" + _CHAVES + r")[ \t]+" + _QUALIFICADOR + r")(?![=:])"
               r"(?!(?:add|set|print|remove|edit|export)\b)"
               r"(?!(?:aes|3?des|sha|hmac|chacha|arcfour)[\w-]*(?:\s|$))"
               + _VALOR),
    re.compile(r"(ssh-(?:rsa|ed25519|dss)[ \t]+)(\S+)"),
]
# O fim é opcional: uma saída truncada pelo limite de tamanho pode cortar o
# bloco antes do END, e nesse caso todo o restante é suprimido.
PADRAO_CERT = re.compile(r"-----BEGIN[^-\n]*-----[\s\S]*?(?:-----END[^-\n]*-----|\Z)")
# MikroTik: o nome da comunidade SNMP aparece como "name=" dentro do bloco
# "/snmp community" do export, sem palavra-chave que o denuncie.
PADRAO_BLOCO_SNMP_MIKROTIK = re.compile(
    r"(?m)^/snmp community\s*$(?:\n(?!/).*)*")


def _mascarar_snmp_mikrotik(m):
    return re.sub(r"(\bname=)(\"[^\"\n]*\"|\S+)", r"\1***REMOVIDO***", m.group(0))

# Arquivos cujo conteúdo é integralmente um segredo, sem par chave=valor que
# permita detecção por padrão (ex.: /opt/andrisoft/etc/dbpass.conf contém
# apenas a senha). Os blocos de despejo de arquivo do netsnap são marcados
# com "===== /caminho/arquivo"; ao encontrar um arquivo com esse perfil de
# nome, todo o conteúdo até o próximo marcador é suprimido.
PADRAO_ARQUIVO_SEGREDO = re.compile(
    r"(?im)^(=====\s+\S*(?:dbpass|passwd|password|secret|shadow|"
    r"\.key|_key|privkey|credential|token)\S*)\s*$"
    r"((?:\n(?!=====).*)*)"
)


def _suprimir_arquivo(m):
    return f"{m.group(1)}\n***CONTEÚDO DE ARQUIVO SENSÍVEL REMOVIDO***"


def sanitizar(texto: str) -> str:
    texto = PADRAO_CERT.sub("***CERTIFICADO/CHAVE REMOVIDO***", texto)
    texto = PADRAO_ARQUIVO_SEGREDO.sub(_suprimir_arquivo, texto)
    texto = PADRAO_BLOCO_SNMP_MIKROTIK.sub(_mascarar_snmp_mikrotik, texto)
    for padrao in PADROES_SENSIVEIS:
        texto = padrao.sub(r"\1***REMOVIDO***", texto)
    return texto


# O systemd emprega cores de 256 níveis no formato \x1b[0;38:5:245m, com
# dois-pontos como separador de parâmetro (ITU-T T.416). Sem ele na
# classe, a sequência atravessa o filtro e vai parar no relatório.
PADRAO_ANSI = re.compile(r"\x1b\[[0-9;:?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\\\)")


def nome_seguro(texto: str) -> str:
    """Normaliza um hostname para uso em nome de arquivo (Windows e Linux):
    remove códigos ANSI e substitui caracteres proibidos (: ~ / \\ etc.)."""
    texto = PADRAO_ANSI.sub("", texto)
    texto = re.sub(r"[^A-Za-z0-9._-]", "_", texto)
    # Hífen no início faria o arquivo ser lido como opção de linha de comando
    # (grep, rm, ls) — caso real: "--Press_any_key..." virou nome de arquivo.
    texto = re.sub(r"_+", "_", texto).strip("_.-")
    return texto


PADRAO_ERRO = re.compile(
    r"(?i)^\s*[%^]*\s*("
    r"invalid input|invalid command|unknown command|unrecognized command|"
    r"incomplete command|bad command|syntax error|error:\s|"
    r"% invalid|% unknown|% incomplete|% bad|% permission"
    r")"
)
# Mensagens que podem aparecer em qualquer posição da linha (shell e CLIs)
PADRAO_ERRO_LIVRE = re.compile(
    r"(?i)(command not found|not recognized as|no such file or directory|"
    r"permission denied|is not supported|unsupported command|"
    r"does not exist|unknown parameter|bad command name|"
    r"expected end of command|"
    # Mesmas mensagens em servidor com locale pt_BR
    r"comando não encontrado|permissão negada|"
    r"arquivo ou diretório (?:inexistente|não encontrado))"
)


# Volume máximo gravado por comando. Existe porque um único comando pode
# devolver dezenas de MB (por exemplo 'named-checkconf -p' em servidor com
# dezenas de milhares de zonas), o que inviabiliza a leitura do snapshot por
# um modelo de linguagem. O corte é explícito no relatório.
LIMITE_SAIDA_COMANDO = 512 * 1024

# A configuração é o conteúdo que justifica o snapshot: truncá-la inutiliza
# o documento para reconstruir ou auditar o equipamento. Um roteador de borda
# com políticas de BGP e filtros passa facilmente de 400 KB, então esta seção
# tem folga muito maior que as demais.
LIMITE_POR_SECAO = {
    "config": 8 * 1024 * 1024,
    "logs": 512 * 1024,
    "inventario": 512 * 1024,
}


def normalizar_saida(texto: str, limite: int = None) -> str:
    """Remove códigos ANSI (o journald colore a saída, o que polui o
    documento sem acrescentar informação) e trunca volumes excessivos,
    registrando o corte de forma explícita."""
    if not texto:
        return texto
    texto = PADRAO_ANSI.sub("", texto)
    texto = texto.replace("\r\n", "\n").replace("\r", "\n")
    limite = LIMITE_SAIDA_COMANDO if limite is None else limite
    if limite and len(texto) > limite:
        total_linhas = len(texto.splitlines())
        corte = texto[:limite]
        corte = corte[:corte.rfind("\n")] if "\n" in corte else corte
        omitidas = total_linhas - len(corte.splitlines())
        corte += (f"\n\n[SAÍDA TRUNCADA PELO netsnap — {len(texto)} bytes no "
                  f"total, {omitidas} linha(s) omitida(s). O conteúdo acima é "
                  f"o início da saída; ajuste LIMITE_SAIDA_COMANDO para "
                  f"ampliar.]")
        return corte
    return texto


def sem_saida_util(saida: str) -> bool:
    """Identifica retorno vazio ou de comando não suportado pela plataforma."""
    texto = PADRAO_ANSI.sub("", saida or "").strip()
    if not texto:
        return True
    linhas = [l for l in texto.splitlines() if l.strip()]
    if not linhas:
        return True
    if len(linhas) <= 3 and any(
        PADRAO_ERRO.search(l) or PADRAO_ERRO_LIVRE.search(l) for l in linhas
    ):
        return True
    return False


# Pipeline anexado às seções de log em hosts Linux.
#
# Serviços com falha recorrente repetem a mesma mensagem centenas de vezes:
# num servidor WANGuard, 285 das 300 linhas coletadas eram o mesmo erro de
# conexão, cada uma arrastando o comando SQL inteiro — 97 KB para dizer uma
# coisa só. O filtro trunca linhas muito longas, agrupa as que têm a mesma
# assinatura (dígitos normalizados) e informa quantas foram omitidas, de
# modo que a repetição continue visível sem dominar o documento.
FILTRO_LOG = (
    r" | cut -c1-400 | awk "
    '\'{ k=$0; gsub(/[0-9]+/,"#",k); gsub(/#[.:,-]#/,"#",k); k=substr(k,1,110); '
    r"if (k==p) { c++; next } "
    r'if (c>1) printf "    [+%d linha(s) semelhante(s) omitida(s)]\n", c-1; '
    r"c=1; p=k; print } "
    'END { if (c>1) printf "    [+%d linha(s) semelhante(s) omitida(s)]\\n", c-1 }\''
)

# ---------------------------------------------------------------------------
# Interação inicial
# ---------------------------------------------------------------------------
def escolher_modo() -> tuple:
    print("\nTipo de extração:")
    print("  1) Configuração completa")
    print("  2) Logs")
    print("  3) Estado do equipamento (CPU, memória, alarmes, protocolos)")
    print("  4) Interfaces e ópticas (módulo SFP/QSFP, sinal, velocidade,")
    print("     tráfego e taxa de erros)")
    print("  5) Vizinhança L2 (LLDP/CDP)")
    print("  6) Inventário (versões, software, licenças)")
    print("  7) MAPA DA REDE — configuração + ópticas + vizinhança + inventário")
    print("     (sem logs; retrato da topologia e da camada física)")
    print("  8) EXTRAÇÃO TOTAL (tudo acima)")
    while True:
        op = input("Escolha [1-8]: ").strip()
        if op in MAPA_MODOS:
            break
    secoes, nome = MAPA_MODOS[op]
    return list(secoes), nome


def escolher_sensivel() -> bool:
    op = input("Incluir dados sensíveis (senhas/chaves/certificados)? [s/N]: ").strip().lower()
    return op == "s"


def escolher_instancias() -> int:
    op = input("Instâncias simultâneas [1-10, padrão 5]: ").strip()
    if op.isdigit() and 1 <= int(op) <= 10:
        return int(op)
    return 5


def escolher_protocolo() -> str:
    print("\nProtocolo de acesso:")
    print("  1) SSH (padrão)")
    print("  2) Telnet — para equipamentos sem SSH, como muitas OLTs")
    print("     ATENÇÃO: o Telnet transmite usuário e senha em texto claro.")
    while True:
        op = input("Escolha [1-2, padrão 1]: ").strip()
        if op in ("", "1"):
            return "ssh"
        if op == "2":
            print("[!] Telnet selecionado: credenciais trafegarão sem "
                  "criptografia. Use apenas em rede de gerência confiável.")
            return "telnet"


def escolher_debug() -> bool:
    op = input("Gerar log de depuração da coleta? [s/N]: ").strip().lower()
    return op == "s"


def escolher_varredura() -> str:
    print("\nModo de varredura:")
    print("  1) FAST — ping ICMP em todos os alvos antes; descarta os sem resposta")
    print("     (mais rápido; equipamentos que bloqueiam ICMP serão pulados)")
    print("  2) BUSCA PROFUNDA — tenta conexão em todos os IPs")
    while True:
        op = input("Escolha [1-2, padrão 1]: ").strip()
        if op in ("", "1"):
            return "fast"
        if op == "2":
            return "deep"


def menu_manual(ip: str):
    print(f"\n[{ip}] Não identificado automaticamente. Selecione o tipo:")
    print("  0) Pular este equipamento")
    for i, chave in enumerate(ORDEM_MENU, 1):
        print(f"  {i}) {PERFIS[chave]['nome']}")
    while True:
        op = input(f"Escolha [0-{len(ORDEM_MENU)}]: ").strip()
        if op == "0":
            return None
        if op.isdigit() and 1 <= int(op) <= len(ORDEM_MENU):
            return ORDEM_MENU[int(op) - 1]


# ---------------------------------------------------------------------------
# Varredura prévia (ICMP e TCP)
# ---------------------------------------------------------------------------
def ping(ip: str, timeout_s: int = 1) -> bool:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout_s + 2)
        if r.returncode != 0:
            return False
        # No Windows, "Host de destino inacessível" vindo do gateway também
        # retorna 0; só há resposta real quando aparece o TTL.
        if platform.system().lower() == "windows":
            return b"TTL=" in r.stdout.upper()
        return True
    except Exception:
        return False


def varrer_icmp(alvos, paralelo: int = 64):
    """Executa ping em todos os alvos em paralelo. Retorna (vivos, mortos)."""
    vivos, mortos = [], []
    if not shutil.which("ping"):
        # Sem o binário, todo ping "falharia" e todos os alvos seriam
        # descartados como fora do ar.
        print("\n[!] Comando 'ping' não encontrado nesta máquina: a varredura "
              "ICMP foi pulada e todos os alvos serão tentados.")
        return list(alvos), []
    print(f"\n[+] Varredura ICMP em {len(alvos)} alvo(s) ...")
    with ThreadPoolExecutor(max_workers=min(paralelo, max(len(alvos), 1))) as pool:
        futuros = {pool.submit(ping, ip): (ip, porta) for ip, porta in alvos}
        for fut in as_completed(futuros):
            alvo = futuros[fut]
            (vivos if fut.result() else mortos).append(alvo)
    print(f"    Responderam: {len(vivos)} | Sem resposta: {len(mortos)}")
    ordem = {a: i for i, a in enumerate(alvos)}
    vivos.sort(key=lambda a: ordem[a])
    mortos.sort(key=lambda a: ordem[a])
    return vivos, mortos


def porta_recusada(ip: str, porta: int, tempo: int = 3) -> bool:
    try:
        with socket.create_connection((ip, porta), timeout=tempo):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def porta_aberta(ip: str, porta: int, tempo: int = 3) -> bool:
    try:
        with socket.create_connection((ip, porta), timeout=tempo):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Identificação rápida pelo banner SSH
#
# O servidor SSH anuncia sua identificação antes de qualquer autenticação
# (RFC 4253, seção 4.2). Ler essa linha custa uma conexão TCP de milissegundos
# e, em boa parte do parque, já determina a plataforma — evitando o
# SSHDetect do Netmiko, que autentica e testa uma sequência de comandos de
# vários fabricantes até acertar.
#
# Confiança 'alta'  : o banner identifica o fabricante sem ambiguidade.
# Confiança 'media' : indica a família, mas exige confirmação (OpenSSH é usado
#                     por Linux, Junos e NX-OS).
# ---------------------------------------------------------------------------
# Cada entrada mapeia um padrão de banner para uma lista ordenada de
# candidatos. Confiança 'alta' dispensa confirmação; 'media' confirma o
# primeiro candidato que responder ao comando de verificação.
BANNER_PLATAFORMA = [
    (re.compile(r"(?i)ROSSSH|RouterOS"), ["mikrotik_routeros"], "alta"),
    # JSSH é o servidor SSH do Junos e não aparece em outra plataforma.
    (re.compile(r"(?i)JSSH|Junos|JUNOSSSH"), ["juniper_junos"], "alta"),
    (re.compile(r"(?i)Cisco-1\.\d+"), ["cisco_ios"], "media"),
    (re.compile(r"(?i)Cisco-2\.\d+"), ["cisco_xr", "cisco_ios"], "media"),
    (re.compile(r"(?i)HUAWEI|VRP"), ["huawei"], "media"),
    # O VRP não publica a identificação do software: anuncia apenas
    # "SSH-2.0--" ou "SSH-1.99--". A ausência da string é, ela própria, a
    # assinatura — pouquíssimos servidores se comportam assim, e o SSH-1.99
    # (compatibilidade com SSHv1) reforça tratar-se de equipamento de rede.
    # A família exata (V5, V8 ou SmartAX) é resolvida depois, por
    # classificar_huawei().
    (re.compile(r"^SSH-\d+\.\d+-+\s*$"), ["huawei", "cisco_ios"], "media"),
    (re.compile(r"(?i)FiberHome|AN[56]\d{3}"), ["fiberhome"], "media"),
    # Sufixo de distribuição identifica Linux com boa margem.
    (re.compile(r"(?i)OpenSSH.*(Ubuntu|Debian|Raspbian|el[789]|SUSE|"
                r"Amazon|CentOS)"), ["linux"], "media"),
    # OpenSSH sem sufixo de distribuição: os MX usam essa forma, assim como
    # appliances baseados em BSD. Testar dois candidatos custa poucos
    # segundos e evita o SSHDetect, que leva mais de dez.
    (re.compile(r"(?i)OpenSSH"), ["juniper_junos", "linux"], "media"),
]


def sondar_ssh(ip: str, porta: int, tempo: int = 4):
    """Lê a identificação do servidor SSH sem autenticar.

    Devolve (situacao, banner). A situação separa casos que pedem ações
    diferentes do operador:
      ok          banner recebido
      recusada    nada escuta na porta (serviço desligado ou outra porta)
      sem_resposta  nenhuma resposta TCP (host fora, ACL, firewall)
      sem_banner  conexão aceita, mas o servidor não se identificou —
                  típico de limite de sessões ou proteção contra força bruta
    """
    try:
        s = socket.create_connection((ip, porta), timeout=tempo)
    except ConnectionRefusedError:
        return "recusada", None
    except OSError:
        return "sem_resposta", None
    with s:
        s.settimeout(tempo)
        dados = b""
        try:
            while b"\n" not in dados and len(dados) < 512:
                pedaco = s.recv(256)
                if not pedaco:
                    break
                dados += pedaco
        except OSError:
            pass
    banner = dados.decode("utf-8", "replace").strip()
    return ("ok", banner) if banner else ("sem_banner", None)


MOTIVO_SONDAGEM = {
    "recusada": "conexão recusada na porta {porta} (serviço desligado ou "
                "em outra porta)",
    "sem_resposta": "sem resposta TCP na porta {porta} (host fora do ar, "
                    "ACL ou firewall)",
    "sem_banner": "porta {porta} aberta, mas o equipamento não enviou o "
                  "banner SSH — provável limite de sessões simultâneas ou "
                  "proteção contra força bruta",
}


def ler_banner(ip: str, porta: int, tempo: int = 4):
    """Banner SSH, ou None quando não há banner (compatibilidade)."""
    return sondar_ssh(ip, porta, tempo)[1]


def plataforma_por_banner(banner: str):
    """Retorna (lista de candidatos, confianca) a partir do banner."""
    if not banner:
        return [], None
    for padrao, candidatos, confianca in BANNER_PLATAFORMA:
        if padrao.search(banner):
            return list(candidatos), confianca
    return [], None


def driver_para(tipo, protocolo="ssh"):
    """device_type do Netmiko para o perfil, conforme o protocolo."""
    if protocolo == "telnet":
        return DRIVER_TELNET.get(tipo, "generic_telnet")
    return PERFIS[tipo].get("driver", tipo)


def confirmar_plataforma(ip, usuario, senha, porta, tipo,
                         protocolo="ssh") -> bool:
    """Confirma um palpite com uma única conexão e um comando."""
    verificacao = {
        "linux": ("uname -s", r"Linux"),
        "mikrotik_routeros": ("/system resource print", r"(?i)routeros|mikrotik"),
        "juniper_junos": ("show version", r"(?i)junos"),
        "cisco_ios": ("show version", r"(?i)cisco ios"),
        "cisco_xr": ("show version", r"(?i)ios xr"),
        "huawei": ("display version", r"(?i)huawei|VRP"),
        "huawei_ce": ("display version", r"(?i)huawei|VRP"),
        "huawei_smartax": ("display version", r"(?i)MA5[68]\d\d|SmartAX|VRP"),
        "fiberhome": ("show version", r"(?i)fiberhome|AN[56]\d{3}|version"),
    }
    if tipo not in verificacao:
        return False
    cmd, esperado = verificacao[tipo]
    try:
        with abrir_conexao(device_type=driver_para(tipo, protocolo), host=ip,
                            username=usuario, password=senha, port=porta,
                            timeout=25, conn_timeout=12) as conn:
            if protocolo == "telnet":
                liberar_cli(conn, ip, protocolo)
                # Plataformas com prompt fora do padrão não confirmam o eco
                # do comando; a leitura por temporização não depende disso.
                saida = conn.send_command_timing(cmd, read_timeout=25,
                                                 last_read=3)
            else:
                saida = conn.send_command(cmd, read_timeout=25)
        ok = bool(re.search(esperado, saida or ""))
        depurar(ip, "confirmacao", f"{tipo}: '{cmd}' -> "
                                   f"{'confirmado' if ok else 'nao confere'} "
                                   f"({resumir_saida(saida, 120)})")
        return ok
    except Exception as e:
        depurar(ip, "confirmacao", f"{tipo}: falhou ({type(e).__name__}: {e})")
        return False


# ---------------------------------------------------------------------------
# Detecção de plataforma
# ---------------------------------------------------------------------------
class NaoIdentificado(Exception):
    """Host acessível cuja plataforma não foi identificada automaticamente."""


def classificar_huawei(ip, usuario, senha, porta,
                       protocolo="ssh") -> str:
    """Determina a família Huawei a partir de 'display version'.

    Três linhas com sintaxes distintas compartilham o driver 'huawei' do
    Netmiko e precisam de perfis próprios:
      huawei         VRP V5, linha campus (S5700/S6720/S6730/S9700)
      huawei_ce      VRP V8, CloudEngine (CE6800/CE6860/CE8800) e NE
      huawei_smartax SmartAX (OLT MA5600/MA5800)
    Uma única conexão decide entre as três."""
    try:
        with abrir_conexao(device_type=driver_para("huawei", protocolo),
                            host=ip, username=usuario, password=senha,
                            port=porta, timeout=25, conn_timeout=12) as conn:
            versao = conn.send_command("display version", read_timeout=25)
    except Exception as e:
        depurar(ip, "familia huawei", f"falha na sonda: {type(e).__name__}")
        return "huawei"

    if re.search(r"(?i)MA5[68]\d\d|SmartAX", versao or ""):
        depurar(ip, "familia huawei", "SmartAX (OLT)")
        return "huawei_smartax"
    # A versão do VRP é o critério primário; o modelo confirma.
    if re.search(r"(?i)Version\s+8\.", versao or "") or \
            re.search(r"(?i)\bCE\d{4}|CloudEngine|NE\d{4}", versao or ""):
        depurar(ip, "familia huawei", "VRP V8 (CloudEngine/NE)")
        return "huawei_ce"
    depurar(ip, "familia huawei", "VRP V5 (campus)")
    return "huawei"


def eh_linux(ip, usuario, senha, porta, protocolo="ssh") -> bool:
    try:
        with abrir_conexao(device_type=driver_para("linux", protocolo),
                            host=ip, username=usuario, password=senha,
                            port=porta, timeout=20, conn_timeout=12) as conn:
            saida = conn.send_command("uname -s", read_timeout=15)
        return "Linux" in saida
    except Exception:
        return False


def detectar_telnet(ip, usuario, senha, porta):
    """Identifica a plataforma numa sessão Telnet.

    Não há banner de protocolo para ler como em SSH, então a identificação
    usa o texto de login que o equipamento apresenta antes da autenticação;
    quando ele não basta, o candidato é confirmado com um comando."""
    t0 = time.perf_counter()
    texto = ler_prompt_telnet(ip, porta)
    if texto is None:
        situacao = "recusada" if porta_recusada(ip, porta) else "sem_resposta"
        motivo = MOTIVO_SONDAGEM[situacao].format(porta=porta)
        depurar(ip, "telnet", motivo)
        raise NetmikoTimeoutException(motivo)
    depurar(ip, "telnet prompt", repr(texto[-160:]))

    candidatos, confianca = plataforma_por_prompt_telnet(texto)
    if candidatos:
        depurar(ip, "prompt->palpite", f"{candidatos} (confianca {confianca})")
        log(ip, f"prompt indica {PERFIS[candidatos[0]]['nome']}; confirmando ...")
        for i, cand in enumerate(candidatos[:2]):
            if i:
                time.sleep(3)
            if confirmar_plataforma(ip, usuario, senha, porta, cand,
                                    protocolo="telnet"):
                if cand == "huawei":
                    cand = classificar_huawei(ip, usuario, senha, porta,
                                              protocolo="telnet")
                log(ip, f"identificado: {PERFIS[cand]['nome']} "
                        f"({time.perf_counter()-t0:.1f}s, via prompt telnet)")
                depurar(ip, "identificado",
                        f"{cand} em {time.perf_counter()-t0:.2f}s (telnet)")
                return cand
        depurar(ip, "prompt->palpite", "nenhum candidato confirmado")

    # Sem pista no prompt resta tentar perfis, mas cada tentativa é um login
    # completo: em OLT, sucessivas falhas costumam disparar bloqueio por
    # tentativa e esgotar o limite de sessões simultâneas, que é baixo. Por
    # isso o número de tentativas é reduzido, com intervalo entre elas, e o
    # operador escolhe manualmente se nenhuma vingar.
    log(ip, "prompt não identifica a plataforma; tentando 2 perfis "
            "(cada tentativa é um login)")
    for i, cand in enumerate(("fiberhome", "huawei_smartax")):
        if i:
            time.sleep(3)
        if confirmar_plataforma(ip, usuario, senha, porta, cand,
                                protocolo="telnet"):
            log(ip, f"identificado: {PERFIS[cand]['nome']} "
                    f"({time.perf_counter()-t0:.1f}s, por tentativa)")
            depurar(ip, "identificado", f"{cand} (telnet, por tentativa)")
            return cand

    depurar(ip, "nao identificado", f"telnet, prompt={texto[-120:]!r}")
    raise NaoIdentificado(ip)


def detectar(ip, usuario, senha, porta, protocolo="ssh"):
    """Identifica a plataforma via SSH.

    Estratégia em três níveis, do mais barato ao mais caro:
      1. banner SSH (uma conexão TCP, sem autenticação) — resolve sozinho os
         casos inequívocos e sugere um candidato nos demais;
      2. confirmação do candidato com uma conexão e um comando;
      3. SSHDetect do Netmiko, que testa comandos de vários fabricantes.

    Levanta NaoIdentificado quando o host responde mas não é reconhecido;
    levanta exceção de conexão/autenticação nos demais casos."""
    if protocolo == "telnet":
        return detectar_telnet(ip, usuario, senha, porta)
    t0 = time.perf_counter()
    situacao, banner = sondar_ssh(ip, porta)
    if situacao != "ok":
        motivo = MOTIVO_SONDAGEM[situacao].format(porta=porta)
        depurar(ip, "banner", motivo)
        raise NetmikoTimeoutException(motivo)
    depurar(ip, "banner", f"{banner!r} em {time.perf_counter()-t0:.2f}s")

    candidatos, confianca = plataforma_por_banner(banner)
    if candidatos:
        depurar(ip, "banner->palpite",
                f"{candidatos} (confianca {confianca})")
        log(ip, f"banner indica {PERFIS[candidatos[0]]['nome']}"
                + (" e outros" if len(candidatos) > 1 else "")
                + "; confirmando ...")
        for candidato in candidatos:
            if confianca == "alta" or confirmar_plataforma(
                    ip, usuario, senha, porta, candidato):
                if candidato == "huawei":
                    candidato = classificar_huawei(ip, usuario, senha, porta)
                log(ip, f"identificado: {PERFIS[candidato]['nome']} "
                        f"({time.perf_counter()-t0:.1f}s, via banner)")
                depurar(ip, "identificado",
                        f"{candidato} em {time.perf_counter()-t0:.2f}s "
                        "(via banner)")
                return candidato
        depurar(ip, "banner->palpite",
                "nenhum candidato confirmado; caindo para SSHDetect")

    log(ip, "detectando plataforma ...")
    detectado = None
    ultimo_erro = None
    for tentativa in range(2):
        try:
            t1 = time.perf_counter()
            guesser = SSHDetect(device_type="autodetect", host=ip,
                                username=usuario, password=senha, port=porta,
                                timeout=20, conn_timeout=15)
            detectado = guesser.autodetect()
            depurar(ip, "SSHDetect",
                    f"retornou {detectado!r} em {time.perf_counter()-t1:.2f}s")
            ultimo_erro = None
            break
        except NetmikoAuthenticationException:
            depurar(ip, "SSHDetect", "falha de autenticacao")
            raise
        except Exception as e:
            ultimo_erro = e
            depurar(ip, "SSHDetect", f"{type(e).__name__}: {e}")
            if "banner" in str(e).lower() and tentativa == 0:
                # Banner não recebido: típico de rate-limit ou proteção
                # anti-brute-force no host. Aguarda e tenta uma única vez.
                log(ip, "banner SSH não recebido; nova tentativa em 10s ...")
                time.sleep(10)
                continue
            break

    if ultimo_erro is not None and "banner" in str(ultimo_erro).lower():
        raise NetmikoTimeoutException(
            "banner SSH não recebido — provável rate-limit ou proteção "
            "anti-brute-force no host (adicione o IP de origem à whitelist "
            "ou aguarde o timeout do bloqueio)"
        )

    if detectado not in PERFIS:
        alias = {"cisco_xe": "cisco_ios", "huawei_vrpv8": "huawei"}
        anterior = detectado
        detectado = alias.get(detectado)
        if anterior and detectado:
            depurar(ip, "alias", f"{anterior} -> {detectado}")

    if detectado == "huawei":
        detectado = classificar_huawei(ip, usuario, senha, porta)

    if detectado is None and eh_linux(ip, usuario, senha, porta):
        detectado = "linux"
        depurar(ip, "sonda linux", "uname -s confirmou Linux")

    if detectado in PERFIS:
        log(ip, f"identificado: {PERFIS[detectado]['nome']} "
                f"({time.perf_counter()-t0:.1f}s)")
        depurar(ip, "identificado",
                f"{detectado} em {time.perf_counter()-t0:.2f}s (via SSHDetect)")
        return detectado

    depurar(ip, "nao identificado",
            f"banner={banner!r} SSHDetect={detectado!r}")
    raise NaoIdentificado(ip)


# ---------------------------------------------------------------------------
# Execução de comandos e montagem do relatório
# ---------------------------------------------------------------------------
def liberar_cli(conn, ip="-", protocolo="ssh") -> str:
    """Obtém o prompt, tratando equipamentos que pedem uma tecla após o login.

    Devolve o texto do prompt já utilizável. Quando o equipamento apresenta
    "--Press any key to continue--", envia um retorno e relê; sem isso o texto
    do aviso seria tomado por prompt e o primeiro comando derrubaria a
    sessão."""
    try:
        prompt = conn.find_prompt()
    except Exception as e:
        depurar(ip, "find_prompt", f"{type(e).__name__}: {e}")
        prompt = ""

    for tentativa in range(3):
        if not PADRAO_TECLA.search(prompt or ""):
            break
        depurar(ip, "tecla requerida",
                f"tentativa {tentativa + 1}: {resumir_saida(prompt, 90)}")
        log(ip, "equipamento aguarda uma tecla; enviando retorno ...")
        try:
            conn.write_channel(conn.RETURN)
            time.sleep(1.5)
            conn.read_channel()
            prompt = conn.find_prompt()
        except Exception as e:
            depurar(ip, "tecla requerida", f"falhou: {type(e).__name__}: {e}")
            break
    depurar(ip, "prompt", repr((prompt or "")[-120:]))
    return prompt or ""


# Texto que denuncia um prompt mal capturado: aviso de tecla, pedido de
# credencial ou resto de banner. Nesses casos o IP identifica melhor o
# equipamento do que o suposto prompt.
PADRAO_PROMPT_INVALIDO = re.compile(
    r"(?i)press\s+any|any\s+key|password|senha|login|user\s*name|"
    r"ctrl[\s+-]*c|welcome|copyright|--\s*more|"
    # Prompts genéricos de nível de acesso (OLT FiberHome: "User>",
    # "Admin#"): não identificam o equipamento.
    r"^(?:user|admin|guest|enable)(?:\(config\))?$"
)


def nome_do_prompt(prompt: str, ip: str) -> str:
    """Extrai o hostname do prompt, recusando capturas evidentemente inválidas."""
    linha = [l for l in (prompt or "").splitlines() if l.strip()]
    bruto = linha[-1] if linha else ""
    bruto = bruto.strip("<>[]#>$ ").replace("/", "_").split("@")[-1]
    if not bruto or len(bruto) > 40 or PADRAO_PROMPT_INVALIDO.search(bruto):
        return ip
    return nome_seguro(bruto) or ip


def sessao_perdida(saida: str) -> bool:
    """Identifica queda de sessão, para interromper a coleta do host."""
    return bool(re.search(
        r"(?i)(EOFError|connection closed|connection reset|broken pipe|"
        r"socket is closed|not connected|no active channel|"
        r"stream closed by remote)", saida or ""))


NUCLEO_PAGINADOR = (r"(?:-{2,}\s*\(?\s*more\b[^\r\n]{0,40}?-{2,}|--more--|"
                    r"press any key to continue|-- \[Q quit\|[^\]\r\n]*\])")
PADRAO_PAGINADOR = re.compile(rf"(?i){NUCLEO_PAGINADOR}\s*$")
def limpar_paginacao(texto):
    """Remove avisos de paginação e as sequências que os apagam.

    Huawei: "---- More ----" seguido, após a tecla, de ESC[nD, n espaços e
    ESC[nD. Cisco: "--More--" apagado com backspaces. Só a sequência de
    apagamento é removida: a indentação da linha seguinte fica intacta."""
    # Aviso e apagamento juntos: tratados separados, o "----" final do
    # aviso emendaria numa linha de traços da página seguinte.
    apagar = r"(?:\x1b\[(\d+)D[ ]*\x1b\[\1D|\x08+[ ]*\x08+)"
    texto = re.sub(rf"(?i)[ \t]*{NUCLEO_PAGINADOR}{apagar}", "", texto)
    texto = re.sub(apagar, "", texto)
    texto = re.sub(rf"(?i)[ \t]*{NUCLEO_PAGINADOR}[ \t]*$", "", texto)
    return texto.replace("\r\n", "\n").replace("\r", "")


def continuar_paginacao(conn, parcial, ip="-", limite_paginas=3000):
    """Responde ao paginador até o prompt voltar.

    Usado quando o comando de desligar a paginação não foi aceito pelo
    equipamento: sem isso, cada comando esperaria o tempo-limite inteiro
    parado em "---- More ----". A continuação é lida do canal sem
    tratamento do Netmiko, para que as sequências de apagamento cheguem
    inteiras e possam ser removidas sem tocar na indentação."""
    canal = getattr(conn, "channel", None)
    ler = canal.read_channel if canal is not None else conn.read_channel
    prompt = re.escape(getattr(conn, "base_prompt", "") or "")
    fim_prompt = re.compile(rf"{prompt}[^\r\n]{{0,40}}[>#\]$%]\s*$") if prompt \
        else re.compile(r"[>#\]$%]\s*$")
    bruto, paginas = "", 0
    while paginas < limite_paginas:
        conn.write_channel(" ")
        paginas += 1
        novo, parado = "", time.time()
        while time.time() - parado < 15:
            pedaco = ler()
            if pedaco:
                novo += pedaco
                parado = time.time()
                visivel = PADRAO_ANSI.sub("", novo)[-200:]
                if PADRAO_PAGINADOR.search(visivel) or fim_prompt.search(visivel):
                    break
            else:
                time.sleep(0.05)
        bruto += novo
        if not novo or fim_prompt.search(PADRAO_ANSI.sub("", novo)[-200:]):
            break
    depurar(ip, "paginacao", f"{paginas} página(s) respondida(s)")
    saida = limpar_paginacao(parcial) + limpar_paginacao(bruto)
    linhas = saida.rstrip().splitlines()
    if linhas and fim_prompt.search(PADRAO_ANSI.sub("", linhas[-1])):
        linhas = linhas[:-1]
    return "\n".join(linhas)


def vigiar_canal(conn, parar):
    """Detecta queda da sessão SSH durante a leitura de um comando.

    Quando o equipamento fecha a sessão, o canal do Paramiko apenas deixa de
    ter dados, e o Netmiko espera o tempo-limite inteiro (180 s) antes de
    desistir. Ao ver o canal fechado e sem dados pendentes, este vigia
    desliga o canal do Netmiko, o que faz a leitura falhar na hora."""
    canal_netmiko = getattr(conn, "channel", None)
    canal = getattr(canal_netmiko, "remote_conn", None)
    if canal is None or not hasattr(canal, "eof_received"):
        return
    while not parar.wait(1.0):
        try:
            fechado = canal.closed or canal.eof_received
            if fechado and not canal.recv_ready():
                canal_netmiko.remote_conn = None
                return
        except Exception:
            return


def executar_comando(conn, cmd, usa_timing, ip="-", limite=None):
    """Executa um comando de leitura e registra tempo e retorno no debug."""
    t0 = time.perf_counter()
    depurar(ip, "envia comando", cmd)
    parar = threading.Event()
    threading.Thread(target=vigiar_canal, args=(conn, parar),
                     daemon=True).start()
    try:
        if usa_timing:
            saida = conn.send_command_timing(cmd, read_timeout=180, last_read=3)
            # A leitura por temporização devolve também o prompt final.
            linhas = (saida or "").rstrip().splitlines()
            if linhas and len(linhas[-1]) < 60 and \
                    PADRAO_FIM_PROMPT.search(linhas[-1]) and \
                    " " not in linhas[-1].strip():
                saida = "\n".join(linhas[:-1])
            if PADRAO_PAGINADOR.search(PADRAO_ANSI.sub("", saida or "")[-200:]):
                saida = continuar_paginacao(conn, saida, ip)
        else:
            # O fim da leitura é o prompt ou um paginador; no segundo caso o
            # equipamento recusou desligar a paginação e as páginas são
            # respondidas aqui.
            base = re.escape(getattr(conn, "base_prompt", "") or "")
            esperado = rf"(?:{base}|(?i:{NUCLEO_PAGINADOR}))" if base else None
            if esperado:
                saida = conn.send_command(cmd, read_timeout=180,
                                          expect_string=esperado)
            else:
                saida = conn.send_command(cmd, read_timeout=180)
            if PADRAO_PAGINADOR.search(PADRAO_ANSI.sub("", saida or "")[-200:]):
                saida = continuar_paginacao(conn, saida, ip)
        dur = time.perf_counter() - t0
        bruto = len(saida or "")
        saida = normalizar_saida(saida, limite)
        depurar(ip, "retorno",
                f"{dur:.2f}s | {bruto} bytes"
                + (f" -> {len(saida)} apos normalizar" if len(saida) != bruto
                   else "")
                + f" | {len((saida or '').splitlines())} linhas | "
                f"{resumir_saida(saida)}")
        return saida
    except Exception as e:
        dur = time.perf_counter() - t0
        depurar(ip, "ERRO no comando",
                f"{dur:.2f}s | {type(e).__name__}: {e} | cmd: {cmd[:120]}")
        return f"[ERRO ao executar comando: {e}]"
    finally:
        parar.set()


def detectar_apps_linux(conn, prefixo_sudo):
    """Identifica aplicações conhecidas instaladas no servidor Linux."""
    encontrados = []
    for chave, app in APPS_LINUX.items():
        cmd = app["deteccao"].replace("{S}", prefixo_sudo)
        try:
            saida = conn.send_command(cmd, read_timeout=25)
        except Exception:
            continue
        if "PRESENTE" in (saida or ""):
            encontrados.append(chave)
    return encontrados


def coletar(ip, porta, tipo, usuario, senha, secoes, nome_modo,
            incluir_sensivel, protocolo="ssh"):
    perfil = PERFIS[tipo]
    dispositivo = {
        "device_type": driver_para(tipo, protocolo),
        "host": ip,
        "username": usuario,
        "password": senha,
        "port": porta,
        "timeout": 45,
        "conn_timeout": 15,
    }
    usa_timing = perfil.get("timing", False)
    blocos = []          # (titulo, [(cmd, saida)])
    apps_detectados = []
    contexto_usado = False
    perdeu_sessao = False

    log(ip, f"conectando ({perfil['nome']}"
            + (" via TELNET" if protocolo == "telnet" else "") + ") ...")
    if perfil.get("contexto"):
        log(ip, "plataforma exige contexto privilegiado; apenas comandos "
                "de leitura serão executados")

    with abrir_conexao(**dispositivo) as conn:
        bruto = liberar_cli(conn, ip, protocolo)
        hostname = nome_do_prompt(bruto, ip)

        # Comandos preparatórios: paginação e contexto. Falhas são ignoradas.
        for cmd in perfil.get("prep", []):
            try:
                saida = conn.send_command_timing(cmd, read_timeout=20)
                if saida and re.search(r"(?i)password|senha", saida[-120:]):
                    saida = conn.send_command_timing(senha, read_timeout=20)
                    depurar(ip, "prep", f"{cmd}: senha solicitada e enviada")
                if cmd in ("enable", "config", "configure"):
                    contexto_usado = True
                depurar(ip, "prep", f"{cmd}: {resumir_saida(saida, 120)}")
            except Exception as e:
                depurar(ip, "prep", f"{cmd}: falhou ({type(e).__name__}: {e})")

        prefixo_sudo = ""
        if tipo == "linux":
            try:
                h = conn.send_command("hostname", read_timeout=15).strip()
                if h:
                    hostname = h.splitlines()[-1].strip()
            except Exception:
                pass
            try:
                r = conn.send_command("sudo -n true 2>/dev/null && echo SUDO_OK",
                                      read_timeout=20)
                if "SUDO_OK" in (r or ""):
                    prefixo_sudo = "sudo -n "
                    log(ip, "sudo não interativo disponível")
                depurar(ip, "sudo", "disponivel" if prefixo_sudo
                        else "indisponivel (comandos privilegiados falharao)")
            except Exception:
                pass
            apps_detectados = detectar_apps_linux(conn, prefixo_sudo)
            depurar(ip, "apps detectados",
                    ", ".join(apps_detectados) or "nenhum")
            if apps_detectados:
                nomes = ", ".join(APPS_LINUX[a]["nome"] for a in apps_detectados)
                log(ip, f"aplicações detectadas: {nomes}")

        hostname = nome_seguro(hostname) or ip

        # Seções da plataforma
        for secao in secoes:
            comandos = [c.replace("{S}", prefixo_sudo)
                        for c in perfil.get(secao, [])]
            if not comandos:
                continue
            if tipo == "mikrotik_routeros" and secao == "config" and not incluir_sensivel:
                comandos = ["/export hide-sensitive"]
            limite = LIMITE_POR_SECAO.get(secao)
            if secao == "logs" and tipo == "linux":
                comandos = [c + FILTRO_LOG for c in comandos]
            saidas = []
            for cmd in comandos:
                if perdeu_sessao:
                    break
                log(ip, f"-> {cmd[:70]}")
                saida = executar_comando(conn, cmd, usa_timing, ip, limite)
                if cmd.startswith("/export ") and sem_saida_util(saida):
                    # RouterOS v6 não conhece 'show-sensitive' e o v7 deixou
                    # de aceitar 'hide-sensitive' (passou a ocultar por
                    # padrão). O '/export' simples funciona nas duas; o
                    # sanitizador continua aplicado se a opção pedir.
                    depurar(ip, "fallback", f"'{cmd}' recusado; usando '/export'")
                    cmd = "/export"
                    saida = executar_comando(conn, cmd, usa_timing, ip, limite)
                saidas.append((cmd, saida))
                # Só o retorno de erro do próprio transporte indica queda. O
                # texto do comando não serve: logs de servidor trazem
                # "Connection closed by ..." do sshd o tempo todo.
                if saida.startswith("[ERRO ao executar comando:") and \
                        sessao_perdida(saida):
                    # Insistir depois da queda produz dezenas de mensagens
                    # idênticas e nenhum dado; a coleta deste host termina
                    # aqui, com o motivo registrado no relatório.
                    perdeu_sessao = True
                    log(ip, "[ABORTADO] sessão encerrada pelo equipamento")
                    depurar(ip, "sessao perdida", f"apos: {cmd[:80]}")
            if saidas:
                blocos.append((TITULOS[secao], saidas))
            if perdeu_sessao:
                break

        # Módulos de aplicação (Linux)
        def rodar_app(chave, comandos, limite=None):
            nonlocal perdeu_sessao
            saidas = []
            for cmd in comandos:
                if perdeu_sessao:
                    break
                log(ip, f"-> [{chave}] {cmd[:70]}")
                saida = executar_comando(conn, cmd, False, ip, limite)
                saidas.append((cmd, saida))
                if saida.startswith("[ERRO ao executar comando:") and \
                        sessao_perdida(saida):
                    perdeu_sessao = True
                    log(ip, "[ABORTADO] sessão encerrada pelo equipamento")
                    depurar(ip, "sessao perdida", f"apos: {cmd[:80]}")
            return saidas

        for chave in ([] if perdeu_sessao else apps_detectados):
            app = APPS_LINUX[chave]
            for secao in secoes:
                comandos = [c.replace("{S}", prefixo_sudo)
                            for c in app.get(secao, [])]
                if not comandos or perdeu_sessao:
                    continue
                if secao == "logs":
                    comandos = [c + FILTRO_LOG for c in comandos]
                saidas = rodar_app(chave, comandos, LIMITE_POR_SECAO.get(secao))
                if saidas:
                    blocos.append((f"{app['nome']} — {TITULOS[secao]}", saidas))
            extra = app.get("extra")
            if extra and set(secoes) & {"config", "basico", "inventario"} \
                    and not perdeu_sessao:
                saidas = rodar_app(chave, [c.replace("{S}", prefixo_sudo)
                                           for c in extra["comandos"]])
                if saidas:
                    blocos.append((f"{app['nome']} — {extra['titulo']}", saidas))

        for cmd in perfil.get("sair", []):
            try:
                conn.send_command_timing(cmd, read_timeout=10)
            except Exception:
                pass

    arquivo = escrever_relatorio(
        ip, hostname, tipo, perfil, blocos, nome_modo, secoes,
        incluir_sensivel, apps_detectados, contexto_usado, protocolo,
        perdeu_sessao,
    )
    return arquivo, hostname


def escrever_relatorio(ip, hostname, tipo, perfil, blocos, nome_modo, secoes,
                       incluir_sensivel, apps, contexto_usado,
                       protocolo="ssh", sessao_encerrada=False):
    agora = datetime.now()
    meta = {
        "netsnap_version": __version__,
        "host": hostname,
        "ip": ip,
        "platform_key": tipo,
        "platform_name": perfil["nome"],
        "vendor": perfil.get("fabricante", ""),
        "collected_at": agora.isoformat(timespec="seconds"),
        "extraction_mode": nome_modo,
        "sections": secoes,
        "applications": [APPS_LINUX[a]["nome"] for a in apps],
        "transport": protocolo,
        "session_lost": sessao_encerrada,
        "sensitive_data": "included" if incluir_sensivel else "redacted",
        "read_only": True,
        "config_changes_made": 0,
    }

    md = []
    md.append("---")
    for k, v in meta.items():
        md.append(f"{k}: {json.dumps(v, ensure_ascii=False)}")
    md.append("---\n")

    md.append(f"# Snapshot — {hostname} ({ip})\n")
    md.append(f"**{perfil['nome']}** · coletado em "
              f"{agora:%d/%m/%Y %H:%M:%S} · netsnap v{__version__}\n")

    md.append("## Como interpretar este documento\n")
    md.append(
        "Este arquivo é um snapshot **somente leitura** de um equipamento em "
        "produção, gerado automaticamente para análise humana ou por sistemas "
        "de IA. Estrutura e convenções:\n"
    )
    md.append(
        "- Cada `##` é uma seção temática; cada `###` é o **comando exatamente "
        "como executado** no equipamento.\n"
        "- Os blocos de código contêm a **saída bruta e não editada** do "
        "comando, na sintaxe nativa da plataforma.\n"
        "- `***REMOVIDO***` indica valor sensível suprimido na coleta; "
        "`***CERTIFICADO/CHAVE REMOVIDO***` indica bloco PEM suprimido. "
        "Esses marcadores substituem dados reais e não devem ser "
        "interpretados como configuração.\n"
        "- `_(sem saída útil...)_` indica comando não suportado por esta "
        "plataforma/firmware ou sem retorno. A ausência de saída **não** "
        "significa que o recurso esteja desabilitado.\n"
        "- Os metadados estão no bloco YAML no topo do arquivo.\n"
    )
    md.append(
        "Ao reconstruir ou replicar a configuração a partir deste documento: a "
        "seção *Configuração* contém a configuração completa na sintaxe nativa; "
        "valide sempre contra a versão de software e o modelo indicados na seção "
        "*Inventário*, pois comandos variam entre famílias e releases. Trate o "
        "conteúdo como um retrato pontual, não como estado corrente.\n"
    )
    if "optica" in secoes:
        md.append(
            "### Como ler a seção de interfaces e ópticas\n"
        )
        md.append(
            "- **Potência óptica (Rx/Tx)** é reportada em dBm e é sempre "
            "negativa em operação normal. Compare com os limiares de "
            "alarme/aviso que a própria plataforma informa quando disponíveis "
            "(`low-warning`, `low-alarm`); um Rx próximo do limiar inferior "
            "indica atenuação, e um valor como `-40 dBm` ou `N/A` costuma "
            "significar ausência de luz, não módulo defeituoso.\n"
            "- **Alcance do módulo** vem do EEPROM (SFF-8472) apenas em "
            "algumas plataformas — Huawei (`Transfer Distance`), MikroTik "
            "(`sfp-link-length-*`) e Linux (`ethtool -m`, campos `Length`). "
            "Em Juniper e Cisco esse campo não é exibido: o alcance deve ser "
            "inferido do modelo/PN do transceiver (por exemplo SR ≈ 300 m, "
            "LR ≈ 10 km, ER ≈ 40 km, ZR ≈ 80 km). Não afirme distância de "
            "enlace a partir do módulo: o PN indica o alcance **suportado**, "
            "não o comprimento real da fibra.\n"
            "- **Contadores de erro são cumulativos** desde o último boot ou "
            "limpeza de contadores. Um valor alto não implica problema atual, "
            "e este snapshot é uma amostra única: **taxa de erro só pode ser "
            "calculada com duas coletas em instantes diferentes**. Prefira "
            "correlacionar o contador com o uptime do equipamento (seção "
            "*Estado do equipamento* ou *Inventário*).\n"
            "- **Tráfego** aparece como taxa instantânea (média móvel da "
            "própria plataforma, geralmente 5 min) e/ou como contador "
            "acumulado de bytes/pacotes. Não são a mesma grandeza; verifique "
            "qual o comando retornou antes de comparar interfaces.\n"
            "- **Velocidade negociada** pode divergir da capacidade do módulo "
            "e da porta; ao montar topologia, use a velocidade negociada e a "
            "descrição da interface, não o modelo do transceiver.\n"
        )
    if "vizinhanca" in secoes:
        md.append(
            "Para construir topologia: cruze a seção *Vizinhança L2* (LLDP/CDP "
            "traz vizinho, porta local e porta remota) com as descrições de "
            "interface e o endereçamento da seção *Configuração*. Enlaces sem "
            "LLDP habilitado não aparecem na vizinhança e **não devem ser "
            "tratados como inexistentes** — confirme por interface ativa sem "
            "vizinho declarado.\n"
        )
    if sessao_encerrada:
        md.append(
            "> **Coleta incompleta.** O equipamento encerrou a sessão durante "
            "a execução e os comandos seguintes não chegaram a ser enviados. "
            "As seções ausentes não indicam recurso inexistente — indicam que "
            "a coleta foi interrompida. Causas frequentes: limite de sessões "
            "simultâneas na plataforma, tempo de inatividade excedido ou "
            "bloqueio após tentativas de login malsucedidas.\n"
        )
    if protocolo == "telnet":
        md.append(
            "> **Coleta por Telnet.** O equipamento foi acessado por Telnet, "
            "protocolo que transmite credenciais e sessão em texto claro. O "
            "conteúdo deste documento é o mesmo de uma coleta por SSH, mas a "
            "sessão que o originou era legível por qualquer sistema no "
            "caminho de rede. Quando a plataforma suportar SSH, prefira-o.\n"
        )
    if contexto_usado and perfil.get("contexto"):
        md.append(
            "> **Nota de contexto:** esta plataforma exige contexto "
            "privilegiado/configuração para executar comandos de exibição. O "
            "contexto foi acessado apenas para leitura; nenhum comando de "
            "escrita foi emitido e nenhuma alteração foi salva.\n"
        )

    md.append("## Índice\n")
    for titulo, saidas in blocos:
        md.append(f"- {titulo} ({len(saidas)} comando(s))")
    md.append("")

    for titulo, saidas in blocos:
        md.append(f"\n## {titulo}\n")
        for cmd, out in saidas:
            if not incluir_sensivel:
                out = sanitizar(out)
            md.append(f"### `{cmd}`\n")
            if sem_saida_util(out):
                resumo = " ".join((out or "").split())[:180]
                md.append(f"_(sem saída útil — retorno: `{resumo or 'vazio'}`)_\n")
            else:
                md.append("```text")
                md.append(out.rstrip())
                md.append("```\n")

    # O IP passa por nome_seguro: em IPv6 os dois-pontos criariam, no
    # Windows, um fluxo alternativo NTFS em vez do arquivo. A abertura em
    # modo exclusivo evita que dois hosts com o mesmo nome no mesmo segundo
    # (mesmo IP em portas diferentes, por exemplo) se sobrescrevam.
    rotulo = nome_seguro(ip) if hostname in (ip, nome_seguro(ip)) \
        else f"{hostname}_{nome_seguro(ip)}"
    base = os.path.join(PASTA_SAIDA, f"{rotulo}_{agora:%Y%m%d_%H%M%S}")
    conteudo = "\n".join(md)
    for n in range(1, 100):
        arquivo = base + (f"_{n}" if n > 1 else "") + ".md"
        try:
            with open(arquivo, "x", encoding="utf-8") as f:
                f.write(conteudo)
            return arquivo
        except FileExistsError:
            continue
    raise OSError(f"não foi possível criar arquivo único para {base}")


def escrever_indice(resultados, nome_modo, segundos_coleta):
    """Índice consolidado da execução, útil para ingestão em lote.

    O tempo informado é o de coleta: o relógio de parede incluiria a espera
    pelo operador no prompt, que em uma execução medida representou 982 s
    de um total de 1007 s."""
    def celula(valor, limite=160):
        # Mensagens de erro do Netmiko vêm em várias linhas e podem conter
        # '|', o que quebraria a tabela Markdown.
        return " ".join(str(valor).split()).replace("|", "/")[:limite]

    agora = datetime.now()
    ok = [r for r in resultados if r[1] is True]
    if not ok:
        return None
    md = ["---",
          f"netsnap_version: {json.dumps(__version__)}",
          f"document_type: {json.dumps('run_index')}",
          f"collection_seconds: {segundos_coleta:.0f}",
          f"generated_at: {json.dumps(agora.isoformat(timespec='seconds'))}",
          f"extraction_mode: {json.dumps(nome_modo)}",
          f"hosts_collected: {len(ok)}",
          "---\n",
          f"# Índice da coleta — {agora:%d/%m/%Y %H:%M:%S}\n",
          f"Modo de extração: **{nome_modo}** · tempo de coleta: "
          f"{segundos_coleta:.0f}s · hosts coletados: **{len(ok)}**\n",
          "Cada arquivo listado abaixo é um snapshot independente, com "
          "metadados YAML próprios.\n",
          "| Host | IP | Arquivo |", "|---|---|---|"]
    for ip, _, arq, host in [(r[0], r[1], r[2], r[3]) for r in ok]:
        md.append(f"| {celula(host)} | {ip} | `{os.path.basename(arq)}` |")
    falhas = [r for r in resultados if r[1] is False]
    if falhas:
        md.append("\n## Hosts não coletados\n")
        md.append("| IP | Motivo |")
        md.append("|---|---|")
        for ip, _, motivo, _ in falhas:
            md.append(f"| {ip} | {celula(motivo)} |")
    caminho = os.path.join(PASTA_SAIDA, f"_indice_{agora:%Y%m%d_%H%M%S}.md")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return caminho


# ---------------------------------------------------------------------------
# Expansão de entradas: IP, IP:porta, CIDR e range
# ---------------------------------------------------------------------------
def ler_ips(caminho):
    # utf-8-sig: o Bloco de Notas do Windows grava BOM no início do arquivo,
    # o que invalidaria a primeira linha.
    with open(caminho, "r", encoding="utf-8-sig") as f:
        linhas = [l.split("#", 1)[0].strip() for l in f]
    return [l for l in linhas if l]


PADRAO_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def expandir_entrada(entrada: str, porta_padrao: int):
    """Expande uma entrada em lista de (ip, porta). Formatos aceitos:
    10.0.0.5 | 10.0.0.5:2222 | 10.0.0.0/24 | 10.0.0.0/24:2222 |
    10.0.0.1-10.0.0.100 | 10.0.0.1-100 | nome.dns | nome.dns:2222 |
    2001:db8::1 | [2001:db8::1]:2222 | 2001:db8::/126"""
    entrada = entrada.split("#", 1)[0].strip()
    porta = porta_padrao
    # Porta: [IPv6]:porta, ou ':porta' quando há um único ':' (IPv4, nome
    # ou CIDR IPv4). IPv6 sem colchetes nunca tem porta — '2001:db8::1:22'
    # é um endereço válido, e separar o ':22' apontaria para outro host.
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", entrada)
    if m:
        entrada = m.group(1)
        if m.group(2):
            porta = int(m.group(2))
    elif entrada.count(":") == 1:
        base, p = entrada.split(":")
        if not p.isdigit():
            print(f"[!] Entrada inválida ignorada: '{entrada}' (porta)")
            return []
        entrada, porta = base, int(p)
    if not 1 <= porta <= 65535:
        print(f"[!] Entrada inválida ignorada: '{entrada}' (porta {porta} "
              "fora de 1-65535)")
        return []

    alvos = []
    try:
        if "/" in entrada:
            rede = ipaddress.ip_network(entrada, strict=False)
            if rede.num_addresses <= 2:
                # /31, /32, /127 e /128: todos os endereços são hosts
                # (RFC 3021) — enlaces ponto a ponto têm os dois lados.
                alvos = [str(h) for h in rede]
            else:
                alvos = [str(h) for h in rede.hosts()]
        elif re.match(r"^[\d.]+\s*-\s*[\d.]+$", entrada):
            inicio, fim = [x.strip() for x in entrada.split("-", 1)]
            ip_ini = ipaddress.ip_address(inicio)
            if "." in fim:
                ip_fim = ipaddress.ip_address(fim)
            else:
                base = inicio.rsplit(".", 1)[0]
                ip_fim = ipaddress.ip_address(f"{base}.{fim}")
            if int(ip_fim) < int(ip_ini):
                raise ValueError("fim do range menor que o início")
            alvos = [str(ipaddress.ip_address(i))
                     for i in range(int(ip_ini), int(ip_fim) + 1)]
        else:
            try:
                alvos = [str(ipaddress.ip_address(entrada))]
            except ValueError:
                # Nome DNS: resolvido na conexão. Um nome que não resolve
                # aparece como falha de conexão no resumo.
                if not PADRAO_HOSTNAME.match(entrada) or \
                        re.match(r"^[\d.]+$", entrada):
                    raise
                alvos = [entrada]
    except ValueError as e:
        print(f"[!] Entrada inválida ignorada: '{entrada}' ({e})")
        return []

    return [(ip, porta) for ip in alvos]


def montar_alvos(entradas, porta_padrao):
    alvos = []
    for e in entradas:
        alvos.extend(expandir_entrada(e, porta_padrao))
    vistos, unicos = set(), []
    for a in alvos:
        if a not in vistos:
            vistos.add(a)
            unicos.append(a)
    if len(unicos) > 256:
        resp = input(
            f"[!] Expansão resultou em {len(unicos)} alvos. Continuar? [s/N]: "
        ).strip().lower()
        if resp != "s":
            return []
    return unicos


# ---------------------------------------------------------------------------
# Processamento: fase paralela e fila de pendentes
# ---------------------------------------------------------------------------
def processar_lote(alvos, instancias, usuario, senha, secoes,
                   nome_modo, incluir_sensivel, resultados,
                   protocolo="ssh"):
    """Fase paralela: detecta e coleta os hosts identificados automaticamente.
    Retorna a lista de pendentes (acessíveis, porém não identificados)."""
    pendentes = []
    trava = threading.Lock()

    def trabalho(ip, porta):
        try:
            depurar(ip, "inicio", f"porta {porta} ({protocolo})")
            tipo = detectar(ip, usuario, senha, porta, protocolo)
            arq, host = coletar(ip, porta, tipo, usuario, senha, secoes,
                                nome_modo, incluir_sensivel, protocolo)
            log(ip, f"[OK] snapshot salvo: {os.path.basename(arq)}")
            with trava:
                resultados.append((ip, True, arq, host))
        except NaoIdentificado:
            log(ip, "[PENDENTE] não identificado — será perguntado ao final")
            with trava:
                pendentes.append((ip, porta))
        except NetmikoAuthenticationException:
            log(ip, "[FALHA] autenticação (usuário/senha)")
            with trava:
                resultados.append((ip, False, "autenticação", ip))
        except NetmikoTimeoutException as e:
            log(ip, f"[FALHA] {e}")
            with trava:
                resultados.append((ip, False, str(e), ip))
        except Exception as e:
            log(ip, f"[FALHA] {e}")
            with trava:
                resultados.append((ip, False, str(e), ip))

    with ThreadPoolExecutor(max_workers=instancias) as pool:
        futuros = [pool.submit(trabalho, ip, porta) for ip, porta in alvos]
        for fut in as_completed(futuros):
            fut.result()

    return pendentes


def processar_pendentes(pendentes, usuario, senha, secoes,
                        nome_modo, incluir_sensivel, resultados,
                        protocolo="ssh"):
    """Fase sequencial: consulta o operador sobre cada host não identificado."""
    if not pendentes:
        return
    print(f"\n[+] {len(pendentes)} equipamento(s) não identificado(s) automaticamente.")
    for ip, porta in pendentes:
        tipo = menu_manual(ip)
        if tipo is None:
            resultados.append((ip, None, "pulado", ip))
            continue
        try:
            arq, host = coletar(ip, porta, tipo, usuario, senha, secoes,
                                nome_modo, incluir_sensivel, protocolo)
            log(ip, f"[OK] snapshot salvo: {os.path.basename(arq)}")
            resultados.append((ip, True, arq, host))
        except Exception as e:
            log(ip, f"[FALHA] {e}")
            resultados.append((ip, False, str(e), ip))


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------
def menu_fim_sessao() -> str:
    """Oferece o que fazer ao encerrar a fila de alvos da sessão atual."""
    print("\n" + "-" * 68)
    print("  1) Nova coleta — reconfigurar tudo (protocolo, credenciais, modo)")
    print("  2) Continuar nesta sessão — informar mais alvos")
    print("  3) Sair")
    while True:
        op = input("Escolha [1-3, padrão 3]: ").strip()
        if op in ("", "3"):
            return "sair"
        if op == "1":
            return "reconfigurar"
        if op == "2":
            return "continuar"


def configurar_sessao():
    """Coleta os parâmetros de uma sessão. Retorna um dicionário de opções."""
    secoes, nome_modo = escolher_modo()
    incluir_sensivel = escolher_sensivel()
    global DEBUG
    if not DEBUG:
        DEBUG = escolher_debug()
    protocolo = escolher_protocolo()
    varredura = escolher_varredura()
    instancias = escolher_instancias()

    rotulo = "Telnet" if protocolo == "telnet" else "SSH"
    padrao = PORTA_TELNET_PADRAO if protocolo == "telnet" else 22
    usuario = input(f"\nUsuário {rotulo}: ").strip()
    senha = getpass.getpass(f"Senha {rotulo}: ")
    porta_txt = input(f"Porta {rotulo} [{padrao}]: ").strip()
    porta_padrao = int(porta_txt) if porta_txt.isdigit() else padrao

    return {
        "secoes": secoes, "nome_modo": nome_modo,
        "incluir_sensivel": incluir_sensivel, "varredura": varredura,
        "instancias": instancias, "usuario": usuario, "senha": senha,
        "porta_padrao": porta_padrao, "protocolo": protocolo,
    }


def imprimir_resumo(resultados, duracao, titulo="RESUMO", sessao=None):
    print("\n" + "=" * 68)
    print(f" {titulo}")
    print("=" * 68)
    ok = [r for r in resultados if r[1] is True]
    pulados = [r for r in resultados if r[1] is None]
    falha = [r for r in resultados if r[1] is False]
    icmp_mortos = [r for r in falha if "ICMP" in str(r[2])]
    outras_falhas = [r for r in falha if "ICMP" not in str(r[2])]

    print(f"Sucesso: {len(ok)}/{len(resultados)}"
          + (f"  |  Pulados: {len(pulados)}" if pulados else "")
          + (f"  |  Sem ICMP: {len(icmp_mortos)}" if icmp_mortos else "")
          + f"  |  Coleta: {duracao:.0f}s"
          + (f"  |  Sessão: {sessao:.0f}s" if sessao and sessao - duracao > 5
             else ""))
    for ip, _, arq, host in ok:
        print(f"  [OK]     {ip} ({host}) -> {os.path.basename(arq)}")
    for ip, _, _, _ in pulados:
        print(f"  [PULADO] {ip}")
    for ip, _, motivo, _ in outras_falhas:
        print(f"  [FALHA]  {ip} -> {motivo}")
    if icmp_mortos:
        print(f"  [SEM ICMP] {len(icmp_mortos)} IP(s) não responderam ping "
              "(use BUSCA PROFUNDA se algum bloqueia ICMP)")
    return ok


def main():
    global DEBUG
    if "--debug" in sys.argv:
        DEBUG = True
        sys.argv.remove("--debug")
    if len(sys.argv) > 1 and sys.argv[1] in ("-v", "--version"):
        print(f"netsnap {__version__}")
        return
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("Uso: python3 netsnap.py [arquivo_de_alvos.txt] [--debug]")
        return

    print("=" * 68)
    print(f" netsnap v{__version__} — Snapshot multi-vendor (somente leitura)")
    print(" Juniper | Huawei/OLT | FiberHome | Cisco | MikroTik | Linux")
    print(" Módulos Linux: ISP-Stack, WANGuard, BIRD, SmokePing, Zabbix, Grafana, BIND9")
    print("=" * 68)

    pasta = preparar_ambiente()
    print(f"[+] Pasta de saída: {pasta}")

    arquivo_lote = (sys.argv[1] if len(sys.argv) > 1
                    and os.path.isfile(sys.argv[1]) else None)
    todos_resultados = []
    inicio_geral = time.time()
    coleta_total = 0.0
    sessao = 0
    modos = []

    while True:
        sessao += 1
        if sessao > 1:
            print("\n" + "=" * 68)
            print(f" NOVA COLETA (sessão {sessao})")
            print("=" * 68)
        opcoes = configurar_sessao()
        modos.append(opcoes["nome_modo"])
        if DEBUG and not ARQUIVO_DEBUG:
            caminho = iniciar_debug(pasta)
            print(f"[+] Log de depuração: {os.path.basename(caminho)}")
        depurar("-", "sessao", f"inicio da sessao {sessao} "
                              f"(modo: {opcoes['nome_modo']}, "
                              f"protocolo: {opcoes['protocolo']}, "
                              f"usuario: {opcoes['usuario']})")

        resultados = []
        inicio = time.time()
        # Contabiliza somente o tempo de trabalho: varredura, detecção e
        # coleta. O tempo em que o programa aguarda o operador digitar um
        # alvo ou escolher no menu não é tempo de execução e distorceria
        # qualquer comparação entre coletas.
        tempo_coleta = [0.0]

        def executar(alvos):
            if not alvos:
                return
            marca = time.perf_counter()
            lista = alvos
            if opcoes["varredura"] == "fast":
                lista, mortos = varrer_icmp(lista)
                for ip, _ in mortos:
                    resultados.append(
                        (ip, False, "sem resposta ICMP (modo fast)", ip))
            if not lista:
                tempo_coleta[0] += time.perf_counter() - marca
                return
            print(f"\n[+] Coletando {len(lista)} alvo(s) com "
                  f"{opcoes['instancias']} instância(s) simultânea(s) ...\n")
            pendentes = processar_lote(
                lista, opcoes["instancias"], opcoes["usuario"],
                opcoes["senha"], opcoes["secoes"], opcoes["nome_modo"],
                opcoes["incluir_sensivel"], resultados, opcoes["protocolo"])
            processar_pendentes(
                pendentes, opcoes["usuario"], opcoes["senha"],
                opcoes["secoes"], opcoes["nome_modo"],
                opcoes["incluir_sensivel"], resultados, opcoes["protocolo"])
            tempo_coleta[0] += time.perf_counter() - marca

        if arquivo_lote:
            entradas = ler_ips(arquivo_lote)
            alvos = montar_alvos(entradas, opcoes["porta_padrao"])
            print(f"\n[+] Modo lote: {len(entradas)} entrada(s) de "
                  f"'{arquivo_lote}' -> {len(alvos)} alvo(s)")
            executar(alvos)
            acao = menu_fim_sessao()
        else:
            acao = None
            while acao is None:
                entrada = input(
                    "\nIP, IP:porta, CIDR (10.0.0.0/24) ou range "
                    "(10.0.0.1-100) — ENTER para o menu: "
                ).strip()
                if not entrada:
                    acao = menu_fim_sessao()
                    if acao == "continuar":
                        acao = None
                    continue
                executar(montar_alvos([entrada], opcoes["porta_padrao"]))

        imprimir_resumo(resultados, tempo_coleta[0],
                        f"RESUMO DA SESSÃO {sessao}" if sessao > 1
                        else "RESUMO", time.time() - inicio)
        todos_resultados.extend(resultados)
        coleta_total += tempo_coleta[0]

        if acao == "reconfigurar":
            # As credenciais da sessão anterior saem de escopo aqui.
            opcoes = None
            continue
        break

    if sessao > 1:
        imprimir_resumo(todos_resultados, coleta_total,
                        f"RESUMO GERAL ({sessao} sessões)",
                        time.time() - inicio_geral)

    indice = escrever_indice(todos_resultados,
                             " + ".join(dict.fromkeys(modos)), coleta_total)
    if indice:
        print(f"\nÍndice da coleta: {os.path.basename(indice)}")
    if DEBUG and ARQUIVO_DEBUG:
        depurar("-", "fim da execucao",
                f"{sessao} sessao(oes), "
                f"{len([r for r in todos_resultados if r[1] is True])} host(s), "
                f"coleta {coleta_total:.0f}s de "
                f"{time.time() - inicio_geral:.0f}s de sessao")
        print(f"Log de depuração: {os.path.basename(ARQUIVO_DEBUG)}")
    print(f"Arquivos Markdown em: {PASTA_SAIDA}")


if __name__ == "__main__":
    main()
