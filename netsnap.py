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
Módulos de aplicação em Linux: WANGuard, Zabbix, Grafana e BIND9
(este último com verificação do bloqueio por RPZ ou por zona-sinkhole).

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT. Consulte o arquivo LICENSE.
"""

__version__ = "1.10.1"

import os
import re
import sys
import time
import json
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
DEBUG_LIMITE_AMOSTRA = 400   # caracteres de retorno registrados por comando


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
    """Compacta um retorno para registro no log, preservando o essencial."""
    t = PADRAO_ANSI.sub("", texto or "")
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
            "systemctl list-unit-files --type=service --state=enabled --no-pager",
            "systemctl list-units --type=service --state=running --no-pager",
            "systemctl list-timers --all --no-pager",
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
            "(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | head -n 400",
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
    # Credenciais do Wanguard 9: host e senha ficam em arquivos separados,
    # cada um contendo apenas o valor. O usuário e o banco chamam-se
    # 'andrisoft' por padrão; o banco é confirmado com SHOW DATABASES.
    "WH=$({S}cat /opt/andrisoft/etc/dbhost.conf 2>/dev/null | tr -d ' \\r\\n'); "
    "WP=$({S}cat /opt/andrisoft/etc/dbpass.conf 2>/dev/null | tr -d ' \\r\\n'); "
    "WU=andrisoft; "
    "WD=$(MYSQL_PWD=\"$WP\" mysql -h \"${WH:-localhost}\" -u \"$WU\" -N -B "
    "-e 'SHOW DATABASES' 2>/dev/null | grep -i -m1 -E 'andrisoft|wanguard'); "
    "W(){ if [ -z \"$WP\" ]; then echo '(credenciais do banco inacessiveis "
    "- requer sudo)'; elif ! command -v mysql >/dev/null 2>&1; then "
    "echo '(cliente mysql ausente no servidor)'; "
    "elif [ -z \"$WD\" ]; then echo '(banco do Wanguard nao localizado)'; "
    "else MYSQL_PWD=\"$WP\" mysql -h \"${WH:-localhost}\" -u \"$WU\" "
    "-D \"$WD\" -B -e \"$1\" 2>&1; fi; }; "
    # WT(): despeja uma tabela excluindo colunas cujo nome indique segredo.
    # Necessário porque a saída do mysql é tabular: um valor sob a coluna
    # 'password' não seria detectado pelo sanitizador, que procura par
    # chave=valor. A exclusão é feita na origem, pela lista de colunas.
    "WT(){ C=$(W \"DESCRIBE \\`$1\\`\" 2>/dev/null | tail -n +2 | "
    "awk '{print $1}' | grep -v -i -E "
    "'pass|secret|_key$|^key$|token|community|credential|hash|salt|"
    "^license$|^prev_license$' | "
    "sed 's/^/`/;s/$/`/' | paste -sd, -); "
    "[ -z \"$C\" ] && { echo \"(tabela $1 inacessivel)\"; return; }; "
    "W \"SELECT $C FROM \\`$1\\` ${2:-LIMIT 50}\"; }; "
    "echo \"banco: ${WD:-nao identificado} em ${WH:-localhost}\""
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
        # A partir do Wanguard 9 a configuração operacional fica no MariaDB.
        # As tabelas abaixo foram confirmadas em uma instalação 9.0-3; as que
        # não existirem em outra versão são marcadas e não poluem o relatório.
        # Tabelas de autenticação (company_staff, httpauth, ldapauth,
        # radiusauth, samlauth) são deliberadamente omitidas por conterem
        # credenciais de operador.
        "extra": {
            "titulo": "Configuração operacional no banco (componentes, "
                      "zonas de IP, respostas, ataques e licença)",
            "comandos": [
                DEF_Q_WANGUARD,
                # Identificação e licença. A coluna 'license' guarda a
                # chave em base64 (segredo do contrato) e não é despejada:
                # só os metadados que interessam ao inventário.
                "WT version",
                "W \"SELECT id, filename, update_time, "
                "LENGTH(license) AS tamanho_chave, "
                "CASE WHEN license IS NULL OR license='' THEN 'ausente' "
                "ELSE 'presente' END AS chave FROM license\"",
                # Componentes: cada linha é um sensor/filtro configurado
                "for t in wanserver wansensor wansensor_virtual wanflow "
                "wansniff wansnmp wanfilter wanconsole wanwatcher; do "
                "echo \"===== $t\"; WT $t; done",
                # Interfaces monitoradas por componente
                "for t in wanserver_interfaces wanflow_interfaces "
                "wansnmp_interfaces; do echo \"===== $t\"; WT $t; done",
                # Zonas de IP, prefixos monitorados e regras por prefixo
                "for t in ipaddr ipaddrdesc ipaddrrules; do "
                "echo \"===== $t\"; WT $t \"LIMIT 300\"; done",
                # Perfis de detecção de anomalia e limiares
                "for t in anomalies templates templatesrules "
                "profiling_templates profiling_templatesrules "
                "profiling_ipaddrrules baseline_profiles; do "
                "echo \"===== $t\"; WT $t \"LIMIT 200\"; done",
                # Respostas automáticas: o que o WANGuard faz ao detectar
                "for t in actions actions_bgp actions_filters "
                "actions_reconfigure actions_snmp actions_syslog "
                "actions_notify actions_webhook actions_reports "
                "actions_scripts actions_dumps; do echo \"===== $t\"; "
                "WT $t \"LIMIT 100\"; done",
                # Roteadores e BGP usados para blackhole/flowspec
                "for t in router quagga scrubber_tunnels "
                "scrubber_tunnel_settings; do echo \"===== $t\"; WT $t; done",
                # Exceções, listas brancas e regras de filtragem
                "for t in whitelists exceptions blacklist_settings "
                "blacklist_ds fr_settings fr_list fw_custom_fr; do "
                "echo \"===== $t\"; WT $t \"LIMIT 200\"; done",
                # Mitigação em vigor neste instante
                "echo '===== active_fw_rules (mitigacao ativa agora)'; "
                "WT active_fw_rules \"LIMIT 200\"",
                # Histórico recente de ataques — o que de fato aconteceu
                "echo '===== attacks (30 mais recentes)'; "
                "WT attacks \"ORDER BY 1 DESC LIMIT 30\"",
                "echo '===== attacks_logs (60 mais recentes)'; "
                "WT attacks_logs \"ORDER BY 1 DESC LIMIT 60\"",
                # Volume das tabelas de séries temporais, sem despejá-las
                "W \"SELECT table_name, table_rows, "
                "ROUND(data_length/1024/1024) AS mb FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name NOT LIKE 'acct%' ORDER BY data_length DESC "
                "LIMIT 40\"",
                # Contagem das tabelas de accounting diário, que são milhares
                "W \"SELECT COUNT(*) AS tabelas_de_accounting FROM "
                "information_schema.tables WHERE table_schema=DATABASE() "
                "AND table_name LIKE 'acct%'\"",
                # Demais tabelas existentes, para diagnóstico de versão
                "W \"SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=DATABASE() AND table_name NOT LIKE 'acct%' "
                "ORDER BY table_name\"",
                # Agendamentos, relatórios e saúde
                "for t in schedule_reports wanhealth_check maintenance "
                "defaults; do echo \"===== $t\"; WT $t \"LIMIT 100\"; done",
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
            "{S}ss -tulpn 2>/dev/null | grep -E ':10050|:10051|:80|:443'",
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
            "{S}ss -tulpn 2>/dev/null | grep -E ':3000|:3001'",
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
    r"authentication-key|auth-key|key-string|hello-password|md5|cipher|"
    r"irreversible-cipher|shared-secret|wpa2?-pre-shared-key|private-key|"
    r"community|dbpass|db_pass|api[_-]?key|access[_-]?key|auth[_-]?token|token"
)
PADROES_SENSIVEIS = [
    # chave=valor, chave: valor, chave "valor" e chave valor (mesma linha).
    # O trecho ["']?\]?["']? cobre formatos como $DB['PASSWORD'] = '...'
    # (frontend PHP do Zabbix) e "password": "..." (JSON/YAML).
    re.compile(r"(?i)((?:" + _CHAVES + r")[\"']?\]?[\"']?[ \t]*[:=][ \t]*)"
               r"([^\s;,]+)"),
    re.compile(r"(?i)((?:" + _CHAVES + r")[ \t]+)(?![=:])([^\s;,]+)"),
    re.compile(r"(?i)(snmp(?:-server|-agent)?[ \t]+community[ \t]+"
               r"(?:read[ \t]+|write[ \t]+)?)(\S+)"),
    re.compile(r"(ssh-(?:rsa|ed25519|dss)[ \t]+)(\S+)"),
]
PADRAO_CERT = re.compile(r"-----BEGIN[\s\S]*?-----END[^-]*-----")

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
    for padrao in PADROES_SENSIVEIS:
        texto = padrao.sub(r"\1***REMOVIDO***", texto)
    return texto


PADRAO_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def nome_seguro(texto: str) -> str:
    """Normaliza um hostname para uso em nome de arquivo (Windows e Linux):
    remove códigos ANSI e substitui caracteres proibidos (: ~ / \\ etc.)."""
    texto = PADRAO_ANSI.sub("", texto)
    texto = re.sub(r"[^A-Za-z0-9._-]", "_", texto)
    texto = re.sub(r"_+", "_", texto).strip("_.")
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
    r"does not exist|unknown parameter|bad command name)"
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
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout_s + 2)
        return r.returncode == 0
    except Exception:
        return False


def varrer_icmp(alvos, paralelo: int = 64):
    """Executa ping em todos os alvos em paralelo. Retorna (vivos, mortos)."""
    vivos, mortos = [], []
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


def ler_banner(ip: str, porta: int, tempo: int = 4):
    """Lê a linha de identificação do servidor SSH sem autenticar.
    Retorna o banner, ou None se a porta não responder."""
    try:
        with socket.create_connection((ip, porta), timeout=tempo) as s:
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


def plataforma_por_banner(banner: str):
    """Retorna (lista de candidatos, confianca) a partir do banner."""
    if not banner:
        return [], None
    for padrao, candidatos, confianca in BANNER_PLATAFORMA:
        if padrao.search(banner):
            return list(candidatos), confianca
    return [], None


def confirmar_plataforma(ip, usuario, senha, porta, tipo) -> bool:
    """Confirma um palpite do banner com uma única conexão e um comando."""
    verificacao = {
        "linux": ("uname -s", r"Linux"),
        "mikrotik_routeros": ("/system resource print", r"(?i)routeros|mikrotik"),
        "juniper_junos": ("show version", r"(?i)junos"),
        "cisco_ios": ("show version", r"(?i)cisco ios"),
        "cisco_xr": ("show version", r"(?i)ios xr"),
        "huawei": ("display version", r"(?i)huawei|VRP"),
        "huawei_ce": ("display version", r"(?i)huawei|VRP"),
    }
    if tipo not in verificacao:
        return False
    cmd, esperado = verificacao[tipo]
    perfil = PERFIS[tipo]
    try:
        with ConnectHandler(device_type=perfil.get("driver", tipo), host=ip,
                            username=usuario, password=senha, port=porta,
                            timeout=25, conn_timeout=12) as conn:
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


def classificar_huawei(ip, usuario, senha, porta) -> str:
    """Determina a família Huawei a partir de 'display version'.

    Três linhas com sintaxes distintas compartilham o driver 'huawei' do
    Netmiko e precisam de perfis próprios:
      huawei         VRP V5, linha campus (S5700/S6720/S6730/S9700)
      huawei_ce      VRP V8, CloudEngine (CE6800/CE6860/CE8800) e NE
      huawei_smartax SmartAX (OLT MA5600/MA5800)
    Uma única conexão decide entre as três."""
    try:
        with ConnectHandler(device_type="huawei", host=ip, username=usuario,
                            password=senha, port=porta, timeout=25,
                            conn_timeout=12) as conn:
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


def eh_linux(ip, usuario, senha, porta) -> bool:
    try:
        with ConnectHandler(device_type="linux", host=ip, username=usuario,
                            password=senha, port=porta, timeout=20,
                            conn_timeout=12) as conn:
            saida = conn.send_command("uname -s", read_timeout=15)
        return "Linux" in saida
    except Exception:
        return False


def detectar(ip, usuario, senha, porta):
    """Identifica a plataforma via SSH.

    Estratégia em três níveis, do mais barato ao mais caro:
      1. banner SSH (uma conexão TCP, sem autenticação) — resolve sozinho os
         casos inequívocos e sugere um candidato nos demais;
      2. confirmação do candidato com uma conexão e um comando;
      3. SSHDetect do Netmiko, que testa comandos de vários fabricantes.

    Levanta NaoIdentificado quando o host responde mas não é reconhecido;
    levanta exceção de conexão/autenticação nos demais casos."""
    t0 = time.perf_counter()
    banner = ler_banner(ip, porta)
    if banner is None:
        depurar(ip, "banner", f"sem resposta TCP em {porta}")
        raise NetmikoTimeoutException(f"sem resposta TCP na porta {porta}")
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
def executar_comando(conn, cmd, usa_timing, ip="-", limite=None):
    """Executa um comando de leitura e registra tempo e retorno no debug."""
    t0 = time.perf_counter()
    depurar(ip, "envia comando", cmd)
    try:
        if usa_timing:
            saida = conn.send_command_timing(cmd, read_timeout=180, last_read=3)
        else:
            saida = conn.send_command(cmd, read_timeout=180)
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


def coletar(ip, porta, tipo, usuario, senha, secoes, nome_modo, incluir_sensivel):
    perfil = PERFIS[tipo]
    dispositivo = {
        "device_type": perfil.get("driver", tipo),
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

    log(ip, f"conectando ({perfil['nome']}) ...")
    if perfil.get("contexto"):
        log(ip, "plataforma exige contexto privilegiado; apenas comandos "
                "de leitura serão executados")

    with ConnectHandler(**dispositivo) as conn:
        hostname = conn.find_prompt().strip("<>[]#>$ ").replace("/", "_") or ip
        hostname = hostname.split("@")[-1]  # Junos/Linux: usuario@host -> host

        # Comandos preparatórios: paginação e contexto. Falhas são ignoradas.
        for cmd in perfil.get("prep", []):
            try:
                saida = conn.send_command_timing(cmd, read_timeout=20)
                if saida and re.search(r"(?i)password|senha", saida[-120:]):
                    saida = conn.send_command_timing(senha, read_timeout=20)
                contexto_usado = True
            except Exception:
                pass

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
            saidas = []
            for cmd in comandos:
                log(ip, f"-> {cmd[:70]}")
                saidas.append((cmd, executar_comando(conn, cmd, usa_timing,
                                                     ip, limite)))
            blocos.append((TITULOS[secao], saidas))

        # Módulos de aplicação (Linux)
        for chave in apps_detectados:
            app = APPS_LINUX[chave]
            for secao in secoes:
                comandos = [c.replace("{S}", prefixo_sudo)
                            for c in app.get(secao, [])]
                if not comandos:
                    continue
                limite = LIMITE_POR_SECAO.get(secao)
                saidas = []
                for cmd in comandos:
                    log(ip, f"-> [{chave}] {cmd[:70]}")
                    saidas.append((cmd, executar_comando(conn, cmd, False,
                                                         ip, limite)))
                blocos.append((f"{app['nome']} — {TITULOS[secao]}", saidas))
            extra = app.get("extra")
            if extra and set(secoes) & {"config", "basico", "inventario"}:
                saidas = []
                for cmd in [c.replace("{S}", prefixo_sudo)
                            for c in extra["comandos"]]:
                    log(ip, f"-> [{chave}] {cmd[:70]}")
                    saidas.append((cmd, executar_comando(conn, cmd, False, ip)))
                blocos.append((f"{app['nome']} — {extra['titulo']}", saidas))

        for cmd in perfil.get("sair", []):
            try:
                conn.send_command_timing(cmd, read_timeout=10)
            except Exception:
                pass

    arquivo = escrever_relatorio(
        ip, hostname, tipo, perfil, blocos, nome_modo, secoes,
        incluir_sensivel, apps_detectados, contexto_usado,
    )
    return arquivo, hostname


def escrever_relatorio(ip, hostname, tipo, perfil, blocos, nome_modo, secoes,
                       incluir_sensivel, apps, contexto_usado):
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

    arquivo = os.path.join(
        PASTA_SAIDA, f"{hostname}_{ip}_{agora:%Y%m%d_%H%M%S}.md"
    )
    with open(arquivo, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return arquivo


def escrever_indice(resultados, nome_modo, inicio):
    """Gera um índice consolidado da execução, útil para ingestão em lote."""
    agora = datetime.now()
    ok = [r for r in resultados if r[1] is True]
    if not ok:
        return None
    md = ["---",
          f"netsnap_version: {json.dumps(__version__)}",
          f"document_type: {json.dumps('run_index')}",
          f"generated_at: {json.dumps(agora.isoformat(timespec='seconds'))}",
          f"extraction_mode: {json.dumps(nome_modo)}",
          f"hosts_collected: {len(ok)}",
          "---\n",
          f"# Índice da coleta — {agora:%d/%m/%Y %H:%M:%S}\n",
          f"Modo de extração: **{nome_modo}** · duração: "
          f"{time.time() - inicio:.0f}s · hosts coletados: **{len(ok)}**\n",
          "Cada arquivo listado abaixo é um snapshot independente, com "
          "metadados YAML próprios.\n",
          "| Host | IP | Arquivo |", "|---|---|---|"]
    for ip, _, arq, host in [(r[0], r[1], r[2], r[3]) for r in ok]:
        md.append(f"| {host} | {ip} | `{os.path.basename(arq)}` |")
    falhas = [r for r in resultados if r[1] is False]
    if falhas:
        md.append("\n## Hosts não coletados\n")
        md.append("| IP | Motivo |")
        md.append("|---|---|")
        for ip, _, motivo, _ in falhas:
            md.append(f"| {ip} | {str(motivo)[:120]} |")
    caminho = os.path.join(PASTA_SAIDA, f"_indice_{agora:%Y%m%d_%H%M%S}.md")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return caminho


# ---------------------------------------------------------------------------
# Expansão de entradas: IP, IP:porta, CIDR e range
# ---------------------------------------------------------------------------
def ler_ips(caminho):
    with open(caminho, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]


def expandir_entrada(entrada: str, porta_padrao: int):
    """Expande uma entrada em lista de (ip, porta). Formatos aceitos:
    10.0.0.5 | 10.0.0.5:2222 | 10.0.0.0/24 | 10.0.0.0/24:2222 |
    10.0.0.1-10.0.0.100 | 10.0.0.1-100"""
    entrada = entrada.strip()
    porta = porta_padrao
    if ":" in entrada and entrada.rsplit(":", 1)[1].isdigit():
        entrada, p = entrada.rsplit(":", 1)
        porta = int(p)

    alvos = []
    try:
        if "/" in entrada:
            rede = ipaddress.ip_network(entrada, strict=False)
            if rede.num_addresses <= 2:
                alvos = [str(rede.network_address)]
            else:
                alvos = [str(h) for h in rede.hosts()]
        elif "-" in entrada:
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
            ipaddress.ip_address(entrada)
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
                   nome_modo, incluir_sensivel, resultados):
    """Fase paralela: detecta e coleta os hosts identificados automaticamente.
    Retorna a lista de pendentes (acessíveis, porém não identificados)."""
    pendentes = []
    trava = threading.Lock()

    def trabalho(ip, porta):
        try:
            depurar(ip, "inicio", f"porta {porta}")
            tipo = detectar(ip, usuario, senha, porta)
            arq, host = coletar(ip, porta, tipo, usuario, senha, secoes,
                                nome_modo, incluir_sensivel)
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
                        nome_modo, incluir_sensivel, resultados):
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
                                nome_modo, incluir_sensivel)
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
    print("  1) Nova coleta — reconfigurar tudo (inclusive usuário e senha)")
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
    varredura = escolher_varredura()
    instancias = escolher_instancias()

    usuario = input("\nUsuário SSH: ").strip()
    senha = getpass.getpass("Senha SSH: ")
    porta_txt = input("Porta SSH [22]: ").strip()
    porta_padrao = int(porta_txt) if porta_txt.isdigit() else 22

    return {
        "secoes": secoes, "nome_modo": nome_modo,
        "incluir_sensivel": incluir_sensivel, "varredura": varredura,
        "instancias": instancias, "usuario": usuario, "senha": senha,
        "porta_padrao": porta_padrao,
    }


def imprimir_resumo(resultados, duracao, titulo="RESUMO"):
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
          + f"  |  Tempo: {duracao:.0f}s")
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
    print(" Módulos Linux: WANGuard, Zabbix, Grafana, BIND9 (RPZ/AnaBlock)")
    print("=" * 68)

    pasta = preparar_ambiente()
    print(f"[+] Pasta de saída: {pasta}")

    arquivo_lote = (sys.argv[1] if len(sys.argv) > 1
                    and os.path.isfile(sys.argv[1]) else None)
    todos_resultados = []
    inicio_geral = time.time()
    sessao = 0

    while True:
        sessao += 1
        if sessao > 1:
            print("\n" + "=" * 68)
            print(f" NOVA COLETA (sessão {sessao})")
            print("=" * 68)
        opcoes = configurar_sessao()
        if DEBUG and not ARQUIVO_DEBUG:
            caminho = iniciar_debug(pasta)
            print(f"[+] Log de depuração: {os.path.basename(caminho)}")
        depurar("-", "sessao", f"inicio da sessao {sessao} "
                              f"(modo: {opcoes['nome_modo']}, "
                              f"usuario: {opcoes['usuario']})")

        resultados = []
        inicio = time.time()

        def executar(alvos):
            if not alvos:
                return
            lista = alvos
            if opcoes["varredura"] == "fast":
                lista, mortos = varrer_icmp(lista)
                for ip, _ in mortos:
                    resultados.append(
                        (ip, False, "sem resposta ICMP (modo fast)", ip))
            if not lista:
                return
            print(f"\n[+] Coletando {len(lista)} alvo(s) com "
                  f"{opcoes['instancias']} instância(s) simultânea(s) ...\n")
            pendentes = processar_lote(
                lista, opcoes["instancias"], opcoes["usuario"],
                opcoes["senha"], opcoes["secoes"], opcoes["nome_modo"],
                opcoes["incluir_sensivel"], resultados)
            processar_pendentes(
                pendentes, opcoes["usuario"], opcoes["senha"],
                opcoes["secoes"], opcoes["nome_modo"],
                opcoes["incluir_sensivel"], resultados)

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

        imprimir_resumo(resultados, time.time() - inicio,
                        f"RESUMO DA SESSÃO {sessao}" if sessao > 1
                        else "RESUMO")
        todos_resultados.extend(resultados)

        if acao == "reconfigurar":
            # As credenciais da sessão anterior saem de escopo aqui.
            opcoes = None
            continue
        break

    if sessao > 1:
        imprimir_resumo(todos_resultados, time.time() - inicio_geral,
                        f"RESUMO GERAL ({sessao} sessões)")

    indice = escrever_indice(todos_resultados, "sessões combinadas"
                             if sessao > 1 else "coleta", inicio_geral)
    if indice:
        print(f"\nÍndice da coleta: {os.path.basename(indice)}")
    if DEBUG and ARQUIVO_DEBUG:
        depurar("-", "fim da execucao",
                f"{sessao} sessao(oes), "
                f"{len([r for r in todos_resultados if r[1] is True])} host(s)")
        print(f"Log de depuração: {os.path.basename(ARQUIVO_DEBUG)}")
    print(f"Arquivos Markdown em: {PASTA_SAIDA}")


if __name__ == "__main__":
    main()
