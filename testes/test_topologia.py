"""Testes do netsnap_topologia com snapshots sintéticos no formato do netsnap.

uso: python3 testes/test_topologia.py

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netsnap_topologia as t  # noqa: E402

def snapshot(pasta, host, ip, plataforma, secoes, quando="2026-10-10T10:00:00"):
    linhas = ["---", 'netsnap_version: "1.16.0"', f'host: "{host}"', f'ip: "{ip}"',
              f'platform_key: "{plataforma}"', f'platform_name: "{plataforma}"',
              f'collected_at: "{quando}"', "---", "", f"# Snapshot — {host} ({ip})", ""]
    titulos = {"config": "Configuração", "vizinhanca": "Vizinhança L2", "optica": "Interfaces e ópticas"}
    for chave, comandos in secoes.items():
        linhas += ["", f"## {titulos[chave]}", ""]
        for cmd, out in comandos:
            linhas += [f"### `{cmd}`", "", "```text", out.rstrip(), "```", ""]
    nome = f"{host}_{ip}_{quando.replace(':','').replace('-','')}.md"
    with open(os.path.join(pasta, nome), "w", encoding="utf-8") as f:
        f.write("\n".join(linhas))

JUNOS_DETALHE_A = """
LLDP Neighbor Information:
Local Information:
Index: 3 Time to live: 120 Time mark: Fri Oct 10 10:00:00 2026 Age: 12 secs
Local Interface    : et-0/0/2
Parent Interface   : ae1
Local Port ID      : 532
Ageout Count       : 0

Neighbour Information:
Chassis type       : Mac address
Chassis ID         : 78:4f:9b:00:00:02
Port type          : Locally assigned
Port ID            : 517
Port description   : BACKBONE-PARA-MX-A
System name        : MX-B

System Description : Juniper Networks, Inc. mx204 internet router

Management Info
Type              : IPv4
Address           : 10.0.0.2
"""
JUNOS_DETALHE_B = """
LLDP Neighbor Information:
Local Information:
Index: 9 Time to live: 120 Time mark: Fri Oct 10 10:00:00 2026 Age: 5 secs
Local Interface    : xe-0/1/0
Parent Interface   : ae1
Local Port ID      : 517
Ageout Count       : 0

Neighbour Information:
Chassis type       : Mac address
Chassis ID         : 78:4f:9b:00:00:01
Port type          : Locally assigned
Port ID            : 532
Port description   : et-0/0/2
System name        : MX-A.exemplo.net.br
"""
DESCR_B = """Interface       Admin Link Description
xe-0/1/0        up    up   BACKBONE-PARA-MX-A
xe-0/1/1        up    up   TRANSITO
"""
CONF_A = "set system host-name MX-A\nset interfaces ae1 unit 0 family inet address 10.255.0.0/31\nset interfaces ae1 unit 0 family inet6 address 2001:db8::/127\nset interfaces lo0 unit 0 family inet address 10.0.0.1/32\nset interfaces xe-0/0/9 unit 0 family inet address 192.0.2.1/24\n"
CONF_B = "set system host-name MX-B\nset interfaces ae1 unit 0 family inet address 10.255.0.1/31\nset interfaces ae1 unit 0 family inet6 address 2001:db8::1/127\nset interfaces xe-0/0/9 unit 0 family inet address 192.0.2.2/24\n"
HUAWEI_CONF = "#\nsysname SW-C\n#\ninterface Vlanif30\n ip address 10.30.0.2 255.255.255.252\n#\ninterface XGigabitEthernet0/0/1\n ipv6 address 2001:db8:30::2/126\n#\n"
MK_EXPORT = "/system identity\nset name=RB-D\n/ip address\nadd address=10.30.0.1/30 interface=\\\n    vlan30-core network=10.30.0.0\nadd address=10.40.0.1/30 disabled=yes interface=ether9 network=10.40.0.0\n/ipv6 address\nadd address=2001:db8:30::1/126 interface=vlan30-core\n"

LLDPD = """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eno1, via: LLDP, RID: 1, Time: 0 day, 00:10:00
  Chassis:
    ChassisID:    mac 78:4f:9b:00:00:09
    SysName:      SW-CORE
    MgmtIP:       10.0.0.9
  Port:
    PortID:       ifname XGigabitEthernet0/0/7
    PortDescr:    SERVIDOR-DNS
-------------------------------------------------------------------------------
"""

class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_porta_canonica(self):
        c = t.porta_canonica
        self.assertEqual(c("XGE0/0/3"), c("XGigabitEthernet0/0/3"))
        self.assertEqual(c("Gi0/1"), c("GigabitEthernet0/1"))
        self.assertEqual(c("xe-0/0/0.0"), c("xe-0/0/0"))
        self.assertEqual(c("100GE0/0/1"), c("100GE 0/0/1"))
        self.assertNotEqual(c("team0"), c("te0"))
        self.assertEqual(c("Te0/1/0"), c("TenGigabitEthernet0/1/0"))

    def test_junos_detalhe(self):
        vs = t.vizinhos_do_comando("show lldp neighbors detail", JUNOS_DETALHE_A)
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertEqual(v["porta_local"], "et-0/0/2")
        self.assertEqual(v["dispositivo"], "MX-B")
        self.assertEqual(v["porta_remota"], "BACKBONE-PARA-MX-A")  # índice SNMP -> descrição
        self.assertIn("517", v["portas_alt"])
        self.assertEqual(v["ip_gerencia"], "10.0.0.2")

    def test_junos_confirmado_por_descricao_e_fqdn(self):
        snapshot(self.d, "MX-A", "10.0.0.1", "juniper_junos", {
            "config": [("show configuration | display set", CONF_A)],
            "vizinhanca": [("show lldp neighbors detail", JUNOS_DETALHE_A)]})
        snapshot(self.d, "MX-B", "10.0.0.2", "juniper_junos", {
            "config": [("show configuration | display set", CONF_B)],
            "optica": [("show interfaces descriptions", DESCR_B)],
            "vizinhanca": [("show lldp neighbors detail", JUNOS_DETALHE_B)]})
        g = t.construir(self.d)
        lldp = [e for e in g["enlaces"] if e["tipo"] == "lldp"]
        self.assertEqual(len(lldp), 1, lldp)
        e = lldp[0]
        self.assertTrue(e["confirmado"])
        self.assertEqual({e["porta_a"], e["porta_b"]}, {"et-0/0/2", "xe-0/1/0"})
        l3 = [e for e in g["enlaces"] if e["tipo"] == "l3"]
        self.assertEqual(len(l3), 1, l3)   # /31 v4 e /127 v6 na mesma interface; /24 e /32 fora
        self.assertEqual(l3[0]["rede"], "10.255.0.0/31")
        self.assertEqual(len([n for n in g["nos"] if n["coletado"]]), 2)

    def test_l3_huawei_mikrotik(self):
        snapshot(self.d, "SW-C", "10.30.0.2", "huawei", {"config": [("display current-configuration", HUAWEI_CONF)]})
        snapshot(self.d, "RB-D", "10.30.0.1", "mikrotik_routeros", {"config": [("/export", MK_EXPORT)]})
        g = t.construir(self.d)
        l3 = [e for e in g["enlaces"] if e["tipo"] == "l3"]
        pares = sorted((e["porta_a"], e["porta_b"]) for e in l3)
        self.assertEqual(len(l3), 2, l3)   # Vlanif30<->vlan30-core e XGE0/0/1<->vlan30-core (v6)
        self.assertIn(("vlan30-core", "Vlanif30"), [(a, b) for a, b in pares] + [(b, a) for a, b in pares])

    def test_mesmo_roteador_varios_ips(self):
        for ip in ("198.51.100.1", "198.51.100.9", "198.51.100.17"):
            snapshot(self.d, "MX204-BGP-CENTRO", ip, "juniper_junos",
                     {"config": [("show configuration | display set", "set system host-name MX204-BGP-CENTRO\n")]})
        snapshot(self.d, "MikroTik", "10.1.1.1", "mikrotik_routeros", {"config": [("/export", "/system identity\nset name=MikroTik\n")]})
        snapshot(self.d, "MikroTik", "10.1.1.2", "mikrotik_routeros", {"config": [("/export", "/system identity\nset name=MikroTik\n")]})
        g = t.construir(self.d)
        col = [n for n in g["nos"] if n["coletado"]]
        self.assertEqual(len(col), 3)
        mx = [n for n in col if n["rotulo"] == "MX204-BGP-CENTRO"][0]
        self.assertEqual(len(mx["ips"]), 3)

    def test_diagnostico(self):
        d = t.diagnosticar_vizinhanca("juniper_junos", [("show lldp neighbors", ""), ("show lldp", "LLDP                      : Disabled\n")])
        self.assertEqual(d["estado"], "desligado")
        self.assertIn("set protocols lldp interface all", d["como_ativar"]["comandos"])
        d = t.diagnosticar_vizinhanca("juniper_junos", [("show lldp neighbors detail", JUNOS_DETALHE_A)])
        self.assertEqual((d["estado"], d["vizinhos"]), ("ok", 1))
        d = t.diagnosticar_vizinhanca("mikrotik_routeros", [("/ip neighbor print detail without-paging", ""),
                                                          ("/ip neighbor discovery-settings print", "  discover-interface-list: none\n                 protocol: cdp,lldp,mndp\n")])
        self.assertEqual(d["estado"], "desligado")
        d = t.diagnosticar_vizinhanca("huawei", [("display lldp neighbor brief", "")])
        self.assertEqual(d["estado"], "sem_vizinhos")
        d = t.diagnosticar_vizinhanca("linux", [("lldpcli show neighbors detail", "bash: lldpcli: command not found")])
        self.assertEqual(d["estado"], "desligado")

    def test_lldpd_com_sudo(self):
        # O netsnap grava o comando do Linux com o prefixo do sudo.
        for cmd in ("sudo -n lldpcli show neighbors detail", "sudo -n lldpctl", "lldpctl"):
            vs = t.vizinhos_do_comando(cmd, LLDPD)
            self.assertEqual([(v["porta_local"], v["dispositivo"]) for v in vs],
                             [("eno1", "SW-CORE")], cmd)
        d = t.diagnosticar_vizinhanca("linux", [("sudo -n lldpcli show neighbors detail", LLDPD),
                                                ("sudo -n lldpctl", LLDPD)])
        self.assertEqual((d["estado"], d["vizinhos"]), ("ok", 1))
        snapshot(self.d, "dns1", "10.0.0.53", "linux", {
            "vizinhanca": [("sudo -n lldpcli show neighbors detail", LLDPD),
                           ("sudo -n lldpctl", LLDPD)]})
        g = t.construir(self.d)
        lldp = [e for e in g["enlaces"] if e["tipo"] == "lldp"]
        self.assertEqual(len(lldp), 1, lldp)
        self.assertEqual(lldp[0]["porta_b"], "XGigabitEthernet0/0/7")

if __name__ == "__main__":
    unittest.main(verbosity=1)
