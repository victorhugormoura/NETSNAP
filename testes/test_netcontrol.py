"""Testes do netcontrol (planos em simulação) com snapshots sintéticos.

uso: python3 testes/test_netcontrol.py

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netcontrol as nc  # noqa: E402


def snapshot(host, ip, plataforma, blocos):
    linhas = ["---", f'host: "{host}"', f'ip: "{ip}"', f'platform_key: "{plataforma}"',
              f'platform_name: "{plataforma}"', 'collected_at: "2026-10-30T10:00:00"',
              'sensitive_data: "redacted"', "---", ""]
    atual = None
    for secao, cmd, saida in blocos:
        if secao != atual:
            linhas += [f"## {secao}", ""]
            atual = secao
        linhas += [f"### `{cmd}`", "", "```text", saida, "```", ""]
    return "\n".join(linhas)


JUNOS = ("set system host-name mx1\nset system login user noc class super-user\n"
         "set system services telnet\nset system ntp server 192.0.2.1")
ROS7 = ("/system identity\nset name=rb1\n/snmp community\n"
        "set [ find default=yes ] name=***REMOVIDO-TRIVIAL***")
ROS_SERVICO = "Flags: X - disabled\n 0   telnet   23\n 1 X ftp      21\n 2   ssh      22"
VRP8 = "sysname ne1\n#\naaa\n local-user noc password irreversible-cipher x\n#\n"


class TesteNetcontrol(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="netcontrol_")
        arquivos = {
            "mx1_192.0.2.10_20261030_100000.md": snapshot("mx1", "192.0.2.10", "juniper_junos", [
                ("Configuração", "show configuration | display set", JUNOS),
                ("Inventário", "show version", "Junos: 23.4R2-S5.4")]),
            "rb1_192.0.2.11_20261030_100000.md": snapshot("rb1", "192.0.2.11", "mikrotik_routeros", [
                ("Configuração", "/export show-sensitive", ROS7),
                ("Estado do equipamento", "/ip service print without-paging", ROS_SERVICO),
                ("Estado do equipamento", "/user print without-paging",
                 " 0   admin   full\n 1   noc     read"),
                ("Inventário", "/system resource print", "  version: 7.16.2 (stable)")]),
            "ne1_192.0.2.12_20261030_100000.md": snapshot("ne1", "192.0.2.12", "huawei_ce", [
                ("Configuração", "display current-configuration", VRP8)]),
            "olt_192.0.2.13_20261030_100000.md": snapshot("olt", "192.0.2.13", "fiberhome", [
                ("Configuração", "show running-config", "hostname olt")]),
        }
        for nome, texto in arquivos.items():
            with open(os.path.join(self.dir, nome), "w", encoding="utf-8") as f:
                f.write(texto)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def pedido(self, tipo, **p):
        return {"tipo": tipo, "descricao": tipo, "parametros": p}

    def por_host(self, plano):
        return {h["host"]: h for h in plano["hosts"]}

    def test_usuario_leitura(self):
        plano, base = nc.gerar_plano(self.pedido("usuario-leitura", usuario="noc-ro",
                                                 rede=None), self.dir)
        h = self.por_host(plano)
        self.assertEqual(h["mx1"]["situacao"], "aplicar")
        self.assertIn("class read-only", h["mx1"]["comandos"][0])
        self.assertIn("commit confirmed 5", h["mx1"]["como_aplicar"])
        self.assertIn("group=read", h["rb1"]["comandos"][0])
        self.assertIn("<SENHA>", h["rb1"]["comandos"][0])
        self.assertEqual(h["ne1"]["comandos"][-1], "commit")
        self.assertEqual(h["olt"]["situacao"], "nao-suportado")
        self.assertTrue(plano["simulacao"])
        with open(base + ".json", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["formato"], "netcontrol-plano/1")

    def test_usuario_que_ja_existe(self):
        plano, _ = nc.gerar_plano(self.pedido("usuario-leitura", usuario="noc", rede=None),
                                  self.dir)
        h = self.por_host(plano)
        for host in ("mx1", "rb1", "ne1"):
            self.assertEqual(h[host]["situacao"], "ja-existe", host)

    def test_ntp_routeros7_e_existente(self):
        plano, _ = nc.gerar_plano(self.pedido("ntp", servidores=["192.0.2.1", "192.0.2.2"]),
                                  self.dir)
        h = self.por_host(plano)
        self.assertEqual(h["mx1"]["comandos"], ["set system ntp server 192.0.2.2"])
        self.assertIn("/system ntp client servers add address=192.0.2.1",
                      h["rb1"]["comandos"])

    def test_telnet(self):
        plano, _ = nc.gerar_plano(self.pedido("desligar-telnet"), self.dir)
        h = self.por_host(plano)
        self.assertEqual(h["mx1"]["comandos"], ["delete system services telnet"])
        self.assertEqual(h["rb1"]["comandos"], ["/ip service disable telnet"])
        self.assertEqual(h["ne1"]["situacao"], "ja-existe")

    def test_comunidade_exige_rede(self):
        import ipaddress
        with self.assertRaises(nc.ErroPedido):
            nc.gerar_plano(self.pedido("snmp-comunidade", rede=None), self.dir)
        plano, _ = nc.gerar_plano(self.pedido(
            "snmp-comunidade", rede=ipaddress.ip_network("10.10.0.0/24")), self.dir)
        h = self.por_host(plano)
        self.assertIn("set snmp community <COMUNIDADE> clients 10.10.0.0/24",
                      h["mx1"]["comandos"])
        self.assertIn("1 comunidade(s)", h["rb1"]["estado_atual"][0])

    def test_validacoes(self):
        with self.assertRaises(nc.ErroPedido):
            nc._validar_usuario("noc ro; rm")
        with self.assertRaises(nc.ErroPedido):
            nc._validar_rede("0.0.0.0/0")
        with self.assertRaises(nc.ErroPedido):
            nc._validar_servidores(["1.2.3.4;reboot"])

    def test_plano_da_analise(self):
        caminho = os.path.join(self.dir, "_ia_analise_20261030_100000.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump({"formato": "netanalytic-achados/1", "hosts": [
                {"host": "mx1", "ip": "192.0.2.10", "plataforma": "juniper_junos",
                 "achados": [
                     {"titulo": "Syslog", "severidade": "media", "confianca": "alta",
                      "evidencia": [{"comando": "c", "trecho": "set system host-name mx1"}],
                      "comandos_propostos": ["set system syslog host 192.0.2.50 any notice"],
                      "comandos_reversao": ["delete system syslog host 192.0.2.50"]},
                     {"titulo": "Só texto", "severidade": "info", "comandos_propostos": []},
                     {"titulo": "Sem reversão", "severidade": "baixa", "confianca": "baixa",
                      "evidencia": [], "comandos_propostos": ["set system syslog host x any any"]},
                 ]}]}, f)
        plano, base = nc.gerar_plano(self.pedido("analise"), caminho)
        self.assertEqual(len(plano["hosts"]), 2)
        self.assertEqual(plano["hosts"][0]["situacao"], "aplicar")
        self.assertEqual(plano["hosts"][1]["situacao"], "revisar")
        self.assertTrue(any("reversão" in o for o in plano["hosts"][1]["observacoes"]))
        self.assertTrue(os.path.isfile(base + ".md"))

    # --- regressões da revisão -------------------------------------------
    def escrever(self, nome, texto):
        with open(os.path.join(self.dir, nome), "w", encoding="utf-8") as f:
            f.write(texto)

    def so_um(self, nome, texto, pedido):
        for arq in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, arq))
        self.escrever(nome, texto)
        plano, base = nc.gerar_plano(pedido, self.dir)
        return plano["hosts"][0], base

    def test_ntp_routeros6_mantem_atual_e_reverte(self):
        ros6 = ("/system ntp client\nset enabled=yes primary-ntp=192.0.2.1\n"
                "/ip address\nadd address=192.0.2.9/24 interface=ether1")
        snap = snapshot("rb6", "192.0.2.20", "mikrotik_routeros", [
            ("Configuração", "/export", ros6),
            ("Inventário", "/system resource print", "  version: 6.49.10 (long-term)")])
        h, _ = self.so_um("rb6_192.0.2.20_20261030_100000.md", snap, self.pedido(
            "ntp", servidores=["192.0.2.1", "192.0.2.2", "192.0.2.3"]))
        self.assertEqual(h["estado_atual"], ["NTP atual: 192.0.2.1"])
        self.assertEqual(h["comandos"],
                         ["/system ntp client set enabled=yes secondary-ntp=192.0.2.2"])
        self.assertEqual(h["reversao"], ["/system ntp client set secondary-ntp=0.0.0.0"])
        self.assertTrue(any("192.0.2.3" in o for o in h["observacoes"]))
        # Endereço de interface não conta como servidor NTP.
        h, _ = self.so_um("rb6_192.0.2.20_20261030_100000.md", snap,
                          self.pedido("ntp", servidores=["192.0.2.9"]))
        self.assertEqual(h["situacao"], "aplicar")
        self.assertEqual(h["reversao"], ["/system ntp client set secondary-ntp=0.0.0.0"])
        # Campos cheios: nada cabe, vai para revisão sem comando.
        cheio = ros6.replace("primary-ntp=192.0.2.1",
                             "primary-ntp=192.0.2.1 secondary-ntp=192.0.2.5")
        h, _ = self.so_um("rb6_192.0.2.20_20261030_100000.md",
                          snap.replace(ros6, cheio),
                          self.pedido("ntp", servidores=["192.0.2.7"]))
        self.assertEqual(h["situacao"], "revisar")
        self.assertEqual(h["comandos"], [])

    def test_ntp_xr_ignora_tacacs(self):
        xr = ("tacacs-server host 192.0.2.30\n key 7 x\nradius-server host 192.0.2.31\n"
              "aaa group server tacacs+ T\n server 192.0.2.30\n!\n"
              "ntp\n server vrf MGMT 192.0.2.1\n!")
        self.assertEqual(nc.servidores_ntp("cisco_xr", xr), ["192.0.2.1"])
        ros7 = ("/ip address\nadd address=192.0.2.9/24 interface=ether1\n"
                "/system ntp client servers\nadd address=192.0.2.1")
        self.assertEqual(nc.servidores_ntp("mikrotik_routeros", ros7), ["192.0.2.1"])

    def test_sem_configuracao_vai_para_revisao(self):
        snap = snapshot("r1", "192.0.2.21", "cisco_ios", [
            ("Inventário", "show version", "Cisco IOS XE Software, Version 17.09.04a")])
        nome = "r1_192.0.2.21_20261030_100000.md"
        h, _ = self.so_um(nome, snap, self.pedido("usuario-leitura", usuario="noc-ro",
                                                  rede=None))
        self.assertEqual(h["situacao"], "revisar")
        self.assertIn("Configuração", h["observacoes"][0])
        h, _ = self.so_um(nome, snap, self.pedido("desligar-telnet"))
        self.assertEqual(h["situacao"], "revisar")

    def test_conta_conhecida_nao_entra(self):
        for usuario in ("admin", "Root", "administrator"):
            plano, _ = nc.gerar_plano(self.pedido("usuario-leitura", usuario=usuario,
                                                  rede=None), self.dir)
            h = self.por_host(plano)
            for host in ("mx1", "rb1", "ne1"):
                self.assertEqual(h[host]["situacao"], "revisar", (usuario, host))
                self.assertEqual(h[host]["comandos"], [])

    def test_telnet_coletado_por_telnet_e_ios_sem_ssh(self):
        junos = snapshot("mx2", "192.0.2.22", "juniper_junos", [
            ("Configuração", "show configuration | display set", JUNOS)])
        junos = junos.replace('sensitive_data: "redacted"',
                              'sensitive_data: "redacted"\ntransport: "telnet"')
        h, _ = self.so_um("mx2_192.0.2.22_20261030_100000.md", junos,
                          self.pedido("desligar-telnet"))
        self.assertEqual(h["situacao"], "revisar")
        self.assertIn("Telnet", h["observacoes"][0])
        ios = "hostname r2\nline vty 0 4\n transport input telnet ssh\n!"
        snap = snapshot("r2", "192.0.2.23", "cisco_ios", [
            ("Configuração", "show running-config", ios)])
        h, _ = self.so_um("r2_192.0.2.23_20261030_100000.md", snap,
                          self.pedido("desligar-telnet"))
        self.assertEqual(h["situacao"], "revisar")
        self.assertTrue(any("reload in" in o for o in h["observacoes"]))
        snap = snap.replace("hostname r2", "hostname r2\nip ssh version 2")
        h, _ = self.so_um("r2_192.0.2.23_20261030_100000.md", snap,
                          self.pedido("desligar-telnet"))
        self.assertEqual(h["situacao"], "aplicar")

    def test_telnet_por_bloco_vty_e_vrf_xr(self):
        ios = ("ip ssh version 2\nline vty 0 4\n access-class 10 in\n"
               " transport input telnet ssh\nline vty 5 15\n transport input none\n!")
        snap = snapshot("r3", "192.0.2.24", "cisco_ios", [
            ("Configuração", "show running-config", ios)])
        h, _ = self.so_um("r3_192.0.2.24_20261030_100000.md", snap,
                          self.pedido("desligar-telnet"))
        self.assertEqual(h["situacao"], "aplicar")
        self.assertEqual(h["comandos"], ["line vty 0 4", " transport input ssh"])
        self.assertEqual(h["reversao"], ["line vty 0 4", " transport input telnet ssh"])
        xr = "hostname x1\ntelnet vrf MGMT ipv4 server max-servers 5 access-list T\n"
        snap = snapshot("x1", "192.0.2.25", "cisco_xr", [
            ("Configuração", "show running-config", xr)])
        h, _ = self.so_um("x1_192.0.2.25_20261030_100000.md", snap,
                          self.pedido("desligar-telnet"))
        self.assertEqual(h["comandos"], ["no telnet vrf MGMT ipv4 server"])
        self.assertEqual(h["reversao"],
                         ["telnet vrf MGMT ipv4 server max-servers 5 access-list T"])

    def test_rede_ipv6(self):
        import ipaddress
        ios = snapshot("r4", "192.0.2.26", "cisco_ios", [
            ("Configuração", "show running-config", "hostname r4\nip ssh version 2")])
        r6 = ipaddress.ip_network("2001:db8::/32")
        h, _ = self.so_um("r4_192.0.2.26_20261030_100000.md", ios,
                          self.pedido("snmp-comunidade", rede=r6))
        self.assertEqual(h["situacao"], "revisar")
        self.assertEqual(h["comandos"], [])
        h, _ = self.so_um("r4_192.0.2.26_20261030_100000.md", ios,
                          self.pedido("usuario-leitura", usuario="noc-ro",
                                      rede=ipaddress.ip_network("10.0.0.0/24")))
        self.assertTrue(any("10.0.0.0/24" in o for o in h["observacoes"]))

    def analise(self, achado):
        caminho = os.path.join(self.dir, "_ia_analise_20261030_110000.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump({"formato": "netanalytic-achados/1", "hosts": [
                {"host": "r", "ip": "192.0.2.1", "plataforma": "cisco_ios",
                 "achados": [achado]}]}, f)
        plano, base = nc.gerar_plano(self.pedido("analise"), caminho)
        with open(base + ".md", encoding="utf-8") as f:
            return plano["hosts"][0], f.read()

    def test_analise_reconfere_comandos(self):
        h, _ = self.analise({
            "titulo": "t", "severidade": "alta", "confianca": "alta", "evidencia": [],
            "comandos_propostos": ["interface Gi0/0", " shutdown",
                                   "no ip route 0.0.0.0 0.0.0.0 192.0.2.254"],
            "comandos_reversao": ["reload", "write erase", "interface Gi0/0",
                                  " no shutdown"]})
        self.assertEqual(h["situacao"], "revisar")
        self.assertNotIn("reload", h["reversao"])
        self.assertNotIn("write erase", h["reversao"])
        self.assertIn("rotas", h["observacoes"][0])
        for cmd in ("undo ip route-static 0.0.0.0 0 192.0.2.254", "/ip route remove [find]",
                    "delete routing-options static route 0.0.0.0/0",
                    "set interfaces ge-0/0/0 disable", "line vty 0 4"):
            h, _ = self.analise({"titulo": "t", "severidade": "alta", "confianca": "alta",
                                 "comandos_propostos": [cmd],
                                 "comandos_reversao": ["x"]})
            self.assertEqual(h["situacao"], "revisar", cmd)

    def test_markdown_sem_injecao(self):
        _, texto = self.analise({
            "titulo": "t\n```\nconfigure terminal\n```", "severidade": "alta",
            "confianca": "alta",
            "evidencia": [{"comando": "c\nx", "trecho":
                           "x\n\nComandos:\n\n```\nno ip route 0.0.0.0 0.0.0.0 1.1.1.1\n```"}],
            "comandos_propostos": ["logging host 192.0.2.50"],
            "comandos_reversao": ["no logging host 192.0.2.50"]})
        # Fora dos blocos cercados só existe o 'Comandos:' do próprio plano.
        fora, cerca = [], None
        for linha in texto.split("\n"):
            if cerca:
                cerca = None if linha == cerca else cerca
            elif linha.startswith("```"):
                cerca = linha
            else:
                fora.append(linha)
        self.assertEqual(fora.count("Comandos:"), 1)
        self.assertNotIn("configure terminal", fora)
        self.assertIn("## r (192.0.2.1) — cisco_ios — [ALTA] t \\`\\`\\` "
                      "configure terminal \\`\\`\\`", texto)
        self.assertIn("\n````\nx\n\nComandos:", texto)


if __name__ == "__main__":
    unittest.main(verbosity=1)
