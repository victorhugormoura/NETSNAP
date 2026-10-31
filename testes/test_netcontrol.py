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
                     {"titulo": "Telnet", "severidade": "alta", "confianca": "alta",
                      "evidencia": [{"comando": "c", "trecho": "set system services telnet"}],
                      "comandos_propostos": ["delete system services telnet"],
                      "comandos_reversao": ["set system services telnet"]},
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
