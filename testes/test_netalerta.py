"""Testes do netalerta: mudança de configuração, KEV e catálogo novos, estado
e um servidor HTTP simulado para webhook e Telegram. Nada sai da máquina.

uso: python3 testes/test_netalerta.py

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import http.server
import json
import os
import shutil
import smtplib
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netalerta as na  # noqa: E402


AQUI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def snap(host, ip, quando, config, sensivel="redacted", sessao_perdida=False):
    return ("---\n" + f'host: "{host}"\nip: "{ip}"\n'
            f'platform_key: "juniper_junos"\nplatform_name: "Junos"\n'
            f'collected_at: "{quando}"\nsensitive_data: "{sensivel}"\n'
            f'session_lost: {json.dumps(sessao_perdida)}\n---\n\n'
            "## Configuração\n\n### `show configuration | display set`\n\n"
            f"```text\n{config}\n```\n")


def triagem(hosts):
    return {"formato": "netcve/1", "hosts": hosts}


class Coletor(http.server.BaseHTTPRequestHandler):
    recebidos = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        corpo = self.rfile.read(int(self.headers["Content-Length"]))
        Coletor.recebidos.append((self.path, json.loads(corpo)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")


class TesteNetalerta(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="netalerta_")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def escrever(self, nome, texto):
        with open(os.path.join(self.dir, nome), "w", encoding="utf-8") as f:
            f.write(texto)

    def test_config_mudou(self):
        self.escrever("mx_192.0.2.10_20261030_090000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T09:00:00", "set a\nset b"))
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00", "set a\nset c"))
        a = na.alertas_de_config(self.dir)
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["tipo"], "config-mudou")
        self.assertIn("+set c", a[0]["detalhe"])
        self.assertIn("-set b", a[0]["detalhe"])

    def test_config_sem_anterior_nao_alerta(self):
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00", "set a"))
        self.assertEqual(na.alertas_de_config(self.dir), [])

    def test_kev_e_catalogo_novos(self):
        self.escrever("_cve_triagem_20261030_090000.json", json.dumps(triagem([
            {"host": "mx", "ip": "192.0.2.10",
             "versoes": [{"cves": [{"id": "CVE-1", "kev": True}]}],
             "catalogo": []}])))
        self.escrever("_cve_triagem_20261030_100000.json", json.dumps(triagem([
            {"host": "mx", "ip": "192.0.2.10",
             "versoes": [{"cves": [{"id": "CVE-1", "kev": True},
                                   {"id": "CVE-2", "kev": True}]}],
             "catalogo": [{"id": "MIKROTRICK", "titulo": "MikroTrick",
                           "situacao": "vulneravel", "base": "versão X", "exposicao": ["SSH aberto"]}]}])))
        a = na.alertas_de_triagem(self.dir)
        tipos = sorted(x["tipo"] for x in a)
        self.assertEqual(tipos, ["catalogo", "kev-nova"])
        kev = next(x for x in a if x["tipo"] == "kev-nova")
        self.assertIn("CVE-2", kev["titulo"])
        self.assertNotIn("CVE-1", " ".join(x["titulo"] for x in a))  # já visto antes

    def test_estado_nao_repete(self):
        self.escrever("mx_192.0.2.10_20261030_090000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T09:00:00", "set a"))
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00", "set b"))
        estado = os.path.join(self.dir, "estado.json")
        # Sem destino configurado, o arquivo é a entrega: marca como visto.
        s1, _ = na.rodar(self.dir, estado=estado, env={})
        self.assertEqual(s1["novos"], 1)
        s2, base = na.rodar(self.dir, estado=estado, env={})
        self.assertEqual(s2["novos"], 0)
        self.assertIsNone(base)

    def _par_que_mudou(self):
        self.escrever("mx_192.0.2.10_20261030_090000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T09:00:00", "set a"))
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00", "set b"))

    def test_simular_nao_grava_estado(self):
        self._par_que_mudou()
        estado = os.path.join(self.dir, "estado.json")
        na.rodar(self.dir, estado=estado, simular=True,
                 env={"NETALERTA_WEBHOOK": "https://exemplo.invalid/h"})
        self.assertFalse(os.path.exists(estado))
        s, _ = na.rodar(self.dir, estado=estado, env={})
        self.assertEqual(s["novos"], 1)

    def test_falha_de_envio_nao_marca_visto(self):
        self._par_que_mudou()
        estado = os.path.join(self.dir, "estado.json")
        # Porta 1 do loopback: conexão recusada, nenhum destino entrega.
        env = {"NETALERTA_WEBHOOK": "http://127.0.0.1:1/h"}
        s1, _ = na.rodar(self.dir, estado=estado, env=env, registrar=lambda m: None)
        self.assertTrue(s1["envio"]["webhook"].startswith("falha"))
        s2, _ = na.rodar(self.dir, estado=estado, env=env, registrar=lambda m: None)
        self.assertEqual(s2["novos"], 1)

    def test_envio_aceito_marca_visto(self):
        self._par_que_mudou()
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Coletor)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        estado = os.path.join(self.dir, "estado.json")
        env = {"NETALERTA_WEBHOOK": f"http://127.0.0.1:{srv.server_address[1]}/h"}
        try:
            s1, _ = na.rodar(self.dir, estado=estado, env=env)
            s2, _ = na.rodar(self.dir, estado=estado, env=env)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(s1["envio"], {"webhook": "ok"})
        self.assertEqual(s2["novos"], 0)

    def test_id_de_config_estavel_entre_processos(self):
        # hash() muda a cada processo; o id precisa sobreviver entre execuções.
        self._par_que_mudou()
        codigo = ("import sys; sys.path.insert(0, sys.argv[1]); import netalerta;"
                  "print(netalerta.alertas_de_config(sys.argv[2])[0]['id'])")
        ids = {subprocess.run([sys.executable, "-I", "-c", codigo, AQUI, self.dir],
                              capture_output=True, text=True, check=True).stdout.strip()
               for _ in range(2)}
        self.assertEqual(ids, {"config|mx|192.0.2.10|2026-10-30T10:00:00"})

    def test_mesma_mudanca_em_outra_coleta_avisa_de_novo(self):
        self._par_que_mudou()
        id1 = na.alertas_de_config(self.dir)[0]["id"]
        # Desfeito e refeito: a diferença mais recente volta a ser "a" -> "b".
        self.escrever("mx_192.0.2.10_20261030_110000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T11:00:00", "set a"))
        self.escrever("mx_192.0.2.10_20261030_120000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T12:00:00", "set b"))
        id2 = na.alertas_de_config(self.dir)[0]["id"]
        self.assertNotEqual(id1, id2)

    def test_cabecalhos_volateis_nao_alertam(self):
        pares = [
            ("# 2026-10-30 09:00:00 by RouterOS 7.15",
             "# 2026-10-30 10:00:00 by RouterOS 7.15"),
            ("# oct/30/2026 09:00:00 by RouterOS 6.49.10",
             "# oct/30/2026 10:00:00 by RouterOS 6.49.10"),
            ("!Time: Fri Oct 30 09:00:00 2026", "!Time: Fri Oct 30 10:00:00 2026"),
            ("ntp clock-period 36028797018963968", "ntp clock-period 36028797018963971"),
            ("! NVRAM config last updated at 09:00:00 UTC Fri Oct 30 2026 by admin",
             "! NVRAM config last updated at 10:00:00 UTC Fri Oct 30 2026 by admin"),
            ("! Last configuration change at 09:00:00 UTC Fri Oct 30 2026",
             "! Last configuration change at 10:00:00 UTC Fri Oct 30 2026"),
            ("!Last configuration was updated at 2026-10-30 09:00:00+00:00",
             "!Last configuration was updated at 2026-10-30 10:00:00+00:00"),
            ("!Last configuration was saved at 2026-10-30 09:00:00+00:00",
             "!Last configuration was saved at 2026-10-30 10:00:00+00:00"),
            ("## Last commit: 2026-10-30 09:00:00 UTC by admin",
             "## Last commit: 2026-10-30 10:00:00 UTC by admin"),
            ("## Last changed: 2026-10-30 09:00:00 UTC",
             "## Last changed: 2026-10-30 10:00:00 UTC"),
        ]
        for antes, depois in pares:
            with self.subTest(linha=antes):
                for n in os.listdir(self.dir):
                    os.remove(os.path.join(self.dir, n))
                self.escrever("r_192.0.2.1_1.md", snap(
                    "r", "192.0.2.1", "2026-10-30T09:00:00", antes + "\nset a"))
                self.escrever("r_192.0.2.1_2.md", snap(
                    "r", "192.0.2.1", "2026-10-30T10:00:00", depois + "\nset a"))
                self.assertEqual(na.alertas_de_config(self.dir), [])
        # A mudança real continua aparecendo, sem a linha volátil no detalhe.
        self.escrever("r_192.0.2.1_2.md", snap(
            "r", "192.0.2.1", "2026-10-30T10:00:00", depois + "\nset b"))
        a = na.alertas_de_config(self.dir)
        self.assertEqual(a[0]["detalhe"], "-set a\n+set b")

    def test_snapshot_com_dados_sensiveis_nao_envia_diferenca(self):
        self.escrever("mx_192.0.2.10_20261030_090000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T09:00:00",
                           "set snmp community velha", sensivel="included"))
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00",
                           "set snmp community nova"))
        a = na.alertas_de_config(self.dir)
        self.assertEqual(len(a), 1)
        self.assertIn("+1/-1", a[0]["titulo"])
        self.assertNotIn("velha", a[0]["detalhe"])
        self.assertNotIn("nova", a[0]["detalhe"])

    def test_diferenca_passa_pelo_sanitizador(self):
        original = na._sanitizar
        na._sanitizar = lambda t: t.replace("segredo", "***")
        try:
            self.escrever("mx_192.0.2.10_20261030_090000.md",
                          snap("mx", "192.0.2.10", "2026-10-30T09:00:00", "set a"))
            self.escrever("mx_192.0.2.10_20261030_100000.md",
                          snap("mx", "192.0.2.10", "2026-10-30T10:00:00",
                               "set a\nset x segredo"))
            a = na.alertas_de_config(self.dir)
        finally:
            na._sanitizar = original
        self.assertEqual(a[0]["detalhe"], "+set x ***")

    def test_sessao_perdida_nao_compara(self):
        self.escrever("mx_192.0.2.10_20261030_090000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T09:00:00", "set a\nset b"))
        self.escrever("mx_192.0.2.10_20261030_100000.md",
                      snap("mx", "192.0.2.10", "2026-10-30T10:00:00", "set a",
                           sessao_perdida=True))
        self.assertEqual(na.alertas_de_config(self.dir), [])

    def test_triagem_corrompida_nao_derruba(self):
        self.escrever("_cve_triagem_20261030_090000.json", json.dumps(triagem([
            {"host": "mx", "ip": "192.0.2.10",
             "versoes": [{"cves": [{"id": "CVE-1", "kev": True}]}]}])))
        self.escrever("_cve_triagem_20261030_100000.json", json.dumps(triagem([
            {"host": "mx", "ip": "192.0.2.10",
             "versoes": [{"cves": [{"id": "CVE-1", "kev": True},
                                   {"id": "CVE-2", "kev": True}]}]}])))
        self.escrever("_cve_triagem_20261030_110000.json", '{"hosts": [')
        avisos = []
        a = na.alertas_de_triagem(self.dir, registrar=avisos.append)
        self.assertEqual([x["titulo"] for x in a],
                         ["CVE com exploração confirmada (KEV): CVE-2"])
        self.assertTrue(any("ilegível" in m for m in avisos))
        s, _ = na.rodar(self.dir, env={}, registrar=avisos.append)
        self.assertEqual(s["novos"], 1)

    def test_webhook_exige_https(self):
        for url in ("http://exemplo.com/h", "ftp://exemplo.com/h",
                    "http://192.0.2.1/h", "file:///etc/passwd"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    na.enviar_webhook(url, [])
        res = na.enviar([{"severidade": "info", "host": "h", "ip": "i",
                          "titulo": "t", "id": "x"}],
                        {"webhook": "http://exemplo.com/h"}, registrar=lambda m: None)
        self.assertTrue(res["webhook"].startswith("falha"))

    def test_smtp_sem_starttls_recusa_login(self):
        chamadas = []

        class SemTLS:
            def __init__(self, *a, **k):
                chamadas.append(("SMTP", a))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self, **k):
                raise smtplib.SMTPNotSupportedError("STARTTLS extension not supported")

            def login(self, *a):
                chamadas.append(("login", a))

            def send_message(self, msg):
                chamadas.append(("send", None))

        class ComSSL(SemTLS):
            def __init__(self, *a, **k):
                chamadas.append(("SMTP_SSL", a, k.get("context") is not None))

        orig = smtplib.SMTP, smtplib.SMTP_SSL
        smtplib.SMTP, smtplib.SMTP_SSL = SemTLS, ComSSL
        try:
            cfg = {"servidor": "smtp.exemplo:587", "de": "a@b", "para": ["c@d"],
                   "usuario": "u", "senha": "s"}
            with self.assertRaises(smtplib.SMTPException):
                na.enviar_email("x", cfg)
            self.assertNotIn("login", [c[0] for c in chamadas])
            # Sem usuário (relay interno) continua entregando.
            chamadas.clear()
            na.enviar_email("x", dict(cfg, usuario=None, senha=None))
            self.assertEqual([c[0] for c in chamadas], ["SMTP", "send"])
            # Porta 465: TLS implícito, login permitido.
            chamadas.clear()
            na.enviar_email("x", dict(cfg, servidor="smtp.exemplo:465"))
            self.assertEqual([c[0] for c in chamadas], ["SMTP_SSL", "login", "send"])
            self.assertTrue(chamadas[0][2])
        finally:
            smtplib.SMTP, smtplib.SMTP_SSL = orig

    def test_envio_webhook_e_telegram(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Coletor)
        porta = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        Coletor.recebidos.clear()
        alertas = [{"tipo": "kev-nova", "severidade": "critica", "host": "mx",
                    "ip": "192.0.2.10", "titulo": "CVE-9", "detalhe": "x",
                    "id": "kev|mx|192.0.2.10|CVE-9"}]
        # webhook sem TLS: aponta direto para o coletor local
        res = {}
        try:
            na.enviar_webhook(f"http://127.0.0.1:{porta}/hook", alertas)
            res["webhook"] = "ok"
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(res["webhook"], "ok")
        caminho, corpo = Coletor.recebidos[0]
        self.assertEqual(caminho, "/hook")
        self.assertEqual(corpo["alertas"][0]["titulo"], "CVE-9")

    def test_destinos_do_ambiente(self):
        env = {"NETALERTA_TELEGRAM_TOKEN": "t", "NETALERTA_TELEGRAM_CHAT": "1",
               "NETALERTA_WEBHOOK": "https://exemplo/h",
               "NETALERTA_SMTP": "smtp:587", "NETALERTA_SMTP_DE": "a@b",
               "NETALERTA_SMTP_PARA": "c@d, e@f"}
        d = na.destinos_do_ambiente(env)
        self.assertEqual(set(d), {"telegram", "webhook", "email"})
        self.assertEqual(d["email"]["para"], ["c@d", "e@f"])
        self.assertEqual(na.destinos_do_ambiente({}), {})


if __name__ == "__main__":
    unittest.main(verbosity=1)
