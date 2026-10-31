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
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netalerta as na  # noqa: E402


def snap(host, ip, quando, config):
    return ("---\n" + f'host: "{host}"\nip: "{ip}"\n'
            f'platform_key: "juniper_junos"\nplatform_name: "Junos"\n'
            f'collected_at: "{quando}"\nsensitive_data: "redacted"\n---\n\n'
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
        s1, _ = na.rodar(self.dir, estado=estado, simular=True, env={})
        self.assertEqual(s1["novos"], 1)
        s2, base = na.rodar(self.dir, estado=estado, simular=True, env={})
        self.assertEqual(s2["novos"], 0)
        self.assertIsNone(base)

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
