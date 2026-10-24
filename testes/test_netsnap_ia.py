"""Testes do netsnap_ia com servidores de API simulados (Anthropic e
compatível com OpenAI). Nenhuma chamada sai da máquina.

uso: python3 testes/test_netsnap_ia.py

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import http.server
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netsnap_ia as ia  # noqa: E402

SNAP = """---
netsnap_version: "1.17.1"
host: "MX-LAB-A"
ip: "192.0.2.10"
platform_key: "juniper_junos"
platform_name: "Juniper Junos (MX)"
collected_at: "2026-10-22T10:00:00"
sensitive_data: "{sens}"
---

# Snapshot — MX-LAB-A (192.0.2.10)

## Configuração

### `show configuration | display set`

```text
set system host-name MX-LAB-A
set system services telnet
set protocols bgp group TRANSITO type external
```

## Logs

### `show log messages | last 300`

```text
Oct 22 09:00:01 MX-LAB-A rpd[1]: BGP_PREFIX_THRESH_EXCEEDED
```
"""

RESPOSTA = {
    "host": "MX-LAB-A", "ip": "192.0.2.10", "resumo": "Telnet ligado.",
    "achados": [
        {"categoria": "seguranca", "severidade": "ALTA", "titulo": "Telnet habilitado",
         "evidencia": [{"comando": "show configuration | display set",
                        "trecho": "set system services telnet"}],
         "impacto": "credenciais em texto claro",
         "recomendacao": "desligar telnet",
         "comandos_propostos": ["delete system services telnet"],
         "comandos_reversao": ["set system services telnet"], "confianca": "alta"},
        {"categoria": "inventada", "severidade": "urgente", "titulo": "Sem evidência",
         "evidencia": [], "confianca": "alta"},
        {"severidade": "baixa"},
    ],
}


class Simulado(http.server.BaseHTTPRequestHandler):
    pedidos = []
    resposta_texto = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        corpo = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Simulado.pedidos.append({"caminho": self.path,
                                 "cabecalhos": {k.lower(): v for k, v in self.headers.items()},
                                 "corpo": corpo})
        texto = Simulado.resposta_texto or json.dumps(RESPOSTA)
        if self.path.startswith("/redir/v1/"):
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:%d/v1/messages"
                             % self.server.server_address[1])
            self.end_headers()
            return
        if self.path == "/nulo/chat/completions":
            bruto = json.dumps({"choices": [{"message": {"content": None}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(bruto)))
            self.end_headers()
            self.wfile.write(bruto)
            return
        if self.path == "/v1/messages":
            dados = {"content": [{"type": "text", "text": "```json\n" + texto + "\n```"}],
                     "usage": {"input_tokens": 100, "output_tokens": 50}}
        elif self.path == "/v1/chat/completions":
            dados = {"choices": [{"message": {"content": texto}}], "usage": {}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        bruto = json.dumps(dados).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(bruto)))
        self.end_headers()
        self.wfile.write(bruto)


class TesteIA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Simulado)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="netsnap_ia_teste_")
        self.snaps = os.path.join(self.dir, "snapshots")
        os.makedirs(self.snaps)
        self.escrever_snapshot("redacted")
        Simulado.pedidos.clear()
        Simulado.resposta_texto = None

    def tearDown(self):
        shutil.rmtree(self.dir)

    def escrever_snapshot(self, sens):
        with open(os.path.join(self.snaps, "MX-LAB-A_192.0.2.10_20261022_100000.md"),
                  "w", encoding="utf-8") as f:
            f.write(SNAP.format(sens=sens))

    def test_contexto_privado_tem_prioridade(self):
        privada = os.path.join(self.dir, "privada")
        os.makedirs(os.path.join(privada, "junos", "referencias"))
        with open(os.path.join(privada, "junos", "SKILL.md"), "w") as f:
            f.write("SKILL COMPLETA JUNOS")
        with open(os.path.join(privada, "junos", "referencias", "bgp.md"), "w") as f:
            f.write("NOTA BGP")
        texto, usados, _ = ia.montar_contexto("juniper_junos", privada)
        self.assertIn("SKILL COMPLETA JUNOS", texto)
        self.assertIn("NOTA BGP", texto)
        self.assertNotIn("checklist de análise", texto.split("---", 1)[-1][:200])
        self.assertTrue(any(u.endswith("geral.md") for u in usados))  # base
        texto, _, _ = ia.montar_contexto("juniper_junos", None)
        self.assertIn("Juniper Junos (linha MX)", texto)

    def test_simulacao_grava_pedido(self):
        r, base, pedidos = ia.analisar(self.snaps, simular=True)
        self.assertEqual(len(Simulado.pedidos), 0)
        arquivo = os.path.join(pedidos, "MX-LAB-A.txt")
        with open(arquivo, encoding="utf-8") as f:
            texto = f.read()
        self.assertIn("set system services telnet", texto)
        self.assertIn("Juniper Junos (linha MX)", texto)
        self.assertTrue(os.path.isfile(base + ".json"))

    def test_snapshot_com_segredos_nao_sai(self):
        self.escrever_snapshot("included")
        r, _, _ = ia.analisar(self.snaps, provedor="openai", modelo="m",
                              url=self.url + "/v1", chave="")
        self.assertIn("segredos", r["hosts"][0]["erro"])
        self.assertEqual(Simulado.pedidos, [])

    def test_anthropic(self):
        r, base, _ = ia.analisar(self.snaps, provedor="anthropic", modelo="claude-x",
                                 url=self.url, chave="sk-teste")
        p = Simulado.pedidos[0]
        self.assertEqual(p["caminho"], "/v1/messages")
        self.assertEqual(p["cabecalhos"]["x-api-key"], "sk-teste")
        self.assertEqual(p["cabecalhos"]["anthropic-version"], "2023-06-01")
        self.assertEqual(p["corpo"]["model"], "claude-x")
        self.assertEqual(p["corpo"]["system"][0]["cache_control"], {"type": "ephemeral"})
        h = r["hosts"][0]
        self.assertNotIn("erro", h)
        self.assertEqual(len(h["achados"]), 2)            # o sem título sai
        self.assertEqual(h["achados"][0]["severidade"], "alta")
        self.assertEqual(h["achados"][1]["severidade"], "info")
        self.assertEqual(h["achados"][1]["confianca"], "baixa")
        self.assertEqual(h["achados"][1]["categoria"], "configuracao")
        self.assertTrue(h["avisos"])
        with open(base + ".md", encoding="utf-8") as f:
            md = f.read()
        self.assertIn("[ALTA] Telnet habilitado", md)
        self.assertIn("delete system services telnet", md)
        with open(base + ".json", encoding="utf-8") as f:
            salvo = json.load(f)
        self.assertEqual(salvo["formato"], "netanalytic-achados/1")

    def test_anthropic_exige_chave(self):
        with self.assertRaises(ia.ErroIA):
            ia.analisar(self.snaps, provedor="anthropic", url=self.url, chave="")

    def test_openai_compativel_sem_chave(self):
        r, _, _ = ia.analisar(self.snaps, provedor="openai", modelo="llama-local",
                              url=self.url + "/v1", chave="")
        p = Simulado.pedidos[0]
        self.assertEqual(p["caminho"], "/v1/chat/completions")
        self.assertNotIn("authorization", p["cabecalhos"])
        self.assertEqual(p["corpo"]["messages"][0]["role"], "system")
        self.assertEqual(len(r["hosts"][0]["achados"]), 2)

    def test_resposta_invalida_vira_erro_do_host(self):
        Simulado.resposta_texto = "não sei responder em JSON"
        r, _, _ = ia.analisar(self.snaps, provedor="openai", modelo="m",
                              url=self.url + "/v1", chave="")
        self.assertIn("JSON", r["hosts"][0]["erro"])

    def test_pacote_do_servidor_com_diff(self):
        zip_path = os.path.join(self.dir, "pacote.zip")
        resumo = [{"arquivo": "MX-LAB-A_192.0.2.10_20261022_100000.md", "host": "MX-LAB-A",
                   "ip": "192.0.2.10", "plataforma": "juniper_junos",
                   "falhas_graves": []}]
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("manifesto.json", json.dumps({"formato": "netsnap-analise/1",
                                                     "id": "pacote-1"}))
            z.writestr("resumo.json", json.dumps(resumo))
            z.write(os.path.join(self.snaps, resumo[0]["arquivo"]),
                    "snapshots/" + resumo[0]["arquivo"])
            z.writestr("mudancas/MX-LAB-A.diff", "+set system services telnet\n")
            z.writestr("../fora.md", "não pode ser extraído")
        r, base, _ = ia.analisar(zip_path, provedor="openai", modelo="m",
                                 url=self.url + "/v1", chave="")
        self.assertEqual(r["pacote"], "pacote-1")
        usuario = Simulado.pedidos[0]["corpo"]["messages"][1]["content"]
        self.assertIn("+set system services telnet", usuario)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "fora.md")))
        self.assertTrue(base.startswith(self.dir))

    def test_contexto_do_modulo_de_aplicacao(self):
        texto, usados, _ = ia.montar_contexto(
            "linux", None, ["WANGuard (detecção e mitigação DDoS)", "Zabbix"])
        self.assertTrue(any(u.endswith("wanguard.md") for u in usados))
        self.assertIn("Wanguard 9", texto)
        _, usados, _ = ia.montar_contexto("linux", None, [])
        self.assertFalse(any(u.endswith("wanguard.md") for u in usados))

    def test_corte_justo_preserva_saidas_pequenas_no_fim(self):
        caminho = os.path.join(self.snaps, "MX-LAB-A_192.0.2.10_20261022_100000.md")
        grande = SNAP.format(sens="redacted").replace(
            "set protocols bgp group TRANSITO type external",
            "\n".join(f"set interfaces ae0 unit {i} vlan-id {i}" for i in range(20000)))
        # Saída curta depois da grande, como um módulo de aplicação
        grande = grande.replace("## Logs", "### `show version`\n\n```text\n"
                                "Junos: 23.4R2-S5\n```\n\n## Logs")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(grande)
        _, texto, cortes = ia.texto_do_snapshot(caminho, limite=50_000)
        self.assertIn("config", cortes)
        self.assertIn("Junos: 23.4R2-S5", texto)
        self.assertIn("saída cortada", texto)
        self.assertEqual(ia._cotas_justas([10, 500, 1000], 410), [10, 200, 200])
        self.assertEqual(ia._cotas_justas([10, 20], 100), [10, 20])

    def test_redirecionamento_nao_leva_a_chave(self):
        r, _, _ = ia.analisar(self.snaps, provedor="anthropic", modelo="m",
                              url=self.url + "/redir", chave="sk-SEGREDO")
        self.assertIn("redirecionou", r["hosts"][0]["erro"])
        self.assertFalse(any(p["caminho"] == "/v1/messages" for p in Simulado.pedidos))

    def test_conteudo_nulo_vira_erro_do_host(self):
        r, base, _ = ia.analisar(self.snaps, provedor="openai", modelo="m",
                                 url=self.url + "/nulo", chave="")
        self.assertIn("vazia", r["hosts"][0]["erro"])
        self.assertTrue(os.path.isfile(base + ".json"))

    def test_marcador_delimita_as_saidas(self):
        r, base, pedidos = ia.analisar(self.snaps, simular=True)
        with open(os.path.join(pedidos, "MX-LAB-A.txt"), encoding="utf-8") as f:
            texto = f.read()
        m = re.search(r"Marcador das saídas deste pedido: SAIDA-([0-9a-f]{12})", texto)
        self.assertTrue(m)
        self.assertIn(f"<<<SAIDA-{m.group(1)}\nset system host-name", texto)

    def test_evidencia_conferida_e_comando_destrutivo(self):
        snapshot = "set system services telnet\nset system host-name X"
        obj = {"achados": [
            {"titulo": "Telnet", "severidade": "alta", "confianca": "alta",
             "evidencia": [{"comando": "c", "trecho": "set system services telnet"}],
             "comandos_propostos": ["delete system services telnet", "request system zeroize"]},
            {"titulo": "Inventado", "severidade": "critica", "confianca": "alta",
             "evidencia": [{"comando": "c", "trecho": "set system root-authentication plain"}],
             "comandos_propostos": "request system reboot"},
            {"titulo": ["não", "texto"], "severidade": "baixa"},
        ]}
        r, avisos = ia.validar_achados(obj, "h", "i", snapshot)
        por_titulo = {a["titulo"]: a for a in r["achados"]}
        self.assertEqual(por_titulo["Telnet"]["confianca"], "alta")
        self.assertEqual(por_titulo["Telnet"]["comandos_propostos"],
                         ["delete system services telnet"])
        self.assertEqual(por_titulo["Telnet"]["comandos_bloqueados"], ["request system zeroize"])
        self.assertEqual(por_titulo["Inventado"]["confianca"], "baixa")
        self.assertFalse(por_titulo["Inventado"]["evidencia"][0]["confere"])
        self.assertEqual(por_titulo["Inventado"]["comandos_propostos"], [])
        self.assertTrue(any("não está no snapshot" in a for a in avisos))

    def test_markdown_nao_e_forjado_pelo_trecho(self):
        resultado = {"gerado_em": "2026-10-24T10:00:00", "provedor": "p", "modelo": "m",
                     "hosts": [{"host": "h", "ip": "i", "achados": [{
                         "severidade": "baixa", "titulo": "t", "categoria": "logs",
                         "confianca": "baixa", "impacto": "", "recomendacao": "",
                         "evidencia": [{"comando": "c", "trecho": "x\n```\n### [CRITICA] falso"}],
                         "comandos_propostos": [], "comandos_reversao": []}]}]}
        md = ia.gerar_md(resultado)
        self.assertIn("````text", md)
        self.assertNotIn("\n### [CRITICA] falso\n```\n", md.split("````text", 1)[0])

    def test_resumo_do_pacote_com_caminho_absoluto(self):
        zip_path = os.path.join(self.dir, "pacote.zip")
        fora = os.path.join(self.snaps, "MX-LAB-A_192.0.2.10_20261022_100000.md")
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("manifesto.json", json.dumps({"formato": "netsnap-analise/1", "id": "p"}))
            z.writestr("resumo.json", json.dumps([{"arquivo": fora, "host": "x"}]))
        with self.assertRaises(ia.ErroIA):
            ia.analisar(zip_path, simular=True)

    def test_corte_proporcional_do_snapshot(self):
        caminho = os.path.join(self.snaps, "MX-LAB-A_192.0.2.10_20261022_100000.md")
        grande = SNAP.format(sens="redacted").replace(
            "set protocols bgp group TRANSITO type external",
            "\n".join(f"set interfaces ae0 unit {i} vlan-id {i}" for i in range(20000)))
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(grande)
        _, texto, cortes = ia.texto_do_snapshot(caminho, limite=50_000)
        self.assertIn("config", cortes)
        self.assertLess(len(texto), 60_000)
        self.assertIn("BGP_PREFIX_THRESH_EXCEEDED", texto)   # logs preservados


if __name__ == "__main__":
    unittest.main(verbosity=1)
