"""Comandos da coleta Linux: sintaxe de shell de todos os comandos (perfil
e módulos de aplicação) e o agrupamento de logs repetidos.

uso: python3 testes/test_coleta_linux.py

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netsnap as ns  # noqa: E402


def comandos_linux():
    perfil = ns.PERFIS["linux"]
    for secao, cmds in perfil.items():
        if isinstance(cmds, list):
            for c in cmds:
                yield f"linux/{secao}", c
    for chave, app in ns.APPS_LINUX.items():
        yield f"{chave}/deteccao", app["deteccao"]
        for secao in ("config", "logs", "basico", "optica", "inventario"):
            for c in app.get(secao, []):
                yield f"{chave}/{secao}", c + (ns.FILTRO_LOG if secao == "logs" else "")
        for c in (app.get("extra") or {}).get("comandos", []):
            yield f"{chave}/extra", c


class TesteComandos(unittest.TestCase):
    def test_sintaxe_sh(self):
        shells = [s for s in ("dash", "bash") if shutil.which(s)]
        self.assertTrue(shells)
        for sudo in ("", "sudo -n "):
            for origem, cmd in comandos_linux():
                texto = cmd.replace("{S}", sudo)
                for sh in shells:
                    r = subprocess.run([sh, "-n", "-c", texto], capture_output=True,
                                       text=True)
                    self.assertEqual(r.returncode, 0,
                                     f"{sh} {origem}: {r.stderr}\n{texto[:200]}")

    def test_wanguard_sem_exabgpcli_nem_escrita(self):
        app = ns.APPS_LINUX["wanguard"]
        todos = " ".join(app["config"] + app["logs"] + app["basico"] +
                         app["inventario"] + app["extra"]["comandos"])
        self.assertNotIn("exabgpcli", todos)
        # Banco só por SELECT, SHOW e DESCRIBE
        for sql in re.findall(r'W "([A-Z]+)', todos):
            self.assertIn(sql, ("SELECT", "SHOW", "DESCRIBE"))
        self.assertNotRegex(todos, r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\s")


@unittest.skipUnless(shutil.which("awk"), "awk ausente")
class TesteFiltroLog(unittest.TestCase):
    def filtrar(self, linhas):
        r = subprocess.run(["sh", "-c", "cat" + ns.FILTRO_LOG], input="\n".join(linhas) + "\n",
                           capture_output=True, text=True, check=True)
        return r.stdout.splitlines()

    def test_agrupa_repeticoes_intercaladas(self):
        linhas = []
        for i in range(50):
            linhas.append(f"ago 20 23:{i:02d}:04 wg genrrds_sensor[{1000 + i}]: fail 1 clickhouse 0")
            linhas.append(f"ago 20 23:{i:02d}:05 wg genrrds_server[{2000 + i}]: fail 1 clickhouse 0")
        linhas.append("ago 20 23:59:00 wg sshd[9]: Accepted publickey for root")
        saida = self.filtrar(linhas)
        self.assertEqual(len(saida), 5)
        self.assertIn("+49 linha(s) semelhante(s) omitida(s); a última em ago 20 23:49:04",
                      saida[1])
        self.assertTrue(saida[-1].endswith("Accepted publickey for root"))

    def test_limite_de_mensagens_distintas(self):
        linhas = [f"2026-10-23T10:00:00 h app: mensagem distinta {chr(97 + i % 26)}"
                  f"{chr(97 + i // 26 % 26)}{chr(97 + i // 676)}" for i in range(250)]
        saida = self.filtrar(linhas)
        self.assertEqual(saida[0], "    [50 mensagem(ns) mais antiga(s) omitida(s)]")
        self.assertEqual(len(saida), 201)


if __name__ == "__main__":
    unittest.main(verbosity=1)
