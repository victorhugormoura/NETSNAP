"""Próxima execução dos agendamentos e retenção de snapshots.

Uso: python3 test_agenda_retencao.py [pasta app montada]

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime

_AQUI = os.path.dirname(os.path.abspath(__file__))
# Pacote montado: ../app (pacote extraído) ou ../build/netsnap-servidor/app
# (repositório, depois de servidor/montar.sh).
APP = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else (
    os.path.join(_AQUI, "..", "app") if os.path.isdir(os.path.join(_AQUI, "..", "app"))
    else os.path.join(_AQUI, "..", "build", "netsnap-servidor", "app")))
sys.path.insert(0, APP)
import netsnap_cofre as cf  # noqa: E402
import netsnap_servidor as srv  # noqa: E402

P = srv.proxima_execucao
D = datetime


class TesteProxima(unittest.TestCase):
    def test_horas(self):
        self.assertEqual(P({"tipo": "horas", "a_cada": 6}, D(2026, 10, 15, 22, 10, 5)),
                         D(2026, 10, 16, 4, 10, 5))

    def test_diario(self):
        f = {"tipo": "diario", "hora": "03:00"}
        self.assertEqual(P(f, D(2026, 10, 15, 2, 59)), D(2026, 10, 15, 3, 0))
        self.assertEqual(P(f, D(2026, 10, 15, 3, 0)), D(2026, 10, 16, 3, 0))  # exatamente na hora: amanhã
        self.assertEqual(P(f, D(2026, 12, 31, 4, 0)), D(2027, 1, 1, 3, 0))

    def test_semanal(self):
        f = {"tipo": "semanal", "hora": "02:30", "dias_semana": [0, 3]}  # seg e qui
        self.assertEqual(P(f, D(2026, 10, 15, 2, 0)), D(2026, 10, 15, 2, 30))   # qui antes da hora
        self.assertEqual(P(f, D(2026, 10, 15, 3, 0)), D(2026, 10, 19, 2, 30))   # qui depois: seg
        self.assertEqual(P(f, D(2026, 10, 19, 2, 30)), D(2026, 10, 22, 2, 30))  # seg na hora: qui
        só_domingo = {"tipo": "semanal", "hora": "00:00", "dias_semana": [6]}
        self.assertEqual(P(só_domingo, D(2026, 10, 18, 0, 0)), D(2026, 10, 25, 0, 0))

    def test_a_cada_n_dias(self):
        f = {"tipo": "dias", "hora": "04:00", "a_cada": 7, "inicio": "2026-10-01"}
        self.assertEqual(P(f, D(2026, 10, 1, 3, 0)), D(2026, 10, 1, 4, 0))
        self.assertEqual(P(f, D(2026, 10, 1, 5, 0)), D(2026, 10, 8, 4, 0))
        self.assertEqual(P(f, D(2026, 10, 15, 3, 0)), D(2026, 10, 15, 4, 0))
        self.assertEqual(P(f, D(2026, 10, 16, 3, 0)), D(2026, 10, 22, 4, 0))
        futuro = dict(f, inicio="2026-11-03")
        self.assertEqual(P(futuro, D(2026, 10, 15, 3, 0)), D(2026, 11, 3, 4, 0))

    def test_texto(self):
        self.assertEqual(srv.texto_frequencia({"tipo": "semanal", "hora": "02:30", "dias_semana": [5, 6]}),
                         "sáb, dom às 02:30")


class TesteRetencao(unittest.TestCase):
    def test_apaga_antigos_mas_mantem_o_ultimo_de_cada_equipamento(self):
        d = tempfile.mkdtemp()
        dados = os.path.join(d, "dados")
        chave = os.path.join(d, "chave")
        with open(chave, "w") as f:
            f.write(cf.chave_para_texto(cf.nova_chave_mestra()))
        os.chmod(chave, 0o400)
        conf = os.path.join(d, "s.conf")
        with open(conf, "w") as f:
            f.write(f"[servidor]\ndados = {dados}\narquivo_chave = {chave}\n"
                    f"[retencao]\nsnapshots_dias = 30\n")
        srv.iniciar(conf)
        pasta = srv.web.PASTA_SNAPSHOTS

        def snap(nome, host, ip, quando, dias_atras):
            c = os.path.join(pasta, nome)
            with open(c, "w") as f:
                f.write(f'---\nhost: "{host}"\nip: "{ip}"\ncollected_at: "{quando}"\n---\n')
            t = time.time() - dias_atras * 86400
            os.utime(c, (t, t))
            return c
        velho_a = snap("A_1.md", "A", "10.0.0.1", "2026-01-01T00:00:00", 200)
        novo_a = snap("A_2.md", "A", "10.0.0.1", "2026-10-01T00:00:00", 5)
        unico_b = snap("B_1.md", "B", "10.0.0.2", "2025-12-01T00:00:00", 300)  # só ele: fica
        indice = snap("_indice_20260101_000000.md", "", "", "", 200)
        srv.aplicar_retencao()
        self.assertFalse(os.path.exists(velho_a))
        self.assertTrue(os.path.exists(novo_a))
        self.assertTrue(os.path.exists(unico_b))
        self.assertFalse(os.path.exists(indice))


class TesteAlvos(unittest.TestCase):
    """Alvos locais e link-local recusados fora do laboratório."""
    def setUp(self):
        class Conf:
            permitir_locais = False
        self.antes = getattr(srv, "CONF", None)
        srv.CONF = Conf()
        import netsnap_web
        srv.web = netsnap_web

    def tearDown(self):
        srv.CONF = self.antes

    def test_loopback_e_metadados(self):
        for alvo in ("127.0.0.1", "169.254.169.254", "::1", "localhost"):
            with self.assertRaises(srv.web.ErroAPI) as e:
                srv.resolver_alvos(alvo, 22, None, None, 10)
            self.assertEqual(e.exception.status, 403, alvo)
        self.assertEqual(srv.resolver_alvos("192.0.2.10", 22, None, None, 10),
                         "192.0.2.10:22")

    def test_laboratorio_libera(self):
        srv.CONF.permitir_locais = True
        self.assertEqual(srv.resolver_alvos("127.0.1.18", 22, None, None, 10),
                         "127.0.1.18:22")


if __name__ == "__main__":
    unittest.main(verbosity=1)
