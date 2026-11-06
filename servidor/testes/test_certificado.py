"""O certificado da CA interna precisa validar também em painel acessado por IP."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(AQUI))
import netsnapctl as ctl  # noqa: E402


@unittest.skipUnless(shutil.which("openssl"), "precisa do openssl")
class CertificadoCaInterna(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.pki_original = ctl.PKI
        self.addCleanup(setattr, ctl, "PKI", self.pki_original)
        ctl.PKI = self.dir

    def valida(self, nomes):
        ctl.gerar_ca_interna(nomes)
        ctl.emitir_certificado_servidor(nomes)
        return subprocess.run(
            ["openssl", "verify", "-CAfile", f"{self.dir}/ca.crt", f"{self.dir}/servidor.crt"],
            capture_output=True, text=True)

    def test_painel_so_por_ip(self):
        saida = self.valida(["172.16.10.177"])
        self.assertEqual(saida.returncode, 0, saida.stderr)

    def test_painel_por_nome_e_ip(self):
        saida = self.valida(["netsnap.exemplo.com.br", "172.16.10.177"])
        self.assertEqual(saida.returncode, 0, saida.stderr)


if __name__ == "__main__":
    unittest.main()
