"""Testes do cofre (criptografia) e do banco do servidor.

Uso: python3 test_cofre_banco.py [pasta app montada]

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import timedelta

_AQUI = os.path.dirname(os.path.abspath(__file__))
# Pacote montado: ../app (pacote extraído) ou ../build/netsnap-servidor/app
# (repositório, depois de servidor/montar.sh).
APP = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else (
    os.path.join(_AQUI, "..", "app") if os.path.isdir(os.path.join(_AQUI, "..", "app"))
    else os.path.join(_AQUI, "..", "build", "netsnap-servidor", "app")))
sys.path.insert(0, APP)
import netsnap_cofre as cf  # noqa: E402
import netsnap_banco as bd  # noqa: E402

SENHA = "Senha-Forte-2026"


def bytes_do_banco(caminho):
    """Banco principal + WAL: com journal_mode=WAL o dado recente fica no -wal."""
    total = b""
    for sufixo in ("", "-wal"):
        if os.path.exists(caminho + sufixo):
            with open(caminho + sufixo, "rb") as f:
                total += f.read()
    return total


class TesteCofre(unittest.TestCase):
    def setUp(self):
        self.c = cf.Cofre(cf.nova_chave_mestra())

    def test_cifra_ida_volta_e_contexto(self):
        b = self.c.cifrar("segredo", "credencial:1")
        self.assertEqual(self.c.decifrar(b, "credencial:1"), b"segredo")
        with self.assertRaises(cf.ErroCofre):
            self.c.decifrar(b, "credencial:2")  # valor copiado para outro registro

    def test_adulteracao(self):
        b = self.c.cifrar("segredo", "x")
        bruto = bytearray(cf.base64.b64decode(b[3:]))
        bruto[-1] ^= 1
        with self.assertRaises(cf.ErroCofre):
            self.c.decifrar("v1:" + cf.base64.b64encode(bytes(bruto)).decode(), "x")

    def test_outra_chave(self):
        b = self.c.cifrar("segredo", "x")
        with self.assertRaises(cf.ErroCofre):
            cf.Cofre(cf.nova_chave_mestra()).decifrar(b, "x")

    def test_subchaves_independentes(self):
        self.assertNotEqual(self.c.hmac("sessao", "a"), self.c.hmac("auditoria", "a"))

    def test_totp_rfc6238(self):
        seg = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(cf.codigo_totp(seg, 59), "287082")
        self.assertEqual(cf.codigo_totp(seg, 1111111109), "081804")
        self.assertEqual(cf.codigo_totp(seg, 20000000000), "353130")

    def test_totp_reuso_e_janela(self):
        seg = cf.novo_segredo_totp()
        t = 1_800_000_000
        cod = cf.codigo_totp(seg, t)
        cont = cf.conferir_totp(seg, cod, 0, t)
        self.assertIsNotNone(cont)
        self.assertIsNone(cf.conferir_totp(seg, cod, cont, t))      # reuso
        self.assertIsNotNone(cf.conferir_totp(seg, cf.codigo_totp(seg, t - 30), 0, t))
        self.assertIsNone(cf.conferir_totp(seg, cf.codigo_totp(seg, t - 90), 0, t))
        self.assertIsNone(cf.conferir_totp(seg, "12345", 0, t))

    def test_senha_scrypt(self):
        h = cf.hash_senha(SENHA)
        self.assertTrue(h.startswith("scrypt$17$8$1$"))
        self.assertTrue(cf.conferir_senha(SENHA, h))
        self.assertFalse(cf.conferir_senha(SENHA + "x", h))
        self.assertFalse(cf.conferir_senha(SENHA, "lixo"))

    def test_politica(self):
        self.assertIsNotNone(cf.problema_na_senha("curta1A!"))
        self.assertIsNotNone(cf.problema_na_senha("somenteminusculas"[:12]))
        self.assertIsNone(cf.problema_na_senha("Senha-Forte-2026"))
        self.assertIsNone(cf.problema_na_senha("cavalo correto bateria grampo"))
        self.assertIsNotNone(cf.problema_na_senha("aaaaaaaaaaaaaaaaaa"))
        self.assertIsNotNone(cf.problema_na_senha("Admin.2026xx", "admin.2026xx"))

    def test_copia_da_chave(self):
        k = cf.nova_chave_mestra()
        texto = cf.exportar_chave(k, "frase de recuperacao longa")
        self.assertEqual(cf.importar_chave(texto, "frase de recuperacao longa"), k)
        with self.assertRaises(cf.ErroCofre):
            cf.importar_chave(texto, "errada")

    def test_arquivo_de_chave_permissao(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "k")
        with open(p, "w") as f:
            f.write(cf.chave_para_texto(cf.nova_chave_mestra()))
        os.chmod(p, 0o644)
        os.environ.pop("CREDENTIALS_DIRECTORY", None)
        with self.assertRaises(cf.ErroCofre):
            cf.carregar_chave_mestra(p)
        os.chmod(p, 0o400)
        self.assertEqual(len(cf.carregar_chave_mestra(p)), 32)
        # credencial do systemd tem prioridade
        os.environ["CREDENTIALS_DIRECTORY"] = d
        os.rename(p, os.path.join(d, "netsnap-chave"))
        self.assertEqual(len(cf.carregar_chave_mestra(None)), 32)
        del os.environ["CREDENTIALS_DIRECTORY"]


class TesteBanco(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.caminho = os.path.join(self.dir, "n.db")
        self.k = cf.nova_chave_mestra()
        self.b = bd.Banco(self.caminho, cf.Cofre(self.k))

    def test_chave_errada_recusada(self):
        with self.assertRaises(bd.ErroBanco):
            bd.Banco(self.caminho, cf.Cofre(cf.nova_chave_mestra()))
        bd.Banco(self.caminho, cf.Cofre(self.k))

    def test_usuario_e_senha_cifrada(self):
        uid = self.b.criar_usuario("Joao.Silva", SENHA, "tecnico")
        u = self.b.usuario(nome="joao.silva")
        self.assertEqual(u["id"], uid)
        self.assertTrue(u["hash_cifrado"].startswith("v1:"))
        self.assertNotIn("scrypt", bytes_do_banco(self.caminho).decode("latin1"))
        self.assertTrue(self.b.conferir_senha(u, SENHA))
        self.assertFalse(self.b.conferir_senha(u, "outra"))
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_usuario("joao.silva", SENHA, "tecnico")
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_usuario("x y", SENHA, "tecnico")
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_usuario("maria", "fraca", "tecnico")
        # hash de um usuário copiado para outro não vale
        uid2 = self.b.criar_usuario("maria", "Outra-Senha-2026", "leitura")
        c = sqlite3.connect(self.caminho)
        c.execute("UPDATE usuarios SET hash_cifrado = (SELECT hash_cifrado FROM usuarios WHERE id=?) WHERE id=?", (uid, uid2))
        c.commit()
        self.assertFalse(self.b.conferir_senha(self.b.usuario(uid2), SENHA))

    def test_bloqueio_da_conta(self):
        uid = self.b.criar_usuario("ana", SENHA, "leitura")
        for _ in range(bd.MAX_FALHAS_CONTA - 1):
            self.b.registrar_falha(uid)
        self.assertFalse(bd.Banco.bloqueado(self.b.usuario(uid)))
        _, ate = self.b.registrar_falha(uid)
        self.assertTrue(ate)
        self.assertTrue(bd.Banco.bloqueado(self.b.usuario(uid)))
        self.assertEqual(self.b.usuario(uid)["falhas"], 0)  # não acumula
        self.b.desbloquear(uid)
        self.assertFalse(bd.Banco.bloqueado(self.b.usuario(uid)))

    def test_ativo_normalizado(self):
        uid = self.b.criar_usuario("ana", SENHA, "leitura")
        self.b.alterar_usuario(uid, ativo=0)
        self.assertEqual(self.b.usuario(uid)["ativo"], 0)
        with self.assertRaises(bd.ErroBanco):
            self.b.alterar_usuario(uid, ativo="não")

    def test_totp_e_recuperacao(self):
        uid = self.b.criar_usuario("ana", SENHA, "leitura")
        seg = cf.novo_segredo_totp()
        codigos = self.b.ativar_totp(uid, seg, 5)
        u = self.b.usuario(uid)
        self.assertEqual(self.b.segredo_totp(u), seg)
        self.assertTrue(self.b.avancar_totp(uid, 6))
        self.assertFalse(self.b.avancar_totp(uid, 6))
        self.assertEqual(self.b.usar_codigo_recuperacao(uid, codigos[0].lower()), 9)
        self.assertIsNone(self.b.usar_codigo_recuperacao(uid, codigos[0]))
        self.assertIsNone(self.b.usar_codigo_recuperacao(uid, "AAAA-BBBB-CCCC"))

    def test_dispositivo(self):
        uid = self.b.criar_usuario("ana", SENHA, "leitura")
        outro = self.b.criar_usuario("bia", SENHA, "leitura")
        tok = self.b.criar_dispositivo(uid)
        self.assertTrue(self.b.dispositivo_valido(uid, tok))
        self.assertFalse(self.b.dispositivo_valido(outro, tok))
        self.assertFalse(self.b.dispositivo_valido(uid, tok + "x"))
        self.assertNotIn(tok, bytes_do_banco(self.caminho).decode("latin1"))
        self.b.trocar_senha(uid, "Nova-Senha-2026!", exigir_troca=True)  # reset pelo admin
        self.assertFalse(self.b.dispositivo_valido(uid, tok))

    def test_sessao(self):
        uid = self.b.criar_usuario("ana", SENHA, "leitura")
        tok, csrf = self.b.criar_sessao(uid, "10.0.0.1", "x", timedelta(hours=12))
        s = self.b.sessao(tok, timedelta(minutes=30))
        self.assertEqual(s["nome"], "ana")
        self.assertEqual(s["csrf"], csrf)
        self.assertNotIn(tok, bytes_do_banco(self.caminho).decode("latin1"))
        self.assertIsNone(self.b.sessao(tok + "x", timedelta(minutes=30)))
        self.assertIsNone(self.b.sessao(tok, timedelta(seconds=-1)))  # ociosa
        self.assertIsNone(self.b.sessao(tok, timedelta(minutes=30)))  # já removida
        tok2, _ = self.b.criar_sessao(uid, "", "", timedelta(hours=1))
        self.b.alterar_usuario(uid, ativo=0)
        self.assertIsNone(self.b.sessao(tok2, timedelta(minutes=30)))

    def test_credencial(self):
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_credencial("x", "u", "s", "", "admin", 1, [])
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_credencial("x", "u", "s", "", "admin", 1, ["0.0.0.0/0"])
        with self.assertRaises(bd.ErroBanco):
            self.b.criar_credencial("x", "u", "s", "", "admin", 1, ["10.0.0.300/24"])
        cid = self.b.criar_credencial("borda", "netsnap", "S3gr3do!", "MX", "admin", 1,
                                      "10.0.0.5/24, 2001:db8::/48")
        bruto = bytes_do_banco(self.caminho)
        self.assertNotIn(b"S3gr3do!", bruto)
        self.assertNotIn(b"netsnap\"", bruto)
        lista = self.b.listar_credenciais()
        self.assertEqual(lista[0]["usuario"], "netsnap")
        self.assertEqual(lista[0]["redes"], ["10.0.0.0/24", "2001:db8::/48"])
        self.assertFalse(lista[0]["telnet"])
        self.assertNotIn("senha", lista[0])
        self.assertEqual(self.b.segredo_credencial(cid)["senha"], "S3gr3do!")
        self.b.atualizar_credencial(cid, senha_disp="Nova#1")
        s = self.b.segredo_credencial(cid)
        self.assertEqual((s["usuario"], s["senha"]), ("netsnap", "Nova#1"))
        self.assertEqual(s["redes"], ["10.0.0.0/24", "2001:db8::/48"])
        self.b.atualizar_credencial(cid, redes=["10.1.0.0/16"], telnet=True)
        s = self.b.segredo_credencial(cid)
        self.assertEqual((s["redes"], s["telnet"], s["senha"]), (["10.1.0.0/16"], True, "Nova#1"))
        self.b.salvar_agendamento({"id": "a1", "nome": "diario", "ativo": True,
                                   "credencial": cid, "criado_por": "admin",
                                   "criado": "2026-01-01T00:00:00"})
        with self.assertRaises(bd.ErroBanco):
            self.b.remover_credencial(cid)
        self.b.remover_agendamento("a1")
        self.b.remover_credencial(cid)

    def test_auditoria_encadeada(self):
        for i in range(5):
            self.b.auditar("admin", "10.0.0.1", "teste", str(i))
        self.assertEqual(self.b.verificar_auditoria(), (True, None))
        c = sqlite3.connect(self.caminho)
        c.execute("UPDATE auditoria SET detalhe='x' WHERE id=3"); c.commit()
        self.assertEqual(self.b.verificar_auditoria(), (False, 3))
        c.execute("UPDATE auditoria SET detalhe='' WHERE id=3"); c.commit()
        self.assertEqual(self.b.verificar_auditoria(), (True, None))
        # corte do fim, mesmo "acertando" a âncora com o hash visível no banco
        c.execute("DELETE FROM auditoria WHERE id=5")
        ultimo = c.execute("SELECT hash FROM auditoria WHERE id=4").fetchone()[0]
        c.execute("UPDATE meta SET valor=? WHERE chave='auditoria_ancora'", (ultimo,))
        c.commit()
        self.assertFalse(self.b.verificar_auditoria()[0])
        # trilha inteira apagada
        c.execute("DELETE FROM auditoria"); c.commit()
        self.assertFalse(self.b.verificar_auditoria()[0])
        # banco novo, sem nenhum registro: íntegro
        d2 = tempfile.mkdtemp()
        b2 = bd.Banco(os.path.join(d2, "n.db"), cf.Cofre(cf.nova_chave_mestra()))
        self.assertEqual(b2.verificar_auditoria(), (True, None))

    def test_permissao_do_arquivo(self):
        self.assertEqual(os.stat(self.caminho).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
