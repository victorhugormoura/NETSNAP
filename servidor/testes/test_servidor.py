"""Teste de integração do servidor: sobe o serviço num diretório temporário e
exercita login em etapas, sessão, CSRF, papéis, cofre, coleta com credencial,
agendamento, pacote de análise e auditoria.

Uso: python3 test_servidor.py <pasta app montada> [ip do laboratório]

Os testes de coleta precisam de um equipamento SSH no IP do laboratório
(porta 22). Se não houver, o roteador simulado (equipamento_simulado.py)
sobe sozinho quando o teste roda como root; sem root, esses testes são
pulados e o motivo aparece no resultado.

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

_AQUI = os.path.dirname(os.path.abspath(__file__))
APP = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else (
    os.path.join(_AQUI, "..", "app") if os.path.isdir(os.path.join(_AQUI, "..", "app"))
    else os.path.join(_AQUI, "..", "build", "netsnap-servidor", "app")))
LAB = sys.argv.pop(1) if len(sys.argv) > 1 else "127.0.1.18"
sys.path.insert(0, APP)
import netsnap_cofre as cf  # noqa: E402
import netsnap_banco as bd  # noqa: E402

SENHA_ADMIN = "Admin-Inicial-2026"
SENHA_NOVA = "Admin-Definitiva-2026"


ULTIMO_CONTADOR = {}


def codigo_livre(segredo):
    """Código TOTP ainda não usado: o servidor recusa reuso do mesmo passo
    (e de passos anteriores), então os testes avançam um passo por login."""
    while True:
        atual = int(time.time() // 30)
        for cont in (atual, atual + 1):
            if cont > ULTIMO_CONTADOR.get(segredo, 0):
                ULTIMO_CONTADOR[segredo] = cont
                return cf.codigo_totp(segredo, cont * 30)
        time.sleep(1)


def preparar_laboratorio(ip):
    """None se há equipamento em ip:22 (real ou simulado); senão o motivo."""
    try:
        socket.create_connection((ip, 22), timeout=2).close()
        return None
    except OSError:
        pass
    sys.path.insert(0, _AQUI)
    try:
        import equipamento_simulado
        equipamento_simulado.iniciar(ip, 22)
        return None
    except ImportError as e:
        return f"simulador indisponível ({e})"
    except OSError as e:
        return f"sem equipamento em {ip}:22 e o simulador não abriu a porta ({e})"


def porta_livre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Cliente:
    def __init__(self, porta, host="netsnap.teste"):
        self.porta, self.host = porta, host
        self.cookie, self.csrf, self.disp = "", "", ""

    def req(self, metodo, caminho, corpo=None, cabecalhos=None, csrf=True):
        c = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=60)
        h = {"Host": f"{self.host}:{self.porta}"}
        cookies = []
        if self.cookie:
            cookies.append("netsnap=" + self.cookie)
        if self.disp:
            cookies.append("netsnap-disp=" + self.disp)
        if cookies:
            h["Cookie"] = "; ".join(cookies)
        if csrf and self.csrf and metodo != "GET":
            h["X-Netsnap-CSRF"] = self.csrf
        dados = None
        if corpo is not None:
            dados = json.dumps(corpo).encode()
            h["Content-Type"] = "application/json"
        h.update(cabecalhos or {})
        c.request(metodo, caminho, dados, h)
        r = c.getresponse()
        bruto = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                m = re.match(r"netsnap=([^;]*)", v)
                if m:
                    self.cookie = m.group(1)
                m = re.match(r"netsnap-disp=([^;]*)", v)
                if m:
                    self.disp = m.group(1)
        try:
            corpo_r = json.loads(bruto)
        except ValueError:
            corpo_r = bruto
        if isinstance(corpo_r, dict) and corpo_r.get("csrf"):
            self.csrf = corpo_r["csrf"]
        return r.status, corpo_r, dict(r.getheaders())

    def entrar(self, usuario, senha, segredo=None, nova=None):
        st, r, _ = self.req("POST", "/api/sessao", {"usuario": usuario, "senha": senha})
        etapas = []
        while st == 200 and r.get("etapa") != "ok":
            etapas.append(r["etapa"])
            if r["etapa"] == "cadastrar_totp":
                segredo = r["segredo"]
                self.ultimos_codigos = None
                st, r, _ = self.req("POST", "/api/sessao/etapa", {
                    "desafio": r["desafio"], "codigo": codigo_livre(segredo)})
                if st == 200:
                    self.ultimos_codigos = r.get("codigos_recuperacao")
            elif r["etapa"] == "totp":
                st, r, _ = self.req("POST", "/api/sessao/etapa", {
                    "desafio": r["desafio"], "codigo": codigo_livre(segredo)})
            elif r["etapa"] == "trocar_senha":
                st, r, _ = self.req("POST", "/api/sessao/etapa", {
                    "desafio": r["desafio"], "nova_senha": nova})
            else:
                raise AssertionError(r)
        return st, r, etapas, segredo


class TesteServidor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sem_lab = preparar_laboratorio(LAB)
        cls.dir = tempfile.mkdtemp(prefix="netsnap_srv_")
        cls.dados = os.path.join(cls.dir, "dados")
        os.makedirs(cls.dados, mode=0o700)
        chave = os.path.join(cls.dir, "chave")
        with open(chave, "w") as f:
            f.write(cf.chave_para_texto(cf.nova_chave_mestra()))
        os.chmod(chave, 0o400)
        cls.porta = porta_livre()
        cls.conf = os.path.join(cls.dir, "servidor.conf")
        with open(cls.conf, "w") as f:
            f.write(f"""[servidor]
porta = {cls.porta}
nomes = netsnap.teste
dados = {cls.dados}
arquivo_chave = {chave}
cookie_seguro = nao
tcp_para_testes = sim
[sessao]
ociosidade_minutos = 30
[coleta]
max_execucoes_simultaneas = 2
permitir_alvos_locais = sim
""")
        banco = bd.Banco(os.path.join(cls.dados, "netsnap.db"),
                         cf.Cofre(cf.carregar_chave_mestra(chave)))
        banco.criar_usuario("admin", SENHA_ADMIN, "admin")
        del banco
        cls.log = open(os.path.join(cls.dir, "servidor.log"), "w")
        # HOME próprio, como o serviço (HOME=/var/lib/netsnap): chaves SSH
        # conhecidas e cache do netcve não se misturam com os do usuário.
        env = dict(os.environ, HOME=cls.dados)
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(APP, "netsnap_servidor.py"),
             "--config", cls.conf], stdout=cls.log, stderr=subprocess.STDOUT,
            env=env)
        for _ in range(100):
            try:
                st, _, _ = Cliente(cls.porta, "127.0.0.1").req("GET", "/api/saude")
                if st == 200:
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError(open(cls.log.name).read())
        cls.admin = Cliente(cls.porta)
        st, r, etapas, cls.segredo_admin = cls.admin.entrar("admin", SENHA_ADMIN,
                                                           nova=SENHA_NOVA)
        assert st == 200, (st, r)
        cls.etapas_admin = etapas
        cls.codigos_admin = cls.admin.ultimos_codigos

    @classmethod
    def tearDownClass(cls):
        cls.proc.send_signal(signal.SIGTERM)
        cls.proc.wait(10)
        cls.log.close()
        print("\n--- log do servidor (fim) ---")
        print("".join(open(cls.log.name).readlines()[-15:]))

    # -- login e sessão ----------------------------------------------------
    def test_01_primeiro_login_exige_totp_e_troca(self):
        self.assertEqual(self.etapas_admin, ["cadastrar_totp", "trocar_senha"])
        self.assertEqual(len(self.codigos_admin), 10)

    def test_02_senha_antiga_nao_vale_e_mensagem_generica(self):
        c = Cliente(self.porta)
        st, r, _ = c.req("POST", "/api/sessao", {"usuario": "admin", "senha": SENHA_ADMIN})
        st2, r2, _ = c.req("POST", "/api/sessao", {"usuario": "naoexiste", "senha": "x"})
        self.assertEqual((st, st2), (401, 401))
        self.assertEqual(r["erro"], r2["erro"])

    def test_03_sem_sessao_e_csrf(self):
        st, _, _ = Cliente(self.porta).req("GET", "/api/painel")
        self.assertEqual(st, 401)
        st, r, _ = self.admin.req("POST", "/api/cofre", {"nome": "x", "usuario": "u", "senha": "s"},
                                  csrf=False)
        self.assertEqual(st, 403)
        st, r, _ = self.admin.req("POST", "/api/cofre", {"nome": "x", "usuario": "u", "senha": "s"},
                                  cabecalhos={"Origin": "https://malicioso.exemplo"})
        self.assertEqual(st, 403)

    def test_04_host_invalido(self):
        st, _, _ = Cliente(self.porta, "evil.exemplo").req("GET", "/api/sessao")
        self.assertEqual(st, 421)

    def test_05_estaticos_e_cabecalhos(self):
        st, corpo, h = Cliente(self.porta).req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("default-src 'self'", h.get("Content-Security-Policy", ""))
        self.assertEqual(h.get("X-Frame-Options"), "DENY")
        # Tema escuro por padrão, aplicado antes do CSS por tema.js
        texto = corpo if isinstance(corpo, str) else corpo.decode("utf-8", "replace")
        self.assertIn('data-tema="escuro"', texto)
        self.assertLess(texto.index("tema.js"), texto.index("app.css"))
        st, js, h = Cliente(self.porta).req("GET", "/tema.js")
        self.assertEqual(st, 200)
        self.assertTrue(h.get("Content-Type", "").startswith("text/javascript"))
        # Fora da página, nada executa se for aberto direto numa aba.
        st, r, h = Cliente(self.porta).req("GET", "/api/sessao")
        self.assertIn("sandbox", h.get("Content-Security-Policy", ""))
        self.assertIsNone(r["ca_impressao"])

    def test_05b_impressao_da_ca_na_tela_de_login(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime as dt
        chave = ec.generate_private_key(ec.SECP256R1())
        nome = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "teste")])
        agora = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
                .public_key(chave.public_key()).serial_number(1)
                .not_valid_before(agora).not_valid_after(agora + dt.timedelta(days=1))
                .sign(chave, hashes.SHA256()))
        caminho = os.path.join(self.dados, "publico", "netsnap-ca.crt")
        with open(caminho, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        try:
            st, r, _ = Cliente(self.porta).req("GET", "/api/sessao")
            esperado = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))
            self.assertEqual((r["ca_interna"], r["ca_impressao"]), (True, esperado))
            st, corpo, h = Cliente(self.porta).req("GET", "/ca.crt")
            self.assertEqual(st, 200)
        finally:
            os.remove(caminho)

    def test_06_login_com_totp_e_recuperacao(self):
        c = Cliente(self.porta)
        st, r, etapas, _ = c.entrar("admin", SENHA_NOVA, segredo=self.segredo_admin)
        self.assertEqual((st, etapas), (200, ["totp"]))
        c2 = Cliente(self.porta)
        st, r, _ = c2.req("POST", "/api/sessao", {"usuario": "admin", "senha": SENHA_NOVA})
        st, r, _ = c2.req("POST", "/api/sessao/etapa", {"desafio": r["desafio"],
                                                        "codigo": self.codigos_admin[0]})
        self.assertEqual(st, 200)
        self.assertIn("restam 9", r.get("aviso", ""))
        # código de recuperação não vale duas vezes
        c3 = Cliente(self.porta)
        st, r, _ = c3.req("POST", "/api/sessao", {"usuario": "admin", "senha": SENHA_NOVA})
        st, r, _ = c3.req("POST", "/api/sessao/etapa", {"desafio": r["desafio"],
                                                        "codigo": self.codigos_admin[0]})
        self.assertEqual(st, 401)

    def test_07_usuarios_papeis_e_bloqueio(self):
        st, r, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "leitor", "senha": "Leitor-Temp-2026", "papel": "leitura"})
        self.assertEqual(st, 200, r)
        leitor = Cliente(self.porta)
        st, r, etapas, _ = leitor.entrar("leitor", "Leitor-Temp-2026", nova="Leitor-Final-2026")
        self.assertEqual(st, 200, r)
        st, _, _ = leitor.req("GET", "/api/inventario")
        self.assertEqual(st, 200)
        st, _, _ = leitor.req("POST", "/api/coletas", {"alvos": LAB})
        self.assertEqual(st, 403)
        st, _, _ = leitor.req("GET", "/api/cofre")
        self.assertEqual(st, 403)
        st, _, _ = leitor.req("GET", "/api/usuarios")
        self.assertEqual(st, 403)
        # não-admin não remove o último admin; admin não remove a si mesmo
        st, lista, _ = self.admin.req("GET", "/api/usuarios")
        uid_admin = next(u["id"] for u in lista if u["nome"] == "admin")
        st, _, _ = self.admin.req("DELETE", f"/api/usuarios/{uid_admin}")
        self.assertEqual(st, 409)
        # bloqueio após 5 senhas erradas, mesmo com a senha certa depois
        x = Cliente(self.porta)
        for _ in range(5):
            x.req("POST", "/api/sessao", {"usuario": "leitor", "senha": "errada"})
        st, _, _ = x.req("POST", "/api/sessao", {"usuario": "leitor", "senha": "Leitor-Final-2026"})
        self.assertEqual(st, 401)
        uid = next(u["id"] for u in lista if u["nome"] == "leitor")
        st, _, _ = self.admin.req("POST", f"/api/usuarios/{uid}/desbloquear", {})
        self.assertEqual(st, 200)
        # desativar encerra a sessão aberta
        self.admin.req("POST", f"/api/usuarios/{uid}/alterar", {"ativo": False})
        st, _, _ = leitor.req("GET", "/api/inventario")
        self.assertEqual(st, 401)

    def test_07b_snapshot_sensivel_e_arquivos_da_pasta(self):
        pasta = os.path.join(self.dados, "snapshots")
        self.assertTrue(os.path.isdir(pasta))
        base = ("---\nhost: \"sens\"\nip: \"192.0.2.77\"\nplatform_key: \"linux\"\n"
                "sensitive_data: \"{}\"\n---\n\n## Configuração\n\n### `x`\n\n```text\nok\n```\n")
        with open(os.path.join(pasta, "sens_192.0.2.77_20261024_100000.md"), "w") as f:
            f.write(base.format("included"))
        with open(os.path.join(pasta, "_debug_20261024_100000.log"), "w") as f:
            f.write("depuracao")
        st, _, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "leitor2", "senha": "Leitor2-Temp-2026", "papel": "leitura"})
        self.assertEqual(st, 200)
        leitor = Cliente(self.porta)
        st, r, _, _ = leitor.entrar("leitor2", "Leitor2-Temp-2026", nova="Leitor2-Final-2026")
        self.assertEqual(st, 200, r)
        nome = "sens_192.0.2.77_20261024_100000.md"
        for rota in (f"/api/snapshots/{nome}", f"/api/arquivo/snapshot/{nome}"):
            st, _, _ = leitor.req("GET", rota)
            self.assertEqual(st, 403, rota)
            st, _, _ = self.admin.req("GET", rota)
            self.assertEqual(st, 200, rota)
        st, _, _ = self.admin.req("GET", "/api/arquivo/snapshot/_debug_20261024_100000.log")
        self.assertEqual(st, 400)
        st, aud, _ = self.admin.req("GET", "/api/auditoria")
        texto = json.dumps(aud)
        self.assertIn("snapshot_sensivel_negado", texto)
        self.assertIn("snapshot_sensivel_lido", texto)
        os.remove(os.path.join(pasta, nome))

    def test_08_bloqueio_distribuido_nao_tranca_dispositivo_conhecido(self):
        st, r, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "alvo", "senha": "Alvo-Temp-2026!", "papel": "leitura"})
        dono = Cliente(self.porta)
        st, r, _, segredo = dono.entrar("alvo", "Alvo-Temp-2026!", nova="Alvo-Final-2026!")
        self.assertEqual(st, 200, r)
        self.assertTrue(dono.disp, "cookie de dispositivo não foi criado")
        atacante = Cliente(self.porta)
        for i in range(6):  # 6 origens x 5 erros = 30: conta inteira bloqueada
            for _ in range(5):
                atacante.req("POST", "/api/sessao", {"usuario": "alvo", "senha": "errada"},
                             cabecalhos={"X-Real-IP": f"203.0.113.{i + 10}"})
        novo = Cliente(self.porta)
        st, _, _ = novo.req("POST", "/api/sessao", {"usuario": "alvo", "senha": "Alvo-Final-2026!"},
                            cabecalhos={"X-Real-IP": "198.51.100.7"})
        self.assertEqual(st, 401)  # navegador desconhecido: conta bloqueada
        dono.cookie = ""
        st, r, etapas, _ = dono.entrar("alvo", "Alvo-Final-2026!", segredo=segredo)
        self.assertEqual(st, 200, r)  # navegador de sempre: entra

    def test_08b_erros_no_mesmo_nat_nao_trancam_dispositivo_conhecido(self):
        st, r, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "vizinho", "senha": "Vizinho-Temp-2026", "papel": "leitura"})
        dono = Cliente(self.porta)
        st, r, _, segredo = dono.entrar("vizinho", "Vizinho-Temp-2026",
                                        nova="Vizinho-Final-2026")
        self.assertEqual(st, 200, r)
        nat = {"X-Real-IP": "192.0.2.200"}
        atacante = Cliente(self.porta)
        for _ in range(6):
            atacante.req("POST", "/api/sessao", {"usuario": "vizinho", "senha": "errada"},
                         cabecalhos=nat)
        st, _, _ = atacante.req("POST", "/api/sessao", {"usuario": "vizinho",
                                                        "senha": "Vizinho-Final-2026"},
                                cabecalhos=nat)
        self.assertEqual(st, 401)  # navegador desconhecido segue bloqueado
        dono.cookie = ""
        st, r, _ = dono.req("POST", "/api/sessao", {"usuario": "vizinho",
                                                    "senha": "Vizinho-Final-2026"},
                            cabecalhos=nat)
        self.assertEqual((st, r.get("etapa")), (200, "totp"), r)
        # TOTP redefinido pelo admin no meio do login: 401, não erro interno.
        # (De outra origem: a redefinição esquece o navegador, e o NAT acima
        # já está bloqueado para desconhecidos.)
        outra = {"X-Real-IP": "192.0.2.203"}
        st, r, _ = dono.req("POST", "/api/sessao", {"usuario": "vizinho",
                                                    "senha": "Vizinho-Final-2026"},
                            cabecalhos=outra)
        self.assertEqual((st, r.get("etapa")), (200, "totp"), r)
        st, lista, _ = self.admin.req("GET", "/api/usuarios")
        uid = next(u["id"] for u in lista if u["nome"] == "vizinho")
        self.admin.req("POST", f"/api/usuarios/{uid}/totp", {})
        st, r, _ = dono.req("POST", "/api/sessao/etapa", {
            "desafio": r["desafio"], "codigo": codigo_livre(segredo)}, cabecalhos=outra)
        self.assertEqual(st, 401, r)
        self.assertIn("expirada", r["erro"])

    def test_08c_nome_desconhecido_mascarado_na_auditoria(self):
        Cliente(self.porta).req("POST", "/api/sessao", {"usuario": "Senha-Digitada-Aqui!",
                                                        "senha": "x"},
                                cabecalhos={"X-Real-IP": "192.0.2.201"})
        st, aud, _ = self.admin.req("GET", "/api/auditoria?limite=50&acao=login_falha")
        self.assertNotIn("digitada", json.dumps(aud).lower())
        self.assertTrue(any(x["usuario"].startswith("se…(20) #") for x in aud), aud[:3])
        with open(self.log.name) as f:
            self.assertNotIn("digitada", f.read().lower())

    def test_08d_um_calculo_de_senha_por_origem(self):
        barreira = threading.Barrier(6)
        estados = []

        def tentar(i):
            barreira.wait()
            st, _, _ = Cliente(self.porta).req(
                "POST", "/api/sessao", {"usuario": f"ninguem{i}", "senha": "x"},
                cabecalhos={"X-Real-IP": "192.0.2.202"})
            estados.append(st)
        fios = [threading.Thread(target=tentar, args=(i,)) for i in range(6)]
        for f in fios:
            f.start()
        for f in fios:
            f.join()
        self.assertIn(429, estados)
        self.assertIn(401, estados)
        self.assertNotIn(503, estados)

    def test_09_tcp_so_em_modo_de_teste(self):
        conf = os.path.join(self.dir, "sem_tcp.conf")
        texto = open(self.conf).read().replace("tcp_para_testes = sim\n", "")
        open(conf, "w").write(texto.replace(f"porta = {self.porta}", f"porta = {porta_livre()}"))
        r = subprocess.run([sys.executable, os.path.join(APP, "netsnap_servidor.py"), "--config", conf],
                           capture_output=True, text=True, timeout=60, env=dict(os.environ, HOME=self.dados))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("socket do systemd", r.stderr + r.stdout)

    # -- cofre, coleta, agendamento, análise -------------------------------
    def test_10_cofre_nao_devolve_senha(self):
        st, r, _ = self.admin.req("POST", "/api/cofre", {
            "nome": "sem-rede", "usuario": "netsnap", "senha": "Lab#2026!"})
        self.assertEqual(st, 400)  # redes obrigatórias
        st, r, _ = self.admin.req("POST", "/api/cofre", {
            "nome": "lab", "usuario": "netsnap", "senha": "Lab#2026!", "descricao": "laboratório",
            "redes": [f"{LAB}/32"]})
        self.assertEqual(st, 200, r)
        self.__class__.cid = r["id"]
        st, lista, _ = self.admin.req("GET", "/api/cofre")
        self.assertEqual(lista[0]["usuario"], "netsnap")
        self.assertNotIn("Lab#2026!", json.dumps(lista))
        bruto = b""
        for suf in ("", "-wal"):
            p = os.path.join(self.dados, "netsnap.db" + suf)
            if os.path.exists(p):
                bruto += open(p, "rb").read()
        self.assertNotIn(b"Lab#2026!", bruto)

    def esperar(self, job_id, limite=240):
        t0 = time.time()
        while time.time() - t0 < limite:
            st, d, _ = self.admin.req("GET", f"/api/jobs/{job_id}")
            if d["estado"] != "executando":
                return d
            time.sleep(2)
        self.fail("execução não terminou")

    def exigir_lab(self):
        if self.sem_lab:
            self.skipTest(self.sem_lab)

    def test_11_coleta_com_credencial_do_cofre(self):
        self.exigir_lab()
        st, r, _ = self.admin.req("POST", "/api/coletas", {
            "alvos": LAB, "modo": "8", "protocolo": "ssh", "credencial": self.cid,
            "varredura": "deep", "instancias": 2, "sensivel": True})
        self.assertEqual(st, 200, r)
        d = self.esperar(r["id"])
        self.assertEqual(d["estado"], "concluido", d)
        self.assertEqual(d["lista_hosts"][0]["estado"], "ok", d["lista_hosts"])
        self.assertEqual(d["config"]["iniciado_por"], "admin")
        self.assertFalse(d["config"]["sensivel"])  # política do servidor
        self.assertNotIn("Lab#2026!", json.dumps(d))
        # Usuário do equipamento é parte da credencial: só o número aparece.
        self.assertEqual(d["config"]["credencial"], self.cid)
        self.assertNotIn("usuario", d["config"])
        snaps = os.listdir(os.path.join(self.dados, "snapshots"))
        self.assertTrue(any(n.endswith(".md") for n in snaps))
        self.__class__.primeiro_job = r["id"]

    def test_12_agendamento_e_pacote_de_analise(self):
        self.exigir_lab()
        base = {"nome": "Diário lab", "alvos": LAB, "modo": "8", "protocolo": "ssh",
                "varredura": "deep", "instancias": 2, "credencial": self.cid, "analise": True}
        for freq, esperado in (({"tipo": "diario", "hora": "03:00"}, "todo dia às 03:00"),
                               ({"tipo": "semanal", "hora": "02:30", "dias_semana": [0, 3]},
                                "seg, qui às 02:30"),
                               ({"tipo": "dias", "hora": "04:00", "a_cada": 7}, "a cada 7 dias às 04:00"),
                               ({"tipo": "horas", "a_cada": 6}, "a cada 6 h")):
            st, r, _ = self.admin.req("POST", "/api/agendamentos", dict(base, frequencia=freq))
            self.assertEqual(st, 200, r)
            self.assertEqual(r["frequencia_texto"], esperado)
            self.assertEqual(r["credencial_nome"], "lab")
            ag = r["id"]
        st, r, _ = self.admin.req("POST", "/api/agendamentos", dict(
            base, frequencia={"tipo": "semanal", "hora": "02:30", "dias_semana": []}))
        self.assertEqual(st, 400)
        st, _, _ = self.admin.req("DELETE", f"/api/cofre/{self.cid}")
        self.assertEqual(st, 400)  # em uso
        st, job, _ = self.admin.req("POST", f"/api/agendamentos/{ag}/executar", {})
        self.assertEqual(st, 200, job)
        d = self.esperar(job["id"])
        self.assertEqual(d["estado"], "concluido")
        for _ in range(60):
            st, analises, _ = self.admin.req("GET", "/api/analises")
            if analises:
                break
            time.sleep(1)
        self.assertTrue(analises, "pacote de análise não foi gerado")
        a = analises[0]
        st, corpo, h = self.admin.req("GET", f"/api/analises/{a['id']}/baixar")
        self.assertEqual(st, 200)
        caminho = os.path.join(self.dir, "pacote.zip")
        with open(caminho, "wb") as f:
            f.write(corpo)
        z = zipfile.ZipFile(caminho)
        nomes = z.namelist()
        for n in ("manifesto.json", "resumo.json", "RESUMO.md", "PROMPT.md"):
            self.assertIn(n, nomes)
        self.assertTrue(any(n.startswith("snapshots/") for n in nomes))
        resumo = json.loads(z.read("resumo.json"))
        self.assertEqual(resumo[0]["ip"], LAB)
        self.assertIsNotNone(resumo[0]["mudanca_config"])  # há coleta anterior
        man = json.loads(z.read("manifesto.json"))
        z.close()
        self.assertEqual(man["totais"]["ok"], 1)
        st, ags, _ = self.admin.req("GET", "/api/agendamentos")
        este = next(x for x in ags if x["id"] == ag)
        self.assertEqual(este["ultimo_estado"], "concluido")

    def test_14_credencial_presa_as_redes(self):
        """A senha do cofre não pode ser desviada para um host qualquer."""
        base = {"modo": "8", "protocolo": "ssh", "credencial": self.cid, "varredura": "deep"}
        for alvos in ("10.9.9.9", f"{LAB}\n10.9.9.9", "localhost", "127.0.0.0/30"):
            st, r, _ = self.admin.req("POST", "/api/coletas", dict(base, alvos=alvos))
            self.assertEqual(st, 403, (alvos, r))
            self.assertIn("só pode ser usada", r["erro"])
        st, r, _ = self.admin.req("POST", "/api/netdiag", dict(base, alvos="10.9.9.9"))
        self.assertEqual(st, 403)
        st, r, _ = self.admin.req("POST", "/api/coletas", dict(base, alvos=LAB,
                                                               protocolo="telnet", porta=23))
        self.assertEqual(st, 403)
        self.assertIn("Telnet", r["erro"])
        st, r, _ = self.admin.req("POST", "/api/agendamentos", dict(
            base, nome="desvio", alvos="10.9.9.9", frequencia={"tipo": "horas", "a_cada": 1}))
        self.assertEqual(st, 403)
        # técnico: cria a própria credencial, mas não libera Telnet nem muda redes
        st, r, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "tec", "senha": "Tecnico-Temp-2026", "papel": "tecnico"})
        tec = Cliente(self.porta)
        st, r, _, _ = tec.entrar("tec", "Tecnico-Temp-2026", nova="Tecnico-Final-2026")
        self.assertEqual(st, 200, r)
        st, r, _ = tec.req("POST", "/api/cofre", {"nome": "tec-cred", "usuario": "u", "senha": "s",
                                                  "redes": ["10.50.0.0/16"], "telnet": True})
        self.assertEqual(st, 403)
        st, r, _ = tec.req("POST", "/api/cofre", {"nome": "tec-cred", "usuario": "u", "senha": "s",
                                                  "redes": ["10.50.0.0/16"]})
        self.assertEqual(st, 200, r)
        st, r, _ = tec.req("POST", f"/api/cofre/{r['id']}", {"redes": ["10.0.0.0/8"]})
        self.assertEqual(st, 403)
        st, r, _ = tec.req("POST", f"/api/cofre/{self.cid}", {"senha": "x"})
        self.assertEqual(st, 403)  # credencial de outra pessoa
        st, r, _ = tec.req("POST", "/api/netcve", {"sem_rede": True, "inseguro": True})
        self.assertEqual(st, 403)  # TLS das bases de CVE: só admin desliga
        # último administrador não é desativado nem com ativo=0
        st, lista, _ = self.admin.req("GET", "/api/usuarios")
        uid_admin = next(u["id"] for u in lista if u["nome"] == "admin")
        st, _, _ = self.admin.req("POST", f"/api/usuarios/{uid_admin}/alterar", {"ativo": 0})
        self.assertEqual(st, 409)

    def test_13_historico_e_limite_de_execucoes(self):
        self.exigir_lab()
        st, lista, _ = self.admin.req("GET", "/api/jobs")
        self.assertTrue(any(j["id"] == self.primeiro_job for j in lista))

    def test_20_auditoria_integra(self):
        st, r, _ = self.admin.req("GET", "/api/auditoria?verificar=1")
        self.assertEqual(r, {"integra": True, "primeiro_invalido": None})
        st, lista, _ = self.admin.req("GET", "/api/auditoria?limite=1000")
        acoes = {x["acao"] for x in lista}
        esperadas = ["login_ok", "login_falha", "totp_cadastrado", "senha_trocada",
                     "credencial_criada", "recuperacao_usada", "usuario_criado"]
        if not self.sem_lab:
            esperadas += ["coleta_iniciada", "agendamento_criado", "agendamento_executado"]
        for a in esperadas:
            self.assertIn(a, acoes)

    def test_25_rebaixamento_simultaneo_mantem_um_admin(self):
        st, r, _ = self.admin.req("POST", "/api/usuarios", {
            "usuario": "admin2", "senha": "Admin2-Temp-2026", "papel": "admin"})
        self.assertEqual(st, 200, r)
        outro = Cliente(self.porta)
        st, r, _, _ = outro.entrar("admin2", "Admin2-Temp-2026", nova="Admin2-Final-2026")
        self.assertEqual(st, 200, r)
        st, lista, _ = self.admin.req("GET", "/api/usuarios")
        ids = {u["nome"]: u["id"] for u in lista}
        barreira = threading.Barrier(2)
        estados = {}

        def rebaixar(cliente, alvo):
            barreira.wait()
            estados[alvo] = cliente.req("POST", f"/api/usuarios/{ids[alvo]}/alterar",
                                        {"papel": "tecnico"})[0]
        fios = [threading.Thread(target=rebaixar, args=(self.admin, "admin2")),
                threading.Thread(target=rebaixar, args=(outro, "admin"))]
        for f in fios:
            f.start()
        for f in fios:
            f.join()
        # Um passa; o outro esbarra no último administrador (409) ou, se
        # chegou depois, já teve a sessão encerrada pelo rebaixamento (401).
        self.assertEqual(list(estados.values()).count(200), 1, estados)
        self.assertTrue(set(estados.values()) <= {200, 401, 409}, estados)
        if estados["admin"] == 200:
            # O admin principal foi rebaixado: o outro devolve o perfil para os
            # testes seguintes.
            st, _, _ = outro.req("POST", f"/api/usuarios/{ids['admin']}/alterar",
                                 {"papel": "admin"})
            self.assertEqual(st, 200)

    def test_30_logout(self):
        c = Cliente(self.porta)
        c.entrar("admin", SENHA_NOVA, segredo=self.segredo_admin)
        st, _, h = c.req("DELETE", "/api/sessao")
        self.assertEqual(st, 200)
        st, _, _ = c.req("GET", "/api/painel")
        self.assertEqual(st, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
