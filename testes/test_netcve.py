"""Testes do netcve sem rede: CVSS, versões de pacote, extração de pacotes,
ecossistema OSV, catálogo de falhas graves (com a condição de exposição) e
KEV por fabricante. Os snapshots são sintéticos, no formato do netsnap.

uso: python3 testes/test_netcve.py
     NETCVE_TESTE_REDE=1 python3 testes/test_netcve.py   (inclui consulta real ao OSV)

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
Licenciado sob a licença MIT.
"""
import csv
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import netcve as n  # noqa: E402


def snapshot(plataforma, blocos):
    """blocos: [(seção, comando, saída)]"""
    linhas = ["---", 'netsnap_version: "1.17.1"', 'host: "teste"',
              'ip: "192.0.2.10"', f'platform_key: "{plataforma}"',
              f'platform_name: "{plataforma}"', "---", ""]
    secao_atual = None
    for secao, cmd, saida in blocos:
        if secao != secao_atual:
            linhas += [f"## {secao}", ""]
            secao_atual = secao
        linhas += [f"### `{cmd}`", "", "```text", "", saida, "```", ""]
    return "\n".join(linhas)


DPKG = ("if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f "
        "'${db:Status-Abbrev}\\t${Package}\\t${Version}' | grep '^ii' | cut -f2-; fi")
PHP = "command -v php >/dev/null 2>&1 && php -v; for f in /etc/php/*/*/php.ini"
OS_RELEASE = ('PRETTY_NAME="Ubuntu 24.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
              'VERSION="24.04.3 LTS (Noble Numbat)"\nID=ubuntu')


class TesteCVSS(unittest.TestCase):
    def test_notas_conhecidas(self):
        casos = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vetor, esperado in casos.items():
            self.assertEqual(n.nota_cvss3(vetor), esperado, vetor)
        self.assertIsNone(n.nota_cvss3("CVSS:4.0/AV:N/AC:L"))
        self.assertIsNone(n.nota_cvss3("CVSS:3.1/AV:X"))


class TesteVersoes(unittest.TestCase):
    def test_dpkg(self):
        k = n.chave_versao_pacote
        self.assertTrue(k("1.0~rc1") < k("1.0"))
        self.assertTrue(k("8.3.6-0ubuntu0.24.04.11") < k("8.3.6-0ubuntu0.24.04.13"))
        self.assertTrue(k("1.2") < k("1.10"))
        self.assertFalse(k("1:1.0") < k("9.9"))
        self.assertFalse(k("2.4.58-1ubuntu8.10") < k("2.4.58-1ubuntu8.9"))

    def test_faixas(self):
        f = n.CATALOGO[1]["faixas"]   # MikroTrick
        self.assertEqual(n.situacao_por_faixa("7.22.1", f), "vulneravel")
        self.assertEqual(n.situacao_por_faixa("7.23.4", f), "parcial")
        self.assertEqual(n.situacao_por_faixa("7.23.7", f), "corrigida")
        self.assertEqual(n.situacao_por_faixa("7.24.1", f), "vulneravel")
        self.assertEqual(n.situacao_por_faixa("6.49.10", f), "vulneravel")
        p = n.CATALOGO[0]["faixas"]   # PHP2Shell
        self.assertEqual(n.situacao_por_faixa("8.2.34", p), "vulneravel")
        self.assertEqual(n.situacao_por_faixa("8.2.35", p), "corrigida")
        self.assertEqual(n.situacao_por_faixa("8.1.2", p), "sem_correcao")


class TestePacotes(unittest.TestCase):
    def test_dpkg_com_fonte(self):
        saida = ("php8.3-fpm\t8.3.6-0ubuntu0.24.04.11\tamd64\tphp8.3\t8.3.6-0ubuntu0.24.04.11\n"
                 "openssh-server\t1:9.6p1-3ubuntu13.19\tamd64\topenssh\t1:9.6p1-3ubuntu13.19\n"
                 "libc6\t2.39-0ubuntu8.6\tamd64\tglibc\t2.39-0ubuntu8.6")
        t = snapshot("linux", [("Inventário", DPKG, saida)])
        pacotes, precisao = n.extrair_pacotes(t)
        self.assertEqual(precisao, "fonte")
        self.assertEqual([p["fonte"] for p in pacotes], ["php8.3", "openssh", "glibc"])

    def test_dpkg_fonte_com_versao_entre_parenteses(self):
        saida = "libfoo1\t1.2-3+b1\tamd64\tfoo (1.2-3)\t1.2-3"
        pacotes, _ = n.extrair_pacotes(snapshot("linux", [("Inventário", DPKG, saida)]))
        self.assertEqual(pacotes[0]["fonte"], "foo")

    def test_rpm(self):
        cmd = "else rpm -qa --qf '%{NAME}'"
        saida = ("openssh-server\t(none):8.7p1-38.el9_4.4\tx86_64\topenssh-8.7p1-38.el9_4.4.src.rpm\n"
                 "php-fpm\t0:8.1.27-1.el9\tx86_64\tphp-8.1.27-1.el9.src.rpm")
        pacotes, _ = n.extrair_pacotes(snapshot("linux", [("Inventário", cmd, saida)]))
        self.assertEqual(pacotes[0]["fonte"], "openssh")
        self.assertEqual(pacotes[0]["versao"], "8.7p1-38.el9_4.4")
        self.assertEqual(pacotes[1]["fonte"], "php")

    def test_snapshot_antigo_sem_fonte(self):
        saida = "openssh-server\t1:9.6p1-3ubuntu13.19\tamd64"
        pacotes, precisao = n.extrair_pacotes(snapshot("linux", [("Inventário", DPKG, saida)]))
        self.assertEqual(precisao, "binario")
        self.assertEqual(pacotes[0]["fonte"], "openssh-server")

    def test_ecossistema(self):
        self.assertEqual(n.ecossistema_osv(OS_RELEASE), "Ubuntu:24.04:LTS")
        self.assertEqual(n.ecossistema_osv('ID=debian\nVERSION_ID="12"'), "Debian:12")
        self.assertEqual(n.ecossistema_osv('ID="rocky"\nVERSION_ID="9.4"'), "Rocky Linux:9")
        self.assertEqual(n.ecossistema_osv('ID="almalinux"\nVERSION_ID="8.10"'), "AlmaLinux:8")
        self.assertIsNone(n.ecossistema_osv('ID=arch\nVERSION_ID=rolling'))
        self.assertEqual(n.ecossistema_osv('ID=ubuntu\nVERSION_ID="25.04"\n'
                                           'VERSION="25.04 (Plucky)"'), "Ubuntu:25.04")


def osv_php(vulneravel):
    vulns = []
    if vulneravel:
        vulns.append({"id": "UBUNTU-CVE-2026-109618", "cves": ["CVE-2026-109618"],
                      "nota": None, "severidade": "CRITICAL",
                      "corrigida": "8.3.6-0ubuntu0.24.04.13"})
    return [{"pacote": "php8.3", "versao": "8.3.6-0ubuntu0.24.04.11",
             "binarios": ["php8.3-fpm"], "vulns": vulns}] if vulns else []


class TesteCatalogo(unittest.TestCase):
    def php_snapshot(self, fpm=True, mitigado=False):
        saida_php = ("PHP 8.3.6 (cli) (built: Sep  2 2026 12:56:02) (NTS)\n"
                     "===== /etc/php/8.3/cli/php.ini\nmemory_limit = -1\n"
                     "===== /etc/php/8.3/fpm/php.ini\n"
                     + ("memory_limit = -1\nsession.upload_progress.enabled = 0\n"
                        if mitigado else "memory_limit = 128M\n")
                     + ("php8.3-fpm.service loaded active running The PHP 8.3 FastCGI Process Manager\n"
                        if fpm else ""))
        saida_dpkg = "php8.3-fpm\t8.3.6-0ubuntu0.24.04.11\tamd64\tphp8.3\t8.3.6-0ubuntu0.24.04.11"
        return snapshot("linux", [("Inventário", DPKG, saida_dpkg),
                                  ("Inventário", PHP, saida_php),
                                  ("Configuração", "cat /etc/os-release", OS_RELEASE)])

    def avaliar(self, texto, osv):
        meta = {"platform_key": "linux"}
        versoes = n.extrair_versoes(meta, texto)
        return n.avaliar_catalogo(meta, texto, versoes, osv)

    def test_php2shell_pelo_pacote_da_distribuicao(self):
        achados = self.avaliar(self.php_snapshot(), osv_php(True))
        self.assertEqual([a["id"] for a in achados], ["PHP2SHELL"])
        a = achados[0]
        self.assertEqual(a["situacao"], "vulneravel")
        self.assertIn("corrigido em 8.3.6-0ubuntu0.24.04.13", a["base"])
        self.assertIn("PHP-FPM ativo", a["exposicao"])
        self.assertEqual(a["mitigacoes"], [])   # memory_limit=-1 só na CLI

    def test_php2shell_distribuicao_ja_corrigiu(self):
        # 8.3.6 pela versão upstream seria vulnerável; o OSV diz que não.
        self.assertEqual(self.avaliar(self.php_snapshot(), osv_php(False)), [])

    def test_php2shell_sem_osv_usa_upstream_e_avisa(self):
        a = self.avaliar(self.php_snapshot(), None)[0]
        self.assertEqual(a["situacao"], "vulneravel")
        self.assertIn("retroportadas", a["base"])

    def test_php2shell_mitigacoes_do_fpm(self):
        a = self.avaliar(self.php_snapshot(mitigado=True), osv_php(True))[0]
        self.assertEqual(len(a["mitigacoes"]), 2)

    def test_mikrotrick_exposto(self):
        t = snapshot("mikrotik_routeros", [
            ("Inventário", "/system resource print",
             "             uptime: 3w1d\n            version: 7.22.1 (stable)"),
            ("Estado", "/ip service print detail without-paging",
             "Flags: X - DISABLED, I - INVALID\n"
             " 0 X  name=\"telnet\" port=23 address=\"\"\n"
             " 3    name=\"ssh\" port=22 address=\"\" vrf=main max-sessions=20\n"
             " 6    name=\"winbox\" port=8291 address=10.0.0.0/8"),
            ("Estado", "/tool bandwidth-server print",
             "                  enabled: yes\n           authenticate: yes"),
            ("Estado", "/system device-mode print",
             "       mode: advanced\n    flagged: yes"),
            ("Estado", "/user print without-paging",
             "Columns: NAME, GROUP\n # NAME   GROUP\n 0 admin  full\n 1 ops    full"),
        ])
        meta = {"platform_key": "mikrotik_routeros"}
        a = n.avaliar_catalogo(meta, t, n.extrair_versoes(meta, t), None)[0]
        self.assertEqual(a["id"], "MIKROTRICK")
        self.assertEqual(a["situacao"], "vulneravel")
        self.assertEqual(len(a["exposicao"]), 4, a["exposicao"])

    def test_mikrotrick_restrito_e_atualizado(self):
        t = snapshot("mikrotik_routeros", [
            ("Inventário", "/system resource print", "            version: 7.23.7 (long-term)"),
            ("Estado", "/ip service print detail without-paging",
             " 3    name=\"ssh\" port=2222 address=10.0.0.0/8")])
        meta = {"platform_key": "mikrotik_routeros"}
        self.assertEqual(n.avaliar_catalogo(meta, t, n.extrair_versoes(meta, t), None), [])

    def test_bandwidth_server_desligado_nao_conta(self):
        t = snapshot("mikrotik_routeros", [
            ("Inventário", "/system resource print", "            version: 7.20.2"),
            ("Estado", "/ip cloud print", "          ddns-enabled: yes"),
            ("Estado", "/tool bandwidth-server print", "                  enabled: no")])
        meta = {"platform_key": "mikrotik_routeros"}
        a = n.avaliar_catalogo(meta, t, n.extrair_versoes(meta, t), None)[0]
        self.assertEqual(a["exposicao"], [])

    def test_catalogo_extra_valida_estrutura(self):
        import json
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([{"id": "X"}], f)
        with self.assertRaises(ValueError):
            n.carregar_catalogo_extra(f.name)
        os.unlink(f.name)


class TesteCobertura(unittest.TestCase):
    def versoes(self, uname):
        texto = uname + "\nPHP 8.3.6 (cli)\n"
        return [{"rotulo": "Kernel Linux", "versao": "x", "consultavel": True, "cves": None},
                {"rotulo": "PHP", "versao": "8.3.6", "consultavel": True, "cves": None},
                {"rotulo": "OpenSSH", "versao": "9.6p1", "consultavel": True, "cves": None}], texto

    def test_kernel_do_pacote_e_php_da_distribuicao(self):
        v, t = self.versoes("Linux srv 6.8.0-146-generic #146-Ubuntu SMP")
        pacotes = [{"fonte": "linux", "versao_fonte": "6.8.0-146.146", "binario": "linux-image-6.8.0-146-generic", "versao": "6.8.0-146.146"},
                   {"fonte": "php8.3", "versao_fonte": "8.3.6-0ubuntu0.24.04.11", "binario": "php8.3-fpm", "versao": "8.3.6-0ubuntu0.24.04.11"}]
        n.marcar_cobertura_osv(v, t, pacotes)
        self.assertTrue(v[0].get("coberto_osv"))
        self.assertTrue(v[1].get("coberto_osv"))
        self.assertTrue(v[2]["consultavel"])          # openssh não instalado por pacote

    def test_kernel_com_reinicio_pendente_nao_vai_para_nvd(self):
        v, t = self.versoes("Linux srv 6.8.0-140-generic #140-Ubuntu SMP")
        pacotes = [{"fonte": "linux", "versao_fonte": "6.8.0-146.146", "binario": "x", "versao": "y"}]
        n.marcar_cobertura_osv(v, t, pacotes)
        self.assertFalse(v[0]["consultavel"])
        self.assertIn("reinício", v[0]["motivo"])

    def test_kernel_compilado_a_mao_vai_para_nvd(self):
        v, t = self.versoes("Linux vm 6.18.44 #1 SMP")
        n.marcar_cobertura_osv(v, t, [{"fonte": "linux", "versao_fonte": "6.8.0-146.146",
                                       "binario": "x", "versao": "y"}])
        self.assertTrue(v[0]["consultavel"])
        self.assertNotIn("motivo", v[0])


    def test_kernel_prefixo_nao_casa_abi_maior(self):
        # 6.8.0-14 rodando, só o pacote 6.8.0-146 instalado: reinício pendente
        v, t = self.versoes("Linux srv 6.8.0-14-generic #14-Ubuntu SMP")
        n.marcar_cobertura_osv(v, t, [{"fonte": "linux", "versao_fonte": "6.8.0-146.146",
                                       "binario": "linux-image-6.8.0-146-generic",
                                       "versao": "6.8.0-146.146"}])
        self.assertFalse(v[0].get("coberto_osv"))
        self.assertIn("reinício", v[0]["motivo"])

    def test_kernel_debian_pelo_binario(self):
        v, t = self.versoes("Linux srv 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1")
        n.marcar_cobertura_osv(v, t, [{"fonte": "linux", "versao_fonte": "6.1.76-1",
                                       "binario": "linux-image-6.1.0-18-amd64",
                                       "versao": "6.1.76-1"}])
        self.assertTrue(v[0].get("coberto_osv"))

    def test_kernel_hwe_do_ubuntu(self):
        v, t = self.versoes("Linux srv 6.8.0-45-generic #45~22.04.1-Ubuntu SMP")
        n.marcar_cobertura_osv(v, t, [{"fonte": "linux-signed-hwe-6.8",
                                       "versao_fonte": "6.8.0-45.45~22.04.1",
                                       "binario": "linux-image-6.8.0-45-generic",
                                       "versao": "6.8.0-45.45~22.04.1"}])
        self.assertTrue(v[0].get("coberto_osv"))


class TesteRevisao(unittest.TestCase):
    def test_routeros_versao_ponto_zero_e_vulneravel(self):
        cat = next(e for e in n.CATALOGO if e["id"] == "MIKROTRICK")
        self.assertEqual(n.situacao_por_faixa("7.24", cat["faixas"]), "vulneravel")
        self.assertEqual(n.situacao_por_faixa("7.24.0", cat["faixas"]), "vulneravel")
        self.assertEqual(n.situacao_por_faixa("7.24.3", cat["faixas"]), "corrigida")

    def test_comunidade_trivial_mascarada_ainda_e_apontada(self):
        import netsnap as ns
        for texto in ("snmp-server community public RO",
                      "/snmp community\nset [ find default=yes ] name=public"):
            snap = ns.sanitizar(snapshot("cisco_ios", [("Configuração", "c", texto)]))
            ids = [a["id"] for a in n.avaliar_config({"platform_key": "cisco_ios"}, snap)]
            self.assertIn("CFG-SNMP-COMUNIDADE-PADRAO", ids, texto)
        snap = ns.sanitizar(snapshot("cisco_ios", [("Configuração", "c",
                                                    "snmp-server community Xk9forte RO")]))
        ids = [a["id"] for a in n.avaliar_config({"platform_key": "cisco_ios"}, snap)]
        self.assertNotIn("CFG-SNMP-COMUNIDADE-PADRAO", ids)

    def regras(self, plataforma, blocos):
        meta = {"platform_key": plataforma, "sensitive_data": "redacted"}
        return {a["id"]: a for a in n.avaliar_config(meta, snapshot(plataforma, blocos))}

    def test_netsnmp_comunidade_no_linux(self):
        import netsnap as ns
        conf = ("===== /etc/snmp/snmpd.conf\n"
                "rocommunity LinhaForteXyz 10.0.0.0/8\n"
                "rocommunity public default\n")
        snap = ns.sanitizar(snapshot("linux", [("Configuração", "c", conf)]))
        ids = [a["id"] for a in n.avaliar_config({"platform_key": "linux"}, snap)]
        self.assertIn("CFG-SNMPV1V2", ids)
        self.assertIn("CFG-SNMP-COMUNIDADE-PADRAO", ids)  # 'public' marcada
        self.assertNotIn("LinhaForteXyz", snap)  # valor forte mascarado

    def test_heuristicas_so_na_configuracao(self):
        r = self.regras("juniper_junos", [
            ("Configuração", "show configuration | display set", "set system host-name x"),
            ("Logs", "show log messages", "UI_CMDLINE_READ_LINE: User 'x', command "
                                          "'set snmp community public authorization read-only '"),
        ])
        self.assertNotIn("CFG-SNMPV1V2", r)
        self.assertNotIn("CFG-SNMP-COMUNIDADE-PADRAO", r)

    def test_ntp_com_e_sem_autenticacao(self):
        sem = self.regras("juniper_junos", [("Configuração", "c",
            "set system ntp server 192.0.2.1\n"
            "set system login user noc authentication encrypted-password \"x\"")])
        self.assertIn("CFG-NTP-SEM-AUTENTICACAO", sem)
        self.assertEqual(sem["CFG-NTP-SEM-AUTENTICACAO"]["evidencia"],
                         "set system ntp server 192.0.2.1")
        com = self.regras("juniper_junos", [("Configuração", "c",
            "set system ntp authentication-key 1 type md5 value \"$9$x\"\n"
            "set system ntp server 192.0.2.1 key 1\nset system ntp trusted-key 1")])
        self.assertNotIn("CFG-NTP-SEM-AUTENTICACAO", com)

    def test_telnet_entre_outros_transportes_e_dns_comentado(self):
        r = self.regras("cisco_ios", [("Configuração", "c",
                                       "line vty 0 4\n transport input ssh telnet")])
        self.assertIn("CFG-TELNET", r)
        r = self.regras("linux", [("Configuração", "c",
                                   "options {\n recursion yes;\n"
                                   "// allow-recursion { any; };\n"
                                   " allow-recursion { 10.0.0.0/8; };\n};")])
        self.assertNotIn("CFG-DNS-RECURSAO-ABERTA", r)

    def test_routeros_snmpv3_nao_e_v2c(self):
        v3 = self.regras("mikrotik_routeros", [("Configuração", "/export", (
            "/snmp community\nset [ find default=yes ] disabled=yes\n"
            "add authentication-protocol=SHA1 name=nms security=private"))])
        self.assertNotIn("CFG-SNMPV1V2", v3)
        v2 = self.regras("mikrotik_routeros", [("Configuração", "/export", (
            "/snmp community\nadd addresses=10.0.0.0/8 name=ro"))])
        self.assertIn("CFG-SNMPV1V2", v2)

    def test_junos_set_version_antigo_nao_e_consultado(self):
        texto = snapshot("juniper_junos", [
            ("Configuração", "show configuration | display set", "set version 21.4R3-S5.4"),
            ("Inventário", "show version", "Hostname: mx\nModel: mx204\nJunos: 23.4R2-S5.4"),
        ])
        vs = [v for v in n.extrair_versoes({"platform_key": "juniper_junos"}, texto)
              if v["rotulo"] == "Junos"]
        self.assertEqual([v["versao"] for v in vs], ["23.4R2-S5.4"])

    def test_junos_evolved(self):
        texto = snapshot("juniper_junos", [("Inventário", "show version",
                                            "Junos: 23.2R2-S1.3-EVO\nJunos OS Evolved")])
        v = next(v for v in n.extrair_versoes({"platform_key": "juniper_junos"}, texto)
                 if v["rotulo"] == "Junos")
        self.assertEqual((v["cpe_produto"], v["versao"]), ("junos_os_evolved", "23.2R2-S1.3"))

    def test_evo_solto_na_configuracao_nao_e_evolved(self):
        texto = snapshot("juniper_junos", [
            ("Inventário", "show version", "Model: mx204\nJunos: 23.4R2-S8.12"),
            ("Configuração", "show configuration | display set",
             "set interfaces xe-0/0/1 description TRANSIT-EVO\n"
             "set policy-options policy-statement IX-EVO term 1 then accept"),
        ])
        v = next(v for v in n.extrair_versoes({"platform_key": "juniper_junos"}, texto)
                 if v["rotulo"] == "Junos")
        self.assertEqual((v["cpe_produto"], v["versao"]), ("junos", "23.4R2-S8.12"))
        # Só a versão com sufixo -EVO, sem a linha "Junos OS Evolved".
        texto = snapshot("juniper_junos", [("Inventário", "show version",
                                            "Junos: 23.4R2-S8.11-EVO")])
        v = next(v for v in n.extrair_versoes({"platform_key": "juniper_junos"}, texto)
                 if v["rotulo"] == "Junos")
        self.assertEqual((v["cpe_produto"], v["versao"]), ("junos_os_evolved", "23.4R2-S8.11"))

    def test_evidencia_omitida_com_dados_sensiveis(self):
        snap = snapshot("mikrotik_routeros", [("Configuração", "/export", (
            "/snmp community\nadd addresses=10.0.0.0/8 name=S3cr3tC0mmunity"))])
        for meta in ({"platform_key": "mikrotik_routeros", "sensitive_data": "included"},
                     {"platform_key": "mikrotik_routeros"}):
            r = {a["id"]: a for a in n.avaliar_config(meta, snap)}
            self.assertIn("CFG-SNMPV1V2", r)
            self.assertNotIn("S3cr3t", r["CFG-SNMPV1V2"]["evidencia"])
            self.assertIn("omitido", r["CFG-SNMPV1V2"]["evidencia"])

    def test_cvss4_so_fica_na_tabela(self):
        r = n.resumir_vuln_osv({"id": "CVE-2026-1", "severity": [
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "affected": []}, "Ubuntu:24.04:LTS", "x")
        self.assertEqual(r["severidade"], "DESCONHECIDA")
        self.assertTrue(n._relevante_osv(r, {}, {}))


class TesteJunosFlowspec(unittest.TestCase):
    def avaliar(self, versao, config, evo=False):
        texto = snapshot("juniper_junos", [
            ("Configuração", "show configuration | display set", config),
            ("Inventário", "show version",
             f"Junos: {versao}" + ("\nJunos OS Evolved" if evo else "")),
        ])
        meta = {"platform_key": "juniper_junos"}
        versoes = n.extrair_versoes(meta, texto)
        return [a for a in n.avaliar_catalogo(meta, texto, versoes, None)
                if a["id"] == "JUNOS-FLOWSPEC-JSA112187"]

    FLOW = ("set protocols bgp group WANGUARD type internal\n"
            "set protocols bgp group WANGUARD family inet flow no-validate FS-IN\n"
            "set system processes routing bgp update-threading")

    def test_versao_junos(self):
        t = n._tupla_junos
        self.assertEqual(t("23.4R2-S8.13"), (23, 4, 2, 8, 13))
        self.assertEqual(t("21.2R3.4"), (21, 2, 3, 0, 4))
        self.assertIsNone(t("23.4X100-D20"))
        self.assertTrue(t("23.4R2-S8.5") < t("23.4R2-S8.13"))

    def test_vulneravel_com_flowspec(self):
        r = self.avaliar("23.4R2-S5.4", self.FLOW)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["situacao"], "vulneravel")
        self.assertEqual(len(r[0]["exposicao"]), 2)

    def test_sem_flowspec_nao_aponta(self):
        self.assertEqual(self.avaliar("23.4R2-S5.4", "set protocols bgp group T type external"), [])

    def test_corrigidas(self):
        for v in ("23.4R2-S8.13", "25.4R2", "26.4R1", "24.4R2-S5"):
            self.assertEqual(self.avaliar(v, self.FLOW), [], v)
        self.assertEqual(len(self.avaliar("26.2R1-S1", self.FLOW)), 1)
        self.assertEqual(len(self.avaliar("21.4R3-S5.4", self.FLOW)), 1)

    def test_evolved_com_build_proprio(self):
        self.assertEqual(self.avaliar("23.4R2-S8.11-EVO", self.FLOW, evo=True), [])
        self.assertEqual(len(self.avaliar("23.4R2-S8.11", self.FLOW)), 1)  # Junos OS: S8.13

    def test_so_update_threading_nao_aponta(self):
        self.assertEqual(self.avaliar("23.4R2-S5.4", (
            "set system processes routing bgp update-threading\n"
            "set protocols bgp group T family inet unicast")), [])

    def test_flowspec_herdado_de_grupo(self):
        grupo = "set groups FS protocols bgp group WG family inet flow no-validate X\n"
        self.assertEqual(len(self.avaliar("23.4R2-S5.4", grupo + "set apply-groups FS")), 1)
        # Grupo sem apply-groups não atua.
        self.assertEqual(self.avaliar("23.4R2-S5.4", grupo), [])

    def test_flowspec_desativado_nao_conta(self):
        flow = "set protocols bgp group WG family inet flow no-validate X\n"
        for desativa in ("deactivate protocols bgp group WG",
                         "deactivate protocols bgp",
                         "deactivate protocols bgp group WG family inet flow"):
            self.assertEqual(self.avaliar("23.4R2-S5.4", flow + desativa), [], desativa)
        # 'deactivate ... group WG' não alcança o grupo WG2.
        self.assertEqual(len(self.avaliar("23.4R2-S5.4", flow.replace("WG", "WG2")
                                          + "deactivate protocols bgp group WG")), 1)
        grupo = ("set groups FS protocols bgp group WG family inet flow\n"
                 "set apply-groups FS\ndeactivate protocols bgp group WG")
        self.assertEqual(self.avaliar("23.4R2-S5.4", grupo), [])

    def test_bmp_com_flowspec_vpn(self):
        r = self.avaliar("23.4R2-S5.4", (
            "set protocols bgp group V family inet-vpn flow\n"
            "set routing-options bmp station S1 station-address 192.0.2.9"))
        self.assertEqual(len(r[0]["exposicao"]), 2)
        self.assertIn("BMP", r[0]["exposicao"][1])

    def test_configuracao_grande_sem_flowspec_e_rapida(self):
        config = "\n".join(f"set interfaces ge-0/0/{i} unit 0 family inet address "
                           f"10.{i % 250}.{i % 200}.1/30 description LINK-{i}"
                           for i in range(25000))
        self.assertGreater(len(config), 2_000_000)
        inicio = time.time()
        self.assertEqual(self.avaliar("23.4R2-S5.4", config), [])
        self.assertLess(time.time() - inicio, 2)

    def test_trem_x_d_fica_para_conferir(self):
        r = self.avaliar("15.1X49-D200", self.FLOW)
        self.assertEqual(r[0]["situacao"], "conferir")
        self.assertIn("conferir manualmente", r[0]["base"])
        self.assertEqual(self.avaliar("15.1X49-D200", "set protocols bgp group T type external"), [])


class TesteSaidas(unittest.TestCase):
    def test_csv_sem_formula(self):
        h = {"host": "@r1", "ip": "192.0.2.1", "plataforma": "x", "config": [],
             "catalogo": [], "osv": None,
             "versoes": [{"rotulo": "X", "versao": "1", "cves": [
                 {"id": "CVE-2026-1", "severidade": "HIGH", "nota": 7.5,
                  "descricao": "=HYPERLINK(\"http://exemplo.invalid\",\"x\")"}]}]}
        with tempfile.TemporaryDirectory() as pasta:
            with open(n.gerar_csv([h], {}, pasta), encoding="utf-8-sig", newline="") as f:
                linha = list(csv.reader(f))[1]
        self.assertEqual(linha[0], "'@r1")
        self.assertTrue(linha[10].startswith("'=HYPERLINK("))
        self.assertEqual(linha[8], "7.5")

    def test_inseguro_nao_grava_cache(self):
        original_cache, original_tls = n.CACHE, n.VERIFICAR_TLS
        with tempfile.TemporaryDirectory() as pasta:
            n.CACHE = os.path.join(pasta, "cache.json")
            try:
                n.VERIFICAR_TLS = False
                n.salvar_cache({"cpe:x": []})
                self.assertFalse(os.path.exists(n.CACHE))
                n.VERIFICAR_TLS = True
                n.salvar_cache({"cpe:x": []})
                self.assertTrue(os.path.exists(n.CACHE))
            finally:
                n.CACHE, n.VERIFICAR_TLS = original_cache, original_tls

    def test_epss_ausente_nao_vai_para_o_cache(self):
        original = n.http_json
        n.http_json = lambda url, timeout=45: {"data": [{"cve": "CVE-2026-1", "epss": "0.5"}]}
        try:
            cache = {}
            r = n.consultar_epss(["CVE-2026-1", "CVE-2026-2"], cache)
        finally:
            n.http_json = original
        self.assertEqual(r, {"CVE-2026-1": 0.5, "CVE-2026-2": None})
        self.assertEqual(cache, {"epss:CVE-2026-1": 0.5})


class TesteKEVFabricante(unittest.TestCase):
    KEV = {
        "CVE-2018-14847": {"fabricante": "MikroTik", "produto": "RouterOS",
                           "incluido_em": "2021-12-01", "ransomware": "", "nome": "",
                           "descricao": ""},
        "CVE-2016-10033": {"fabricante": "PHP", "produto": "PHPMailer",
                           "incluido_em": "2025-07-07", "ransomware": "", "nome": "",
                           "descricao": ""},
        "CVE-2019-11043": {"fabricante": "PHP", "produto": "FastCGI Process Manager (FPM)",
                           "incluido_em": "2022-03-25", "ransomware": "Known",
                           "nome": "", "descricao": ""},
    }

    def test_por_plataforma(self):
        r = n.kev_do_fabricante("mikrotik_routeros", False, self.KEV, set())
        self.assertEqual([i["cve"] for i in r], ["CVE-2018-14847"])
        r = n.kev_do_fabricante("mikrotik_routeros", False, self.KEV, {"CVE-2018-14847"})
        self.assertEqual(r, [])

    def test_php_sem_phpmailer(self):
        r = n.kev_do_fabricante("linux", True, self.KEV, set())
        self.assertEqual([i["cve"] for i in r], ["CVE-2019-11043"])


@unittest.skipUnless(os.environ.get("NETCVE_TESTE_REDE") == "1", "sem rede")
class TesteOSVReal(unittest.TestCase):
    def test_php2shell_no_ubuntu(self):
        pacotes = [{"binario": "php8.3-fpm", "versao": "8.3.6-0ubuntu0.24.04.11",
                    "fonte": "php8.3", "versao_fonte": "8.3.6-0ubuntu0.24.04.11"}]
        r = n.consultar_osv("Ubuntu:24.04:LTS", pacotes, {})
        cves = {c for p in r for v in p["vulns"] for c in v["cves"]}
        self.assertIn("CVE-2026-109618", cves)


if __name__ == "__main__":
    unittest.main(verbosity=1)
