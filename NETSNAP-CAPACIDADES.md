# netsnap — referência de capacidades

Documento de contexto para projetos que vão consumir, integrar ou estender o netsnap. Descreve o que a ferramenta faz, o que entrega, em que formato e com quais limites. Versões cobertas: **netsnap 1.15.1**, netsnap_transporte 1.1.1, netdiag 1.1.1, netcve 0.3.1.

Autor: Victor Hugo R. Moura (VHRMO3) / Infinity Consulting — licença MIT.

---

## 1. O que é

O netsnap é um extrator **somente leitura** de configuração e estado de equipamentos de rede e servidores Linux, voltado a provedores de internet (ISP). Ele acessa cada host por SSH ou Telnet, identifica sozinho a plataforma, executa uma lista de comandos de leitura específica dela e grava **um arquivo Markdown por host**, estruturado para ser lido por pessoas e por sistemas de IA.

Usos típicos:

- backup de configuração em formato legível e versionável;
- retrato do parque para análise por IA (diagnóstico, auditoria, documentação, desenho de topologia);
- inventário de versões, licenças, módulos ópticos e vizinhança L2;
- insumo para triagem de vulnerabilidades (netcve) e, futuramente, para aplicar mudanças com confirmação humana (NETCONTROL) e para um agente de análise (NETANALYTIC).

### Garantias

- **Nenhum comando de escrita.** Os perfis contêm comandos de leitura (`show`, `display`, `print`, `/export`, leitura de arquivo e de estado de serviço — `systemctl`, `rndc`, `chronyc`, `unbound-control`, `certbot certificates`, `dig`, `curl` GET em `127.0.0.1` —, verificadores `install.sh --audit/--verify` do ISP-Stack), consultas SQL `SELECT`/`SHOW`/`DESCRIBE` e comandos de sessão (desligar paginação, `enable`/`config` onde a CLI exige, `quit`/`exit`). Cada snapshot declara `read_only: true` e `config_changes_made: 0`.
- Exceções de contexto, documentadas no próprio snapshot: a OLT FiberHome exige `enable` e `config` até para `show`; o SmartAX exige `enable` para ler a configuração. Esses comandos apenas mudam o modo da sessão; nada é gravado.
- Efeitos colaterais conhecidos em Linux, sem alteração de configuração: `certbot certificates` escreve no próprio log do certbot; `install.sh --audit/--verify` do ISP-Stack inicializa o log de instalação do stack.

---

## 2. Componentes

| Arquivo | Função | Dependências |
|---|---|---|
| `netsnap.py` | Coletor principal (menu interativo e modo lote) | Python 3.8+, Netmiko |
| `netsnap_transporte.py` | Camada de acesso SSH/Telnet só com a biblioteca padrão (SSH via cliente OpenSSH do sistema). **Ainda não integrada ao netsnap.py** | Python 3.8+, cliente OpenSSH para SSH |
| `netdiag.py` | Executa cada comando do perfil isoladamente e classifica o resultado, para depurar perfis | netsnap.py, Netmiko |
| `netcve.py` | Lê os snapshots e faz triagem de vulnerabilidades (NVD + CISA KEV) e de configuração insegura | só biblioteca padrão (certifi opcional) |
| `zabbix-para-netsnap.md` | Instruções para uma IA converter a lista de hosts do Zabbix em arquivo de alvos | — |
| `README.md`, `DEPENDENCIAS.md` | Documentação de uso e da estratégia de dependências | — |

---

## 3. Execução

```bash
python3 netsnap.py                 # interativo
python3 netsnap.py alvos.txt       # lote
python3 netsnap.py alvos.txt --debug
python3 netsnap.py --version
```

Perguntas feitas no início de cada sessão, nesta ordem:

1. tipo de extração (1–8, ver seção 6);
2. incluir dados sensíveis (padrão: não);
3. modo de depuração (pulado se `--debug` foi passado);
4. protocolo: SSH ou Telnet;
5. varredura: **FAST** (ping ICMP antes; quem não responde é descartado) ou **BUSCA PROFUNDA** (tenta todos);
6. instâncias simultâneas: 1–10, padrão 5;
7. usuário, senha (sem eco) e porta padrão (22 SSH, 23 Telnet).

Ao terminar a fila há um menu: nova coleta com outra configuração/credencial, mais alvos na mesma sessão, ou sair. Cada sessão tem resumo próprio, e há um resumo geral no fim.

Não há interface não interativa completa: credenciais e opções são sempre perguntadas no terminal. Integrações que precisem rodar sem operador devem chamar as funções do módulo (ver seção 12) ou aguardar a migração para o transporte nativo.

---

## 4. Alvos aceitos

Um por linha no arquivo, ou digitados um a um no modo interativo:

```
10.0.0.5                 IP
10.0.0.5:2222            IP com porta própria
olt-centro.isp.net       nome DNS (resolvido na conexão)
10.0.0.0/24              bloco (hosts utilizáveis)
10.0.0.0/24:2222         bloco com porta
100.64.0.0/31            /31 e /127: os dois endereços
10.0.0.1-10.0.0.100      intervalo
10.0.0.1-100             intervalo abreviado (último octeto)
2001:db8::1              IPv6
[2001:db8::1]:2222       IPv6 com porta (só entre colchetes)
# comentário             linha ignorada
10.0.0.5   # BRAS        comentário após a entrada
```

Duplicatas são removidas. Expansões acima de 256 alvos pedem confirmação; uma entrada com mais de 65.536 endereços é recusada antes de ser expandida. Portas fora de 1–65535 e entradas inválidas são ignoradas com aviso. Arquivo com BOM (Bloco de Notas) ou em UTF-16 (PowerShell 5) é aceito; arquivo inexistente encerra com erro.

---

## 5. Fluxo de uma coleta

1. **Varredura** (modo FAST): ping paralelo (64 simultâneos); no Windows só conta como vivo quem responde com TTL ou, em IPv6, com tempo de resposta; no macOS e no FreeBSD o tempo de espera é passado em milissegundos, como esses sistemas exigem.
2. **Identificação da plataforma**, por host, em paralelo:
   - **SSH:** lê o banner SSH sem autenticar (milissegundos). `JSSH` → Junos e `ROSSSH` → MikroTik, com confiança alta; `SSH-2.0--` (identificação vazia) → Huawei; OpenSSH com sufixo de distribuição → Linux; OpenSSH puro → Junos ou Linux. Candidatos de confiança média são confirmados com uma conexão e um comando (`show version`, `display version`, `uname -s`...). Sem candidato, recorre ao SSHDetect do Netmiko e, por fim, a uma sonda Linux. Credencial recusada em qualquer etapa encerra a identificação do host na hora, sem tentar o próximo candidato com a mesma senha.
   - **Huawei:** um `display version` decide entre VRP V5 (campus, inclusive a linha *CloudEngine S*), VRP V8 (CloudEngine/NE) e SmartAX (OLT), que usam perfis diferentes. A versão do VRP prevalece sobre o nome do modelo.
   - **Telnet:** lê o texto de login (respondendo à negociação de opções, que alguns equipamentos exigem antes de mostrar o pedido): `>>User name:` → SmartAX; `Username:` → VRP/Cisco; `Login:` → FiberHome/Linux; `nome-do-host login:` → Linux/NX-OS; modelo no banner (MA5xxx, AN5xxx). Sem pista, testa no máximo dois perfis, com intervalo e sem repetir um já tentado, para não disparar bloqueio por tentativas. A confirmação da FiberHome recusa saídas que identificam outro fabricante, para que um Cisco ou Linux nunca receba `enable`/`config`.
   - Host acessível e não reconhecido vai para uma **fila de pendentes**, perguntada ao operador depois da fase paralela (nenhuma thread fica parada esperando).
3. **Coleta:** abre a sessão, trata o aviso `--Press any key--`, extrai o hostname do prompt (recusando capturas inválidas), executa os comandos preparatórios do perfil, as seções escolhidas e, em Linux, os módulos de aplicação detectados.
4. **Queda de sessão:** se o transporte reportar sessão encerrada, a coleta daquele host para, e o snapshot registra `session_lost: true` com nota explicando que seções ausentes indicam interrupção, não recurso inexistente.
5. **Saída:** grava o snapshot, depois o índice da execução e o resumo no terminal.

---

## 6. Seções e modos de extração

| Seção | Conteúdo |
|---|---|
| `config` | Configuração completa na sintaxe nativa. Em Linux: identidade, endereçamento, rotas de todas as tabelas, regras de roteamento, firewall (nftables/iptables/ufw), serviços habilitados e em execução, timers, cron, fstab, repositórios, usuários, sshd_config, sudoers.d, sysctl |
| `logs` | Últimas entradas de log (Linux: `journalctl -n 300`, com deduplicação) |
| `basico` | CPU, memória, alarmes, ambiente/temperatura, sessões BGP/OSPF, resumo de assinantes em BNG, serviços de gerência |
| `optica` | Interfaces, descrições, DOM (Rx/Tx, temperatura, bias, limiares), modelo/PN do transceiver, velocidade, contadores de erro e tráfego |
| `vizinhanca` | LLDP (todas), CDP (Cisco), `/ip neighbor` (MikroTik), `lldpcli` (Linux) |
| `inventario` | Versão, hardware, firmware, patches, licenças, pacotes instalados, containers |

| Modo | Seções |
|---|---|
| 1–6 | uma seção cada |
| 7 — Mapa da rede | config + optica + vizinhanca + inventario (sem logs) |
| 8 — Extração total | todas |

---

## 7. Plataformas

| Chave (`platform_key`) | Plataforma | Acesso | Observações |
|---|---|---|---|
| `juniper_junos` | Juniper MX (Junos) | SSH, Telnet | `display set`; em BNG, contagem de sessões em vez de listar assinantes; `show interfaces extensive` retirado (52 s/host) |
| `huawei` | Huawei VRP V5 (S5700, S6720, S6730, S9700) | SSH, Telnet | |
| `huawei_ce` | Huawei VRP V8 (CE6800/CE6860/CE8800, NE) | SSH, Telnet | driver Netmiko `huawei_vrpv8` |
| `huawei_smartax` | Huawei SmartAX (OLT MA5600/MA5800) | SSH, Telnet | `enable` antes da leitura |
| `fiberhome` | FiberHome OLT (AN551x, AN6000) | SSH, Telnet | sem driver Netmiko nativo: leitura por temporização; `enable` + `config` exigidos pela CLI; lista ampla de comandos candidatos |
| `cisco_nxos` | Cisco Nexus (NX-OS) | SSH, Telnet | |
| `cisco_ios` | Cisco IOS/IOS-XE (ASR 1000) | SSH, Telnet | |
| `cisco_xr` | Cisco IOS-XR (ASR 9000) | SSH, Telnet | |
| `mikrotik_routeros` | MikroTik RouterOS v6/v7 | SSH, Telnet | `/export hide-sensitive` com recuo para `/export`; `/ip service print` para serviços de gerência |
| `linux` | Servidor Linux (Debian/Ubuntu/RHEL e derivados) | SSH, Telnet | usa `sudo -n` quando disponível, sem pedir senha |

### Módulos de aplicação em Linux

Detectados automaticamente após o login (cada detecção imprime `PRESENTE`). Cada módulo acrescenta blocos próprios às mesmas seções.

| Módulo | O que extrai |
|---|---|
| **WANGuard** (Andrisoft) | Arquivos de configuração e, no banco MySQL/MariaDB, a configuração operacional: componentes, zonas e prefixos (`ipaddr`), respostas/ações, roteadores BGP/blackhole/Flowspec, regras de mitigação ativas, fila de filtros, as 1000 anomalias mais recentes, distribuição de ataques por tipo (90 dias), logs de ataque, metadados de licença, retenção. Colunas de segredo são excluídas na origem; endereços binários convertidos com `INET6_NTOA`; datas Unix com `FROM_UNIXTIME`. Credenciais lidas de `dbhost.conf`/`dbpass.conf` em tempo de execução |
| **Zabbix** | Configuração de server/proxy/agent, frontend, scripts externos, serviços e portas; no banco: hosts, grupos, templates, problemas, ações, dashboards |
| **Grafana** | `grafana.ini`, provisioning, health da API; no banco (SQLite/MySQL/PostgreSQL): dashboards, datasources, regras de alerta, usuários |
| **BIRD** | `bird.conf` e `conf.d`, `show status`, `show protocols` e `show protocols all`, memória e contagem de rotas (BIRD 2 por `birdc`/`birdcl`; BIRD 1 também por `birdc6`, que atende o daemon IPv6), sessões TCP/179 |
| **SmokePing** | Configuração, quantidade de alvos, volume de RRDs |
| **BIND9** | Configuração efetiva (`named-checkconf -p`, compactada quando há dezenas de milhares de zonas), `rndc status`, portas; **bloqueio DNS**: identifica RPZ ou sinkhole por zona (AnaBlock), lista instalada, script e cron de atualização, e prova de efetividade por `dig` em domínios de teste, numa amostra da lista e num domínio de controle |
| **ISP-Stack** | `provider.conf`, Routinator, jumphost, módulos instalados, serviços do stack (Unbound, Prometheus, Grafana, Apache, fail2ban, certbot, GVM) e verificadores oficiais `install.sh --audit` e `--verify` (só executados se o script declarar essas opções) |

Acesso a banco: credenciais lidas do arquivo de configuração local da aplicação e passadas por variável de ambiente (`MYSQL_PWD`, `PGPASSWORD`), nunca na linha de comando.

---

## 8. Formato de saída

### Arquivo por host

Nome: `<hostname>_<ip>_<AAAAMMDD_HHMMSS>.md` (apenas `<ip>_...` quando o hostname não pôde ser obtido). Caracteres inválidos no Windows são substituídos; colisões no mesmo segundo recebem sufixo `_2`, `_3`.

Pasta: `snapshots/` ao lado do script ou, sem permissão de escrita, `~/netsnap_snapshots/`.

Estrutura:

````markdown
---
netsnap_version: "1.15.1"
host: "MX204-BORDA"
ip: "203.0.113.200"
platform_key: "juniper_junos"
platform_name: "Juniper Junos (MX)"
vendor: "Juniper"
collected_at: "2026-08-04T20:02:30"
extraction_mode: "Extração total"
sections: ["config", "logs", "basico", "optica", "vizinhanca", "inventario"]
applications: []
transport: "ssh"
session_lost: false
sensitive_data: "redacted"
read_only: true
config_changes_made: 0
---

# Snapshot — <host> (<ip>)
## Como interpretar este documento      (guia para IA: convenções, ópticas, topologia, notas de Telnet/contexto/queda)
## Índice
## Configuração
### `show configuration | display set`
```text
<saída bruta do comando>
```
## <Nome do módulo> — <Seção>            (módulos de aplicação em Linux)
````

Convenções:

- Cada valor do front-matter é JSON válido (listas e booleanos incluídos), portanto YAML válido.
- `##` = seção temática; `###` = comando **exatamente como executado**; bloco ```` ```text ```` = saída bruta. Quando a própria saída contém crases, a cerca do bloco fica uma crase mais longa que a maior sequência delas, para que o bloco não termine antes da hora.
- `***REMOVIDO***` = valor sensível suprimido; `***CERTIFICADO/CHAVE REMOVIDO***` = bloco PEM; `***CONTEÚDO DE ARQUIVO SENSÍVEL REMOVIDO***` = arquivo que é integralmente segredo.
- `_(sem saída útil — retorno: ...)_` = comando vazio ou não suportado por aquela plataforma/firmware. **Não** significa recurso desabilitado.

### Índice da execução

`_indice_<AAAAMMDD_HHMMSS>.md`, com front-matter `document_type: "run_index"`, `collection_seconds` (tempo de trabalho, sem a espera pelo operador), `generated_at`, `extraction_mode`, `hosts_collected`; tabela Host/IP/Arquivo e tabela de hosts não coletados com o motivo.

### Log de depuração (opcional)

`_debug_<AAAAMMDD_HHMMSS>.log`: por evento, hora, host, etapa e detalhe — banner, palpite, confirmação, comandos enviados, tempo, bytes, linhas e amostra de até 1200 caracteres do retorno. A amostra é **sempre sanitizada**, mesmo com dados sensíveis incluídos no snapshot.

---

## 9. Tratamento do conteúdo

- **Sanitização** (padrão ligado): senhas e hashes, inclusive com qualificador (`password irreversible-cipher $1c$...`, `enable secret 9 ...`, `key-string 7 ...`, `authentication-key 1 type md5 value "$9$..."`, `pre-shared-key ascii-text ...`); chaves BGP/OSPF/NTP/TACACS/RADIUS/MD5 do MikroTik; communities SNMP v1/v2c (Cisco, Huawei, Junos, MikroTik, snmpd.conf), inclusive em destinos de trap (`snmp-server host`, `snmp-agent target-host`, `trapsink`/`trap2sink`/`informsink`), e credenciais SNMPv3 (`auth`/`priv`, `createUser`); chaves RADIUS/TACACS+/IKE em texto claro, OSPF `message-digest-key`, Huawei `authentication-mode ... plain`, HSRP e `wpa-psk`; todas as cifras Huawei (`%^%#`, `%@%@`, `%$%$`, `%+%#`, `%#%#`); chaves WireGuard, `bindpw`, tokens e chaves de API, chaves de serviço do Alertmanager e webhooks; credenciais em URL (`esquema://usuario:senha@`) e em linha de comando (`mysql -p`, `sshpass -p`, `curl -u`); formatos `chave=valor`, `chave: valor`, JSON, PHP (`$DB['PASSWORD']`); blocos PEM, inclusive truncados; arquivos inteiramente secretos (`dbpass.conf`). Comunidades **BGP** são preservadas.
- **Limpeza:** códigos ANSI (inclusive cores 256 com `:`), bytes nulos.
- **Limites de tamanho:** 512 KB por comando; 8 MB para configuração; 512 KB para logs e inventário. O corte é sinalizado no texto.
- **Logs deduplicados:** linhas repetidas (mesma assinatura com dígitos normalizados) viram uma linha e `[+N linha(s) semelhante(s) omitida(s)]`.
- **Saídas grandes reduzidas na origem:** `dpkg-query` em vez de `dpkg -l`; contagem de subinterfaces `pp0`/`demux0` em BNG em vez de lista; tabelas WANGuard curadas em vez de despejar 2500 tabelas.

---

## 10. Telnet

- Escolhido no menu; porta padrão 23. Drivers Netmiko específicos para Junos, Huawei, SmartAX e Cisco. Para FiberHome, MikroTik e Linux o netsnap faz o login por conta própria, porque o `generic_telnet` do Netmiko não envia credenciais.
- Credenciais enviadas **uma única vez**: novo pedido de usuário ou senha é tratado como recusa, sem nova tentativa (OLT costuma bloquear a conta por tentativas).
- Snapshot marcado com `transport: "telnet"` e nota de que a sessão trafegou em texto claro.

---

## 11. Ferramentas complementares

### netdiag

```bash
python3 netdiag.py 10.0.0.1 [10.0.0.2 ...] [--porta 22] [--usuario U] [--secao optica]
                   [--plataforma fiberhome] [--timeout 120] [--anonimizar] [--sensivel]
```

Repete a detecção registrando cada etapa e o tempo, roda cada comando do perfil (e dos módulos Linux) isoladamente e classifica em `OK`, `VAZIO`, `NAO_SUPORTADO`, `ERRO` ou `PAGINACAO`, marcando os lentos (> 30 s). Gera `_diagnostico_<ts>.md` e `.json` com amostra dos comandos problemáticos, versão e linhas de licença encontradas. `--anonimizar` troca IPv4/IPv6, MACs (três formatos), hostnames (inclusive alvos informados por nome DNS) e números de série por substitutos consistentes, preservando máscaras e loopback. Os alvos seguem o formato do netsnap (IPv6, `[IPv6]:porta`, CIDR). Os comandos preparatórios não entram na cobertura. **Só SSH.**

### netcve

```bash
python3 netcve.py snapshots/ [--api-key K | NVD_API_KEY] [--sem-rede] [--csv] [--todos]
                             [--limite-cve 15] [--inseguro]
```

Não acessa equipamentos. Lê os snapshots (o mais recente por host, salvo `--todos`), extrai a versão a partir do Inventário (ignorando Vizinhança e Logs), aplica 9 heurísticas de configuração (Telnet ativo, SNMP padrão, SNMP v1/v2c, HTTP de gerência, serviços legados do RouterOS, `PermitRootLogin yes`, recursão DNS aberta, versão do BIND exposta, NTP sem autenticação), consulta a NVD 2.0 por CPE com paginação completa e cruza com o catálogo CISA KEV. Gera `_cve_triagem_<ts>.md` (e `.csv`). Cache de 7 dias em `~/.netcve_cache.json`. Huawei VRP, SmartAX MA5600 e FiberHome têm versão extraída mas não consultada (sem CPE genérico na NVD); o SmartAX MA5800 é consultado como `huawei:ma5800_firmware`. A versão é convertida para o formato CPE da NVD (Junos `21.4R3-S5.4` → `21.4:r3-s5`; IOS-XE `17.03.04a` → `17.3.4a`). Falha de TLS ou erro 4xx não é repetido; o cache é gravado a cada consulta. Resultado é triagem, não laudo.

### netsnap_transporte

Sessões SSH e Telnet sem pacotes externos: Telnet completo (RFC 854) sobre socket; SSH conduzindo o cliente OpenSSH do sistema por pseudoterminal (Unix) ou `SSH_ASKPASS` (Windows, OpenSSH 8.4+). Pede algoritmos legados (DH group1/14-sha1, ssh-rsa, CBC, hmac-sha1) apenas se o cliente local os conhecer (`ssh -Q`), o que evita a falha do OpenSSH 10. Interface única para os dois transportes e para o Netmiko opcional:

```python
import netsnap_transporte as tr
s = tr.conectar(ip, usuario, senha, 22, "ssh")      # "telnet" | transporte="nativo"/"netmiko"
s.descobrir_prompt()
saida = s.executar("show version")
s.fechar()
```

Exceções: `ErroAutenticacao`, `ErroConexao` (ambas subclasses de `ErroTransporte`). `python3 netsnap_transporte.py` imprime o diagnóstico da máquina.

---

## 12. Como integrar em outro projeto

**Consumindo os arquivos (recomendado):** o snapshot é o contrato. Para processar:

```python
import json, re

def ler_snapshot(caminho):
    """Devolve (metadados, [(seção, comando, saída ou None)])."""
    texto = open(caminho, encoding="utf-8").read()
    cab = re.match(r"^---\n(.*?)\n---\n", texto, re.S).group(1)
    meta = {k.strip(): json.loads(v) for k, _, v in
            (l.partition(":") for l in cab.splitlines() if ":" in l)}
    itens = []
    for bloco in re.split(r"(?m)^## ", texto)[1:]:
        secao = bloco.split("\n", 1)[0].strip()
        for m in re.finditer(r"^### `(.+?)`\n+(?:(`{3,})text\n(.*?)\n\2\n|_\(sem saída útil.*?\)_)",
                             bloco, re.S | re.M):
            itens.append((secao, m.group(1), m.group(3)))   # None = sem saída útil
    return meta, itens
```

O mesmo comando pode aparecer em mais de uma seção (por exemplo `show chassis hardware detail` em ópticas e em inventário), por isso a chave natural é o par seção + comando.

A saída dos comandos não é escapada; o que a protege é a cerca, sempre mais longa que qualquer sequência de crases da saída. Uma linha de saída que comece com `## ` ainda confundiria este parser simplificado; para uso em produção, percorra o arquivo linha a linha e ignore cabeçalhos enquanto estiver dentro de um bloco de código.

- Use `platform_key` para escolher o parser e `collected_at` para ordenar coletas.
- Confira `session_lost` antes de concluir que algo não existe.
- Confira `sensitive_data`: com `"redacted"`, valores de segredo não estão no arquivo.
- Arquivos que começam com `_` (índice, triagem, diagnóstico) não são snapshots de host.

**Chamando como biblioteca:** `netsnap.detectar(ip, usuario, senha, porta, protocolo)` devolve a `platform_key`; `netsnap.coletar(ip, porta, tipo, usuario, senha, secoes, nome_modo, incluir_sensivel, protocolo)` devolve `(arquivo, hostname)`. Defina `netsnap.PASTA_SAIDA` antes. Exceções de Netmiko (`NetmikoAuthenticationException`, `NetmikoTimeoutException`) e `netsnap.NaoIdentificado` sinalizam as falhas. Os perfis ficam em `netsnap.PERFIS` e `netsnap.APPS_LINUX`, e `netsnap.sanitizar(texto)` pode ser reutilizado.

**Para NETCONTROL / NETANALYTIC:**

- O snapshot mais recente informa plataforma, versão e configuração vigente antes de propor uma mudança; um novo snapshot depois dela serve de verificação.
- A detecção de plataforma e a camada de transporte podem ser reaproveitadas; a escrita, porém, deve ficar em ferramenta separada, preservando a garantia de somente leitura do netsnap.
- Diferença entre dois snapshots do mesmo host (mesmas seções) é a forma natural de detectar mudanças não planejadas.

---

## 13. Limites e estado de validação

| Item | Situação |
|---|---|
| Juniper MX (MX204, MX80), Linux, WANGuard, BIND9/AnaBlock | Validados com coletas reais |
| Huawei S6730 (V5) e CE6860 (V8) | Coletados em campo; os perfis separados V5/V8 foram derivados dessas coletas e ainda não rodaram em campo na forma atual |
| BIRD e SmokePing | Uma coleta real (um servidor) |
| Telnet em FiberHome AN551x e Huawei MA5800 | Login corrigido na 1.15.0 e testado contra servidor que reproduz o comportamento observado; **falta validação em equipamento real** |
| FiberHome (lista de comandos), Zabbix, Grafana, ISP-Stack | Escritos a partir de documentação e do código; sem coleta real recebida até aqui |
| Cisco NX-OS/IOS/XR, MikroTik | Perfis por documentação e sintaxe conhecida; validação de campo limitada |
| Transporte sem dependências | Validado isoladamente; não integrado ao netsnap.py |
| Execução não interativa (credenciais por argumento/variável) | Não existe |
| Taxa de erro de interface | Contadores são cumulativos; uma coleta não dá taxa — são necessárias duas |
| Alcance de transceiver | Inferido do PN em Juniper/Cisco; não é comprimento real de fibra |
| Rate-limit/anti-brute-force | Muitas instâncias simultâneas contra o mesmo segmento podem gerar falha de banner SSH; o netsnap detecta, aguarda e tenta uma vez |
