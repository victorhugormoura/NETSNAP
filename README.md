<<<<<<< HEAD
# NETSNAP
=======
# netsnap

Extrator de snapshot **multi-vendor** e **somente leitura** para equipamentos de rede e servidores em produção. Conecta via SSH, autodetecta a plataforma, coleta as informações escolhidas em paralelo e gera um arquivo **Markdown por host** — pronto para análise humana, ingestão em outra IA ou arquivamento.

> **Garantia de leitura:** o netsnap executa exclusivamente comandos `show` / `display` / `print` / `export` / leitura de sistema. Nunca entra em modo de configuração e nunca escreve nada no equipamento.

---

## Plataformas suportadas

| Plataforma | `device_type` | Exemplos |
|---|---|---|
| Juniper Junos | `juniper_junos` | MX80, MX104, MX204 |
| Huawei VRP | `huawei` | S6730, CE6730/CE6860, NE8000 |
| Huawei SmartAX | `huawei_smartax` | OLT MA5800 |
| FiberHome OLT | `fiberhome`* | AN5516, AN6000 |
| Cisco NX-OS | `cisco_nxos` | Nexus |
| Cisco IOS / IOS-XE | `cisco_ios` | ASR 1000 |
| Cisco IOS-XR | `cisco_xr` | ASR 9000 |
| MikroTik RouterOS | `mikrotik_routeros` | CCR, RB |
| Linux | `linux` | Debian, Ubuntu, RHEL e derivados |

### Módulos de aplicação (detectados automaticamente em hosts Linux)

| Módulo | O que extrai |
|---|---|
| **WANGuard** | Configuração (descoberta por glob — o nome do arquivo muda entre versões), unidades systemd e processos ativos, endereçamento, mitigação em uso (`iptables`, `nftables`, `ipset`), sessões BGP de blackhole/flowspec (BIRD, FRR, ExaBGP), log de anomalias e ataques, binários e licença |
| **Zabbix** | `zabbix_server.conf` / `zabbix_proxy.conf` / agente **sem linhas comentadas**, includes, frontend e vhost, scripts externos e de alerta, estado dos serviços e portas, versões e pacotes |
| **Zabbix — inventário monitorado** | Consulta ao banco (somente `SELECT`): contagem de hosts/itens/triggers, **lista de hosts com IP e estado**, grupos, templates, **problemas ativos com severidade**, ações, tipos de mídia, dashboards e proxies |
| **Grafana** | `grafana.ini` sem comentários, provisionamento declarativo (`provisioning/datasources`, `dashboards`, `alerting`), plugins, `/api/health`, versões e pacotes |
| **Grafana — conteúdo** | Consulta ao banco (somente `SELECT`, SQLite/MySQL/PostgreSQL): **dashboards e pastas** com uid e versão, **datasources** com tipo e URL, **regras de alerta** e estado, dashboards provisionados e usuários |
| **BIND9** | Configuração efetiva (`named-checkconf -p`), `named.conf` e includes, lista e contagem de zonas, `rndc status`, versão e pacotes, logs do serviço |
| **BIND9 — RPZ / AnaBlock** | Seção dedicada: bloco `response-policy` em uso, zonas RPZ/AnaBlock declaradas, `rndc zonestatus` de cada uma (serial carregado = prova de que está *atuando*), arquivos de zona com contagem de entradas, serviços e cronjobs de atualização |

\* O Netmiko não possui driver nativo para FiberHome; o netsnap usa o driver `generic` com leitura por temporização. Como a CLI FiberHome exige contexto privilegiado (`enable`, e em várias famílias também `config`) **mesmo para comandos `show`**, o perfil acessa esse contexto — executando exclusivamente comandos de leitura e saindo ao final. Isso está registrado no cabeçalho de cada relatório FiberHome. Por variar bastante entre famílias e firmwares, o perfil executa um conjunto amplo de comandos candidatos; os não suportados são marcados e não poluem a saída. Ajuste a lista em `PERFIS` conforme o seu parque.

---

## Funcionalidades

- **Zero preparação**: cria a pasta de saída na primeira execução sem exigir privilégios de administrador (se não houver permissão na pasta do script, usa `~/netsnap_snapshots` automaticamente)
- **Coleta paralela**: de 1 a 10 instâncias simultâneas (padrão 5), acelerando a varredura de ranges e blocos
- **Dois modos de varredura**:
  - **FAST** — ping ICMP em todos os alvos antes de qualquer SSH; IPs sem resposta são descartados de imediato. Ideal para ranges/CIDR com buracos. Equipamentos que bloqueiam ICMP serão pulados
  - **BUSCA PROFUNDA** — tenta conexão em todos os IPs, sem filtro prévio
- **Autodetecção individual por host** — identificou, segue direto com a extração; host acessível mas não reconhecido entra numa **fila de pendentes** consultada ao final da fase paralela (nenhuma instância fica parada aguardando o operador). A lista pode misturar fabricantes livremente. Servidores Linux são reconhecidos por sonda própria (`uname`); OLTs SmartAX são distinguidas de switches VRP automaticamente
- **Aceita CIDR e ranges**: `10.0.0.0/24`, `10.0.0.1-10.0.0.100` ou `10.0.0.1-100` — além do ICMP do modo FAST, cada alvo passa por teste TCP rápido (3 s) antes do SSH
- **Menu de extração** com seis seções independentes e dois modos combinados:
  1. **Configuração completa** — em Linux, inclui serviços (`systemctl`), portas em escuta (`ss -tulpn`), endereçamento e rotas
  2. **Logs**
  3. **Estado do equipamento** — CPU, memória, alarmes, ambiente/temperatura, adjacências de roteamento; em Linux: recursos, discos, processos
  4. **Interfaces e ópticas** — status e descrição das portas, tipo de módulo (SFP/SFP+/XFP/QSFP), vendor e PN, wavelength, alcance suportado, potência Rx/Tx com limiares de alarme, velocidade negociada, estatística de tráfego e contadores de erro
  5. **Vizinhança L2** — LLDP em todas as plataformas, CDP nas Cisco, `/ip neighbor` (MNDP/CDP/LLDP) no MikroTik, `lldpcli` no Linux
  6. **Inventário** — versão de sistema, firmware, módulos/placas, pacotes e software instalado, patches e **licenças** (`show system license`, `display license`, `/system license print`, `show license usage`, licenças de aplicação no Linux)
  7. **Mapa da rede** — configuração + ópticas + vizinhança + inventário, **sem logs**: o retrato da topologia e da camada física, pensado para análise e desenho de mapa por IA
  8. **Extração total**
- **Saída preparada para análise por IA**: cada arquivo abre com front-matter YAML (host, IP, plataforma, fabricante, data, seções, aplicações, flag de sanitização), seguido de um guia de interpretação do documento, índice de seções e os comandos com saída bruta. Ao final da execução é gerado um `_indice_*.md` consolidando toda a coleta — útil para ingerir um site inteiro de uma vez
- **Comandos sem suporte são marcados, não poluem**: retorno vazio ou erro de sintaxe vira `_(sem saída útil — retorno: ...)_` em vez de despejar a mensagem de erro no relatório
- **Porta SSH configurável** — padrão perguntado na inicialização; porta individual por entrada: `IP:porta`, `10.0.0.0/24:2222`
- **Filtro de dados sensíveis (opcional)** — remove senhas, ciphers, communities SNMP, chaves SSH e blocos de certificado. No MikroTik usa o mecanismo nativo (`/export hide-sensitive`)
- **Modo interativo** ou **modo lote** (arquivo de entradas)
- **Resumo final** com sucessos, pulados, falhas (com motivo) e tempo total

---

## Requisitos

- Python 3.8+
- [Netmiko](https://github.com/ktbyers/netmiko)
- Acesso SSH (leitura) aos hosts

```bash
pip install netmiko
```

---

## Uso

### Modo interativo

```bash
python3 netsnap.py
```

Fluxo:

```
1. Tipo de extração [1-8]
2. Incluir dados sensíveis? [s/N]
3. Modo de varredura: FAST (ICMP prévio) ou BUSCA PROFUNDA [1-2]
4. Instâncias simultâneas [1-10, padrão 5]
5. Usuário SSH
6. Senha SSH
7. Porta SSH [22]
8. Alvos (IP, IP:porta, CIDR ou range) — ENTER vazio encerra
```

Ao final da fase paralela, hosts acessíveis que não foram identificados são apresentados um a um para escolha manual do tipo (com opção de pular).

### Modo lote

Crie um arquivo `ips.txt` com uma entrada por linha — formatos e fabricantes podem ser misturados:

```
# Borda (Juniper)
172.16.0.1
172.16.0.2:2222

# Anel de switches (range)
10.200.0.1-10.200.0.14
10.200.0.20-30

# CGNAT (bloco inteiro)
10.250.0.0/28
10.251.0.0/28:2200

# OLTs e servidores
10.200.1.1
10.10.0.5
```

Execute:

```bash
python3 netsnap.py ips.txt
```

Expansões acima de 256 alvos pedem confirmação antes de iniciar.

### Saída

Um arquivo por host em `snapshots/` (ao lado do script) ou `~/netsnap_snapshots`:

```
snapshots/
├── BRAS-TUPA_172.16.0.1_20260722_141002.md
├── SW-CENTRO_10.200.0.10_20260722_141130.md
└── srv-zabbix_10.10.0.5_20260722_141355.md
```

Cada arquivo contém cabeçalho de metadados (data, plataforma, modo de extração, tratamento de sensíveis) e a saída de cada comando em bloco de código.

---

## Interfaces e ópticas — o que é coletado por plataforma

| Plataforma | Módulo / DOM | Alcance no EEPROM | Erros e tráfego |
|---|---|---|---|
| Juniper Junos | `show interfaces diagnostics optics` (Rx/Tx, temperatura, bias, limiares) + PN via `show chassis hardware detail` | não exibido — inferir pelo PN | `show interfaces media` e `extensive` filtrado |
| Huawei VRP | `display transceiver verbose` (vendor, PN, wavelength, Rx/Tx) | **sim** — campo `Transfer Distance` | `display interface brief` traz InUti/OutUti e erros |
| Huawei SmartAX | ópticas dos uplinks; sintaxe varia por placa de controle | parcial | `display port state all`, estatísticas por porta |
| FiberHome | vários comandos candidatos (a nomenclatura varia entre AN55xx e AN6000) | parcial | `show port statistics` |
| Cisco NX-OS | `show interface transceiver details` (DOM com limiares) | não exibido — inferir pelo PN | `show interface counters errors` e `detailed` |
| Cisco IOS/IOS-XE | `show interfaces transceiver detail` | não exibido — inferir pelo PN | `show interfaces counters errors` |
| Cisco IOS-XR | `show controllers optics` (disponibilidade varia por release) | não exibido — inferir pelo PN | `show interfaces`, accounting |
| MikroTik | `/interface ethernet monitor [find] once` (vendor, PN, wavelength, Rx/Tx) | **sim** — `sfp-link-length-*` | `/interface ethernet print stats` |
| Linux | `ethtool -m` por interface (SFF-8472) | **sim** — campos `Length` | `ip -s -s link` e `ethtool -S` filtrado por erro |

Pontos que valem entender antes de interpretar o resultado (o relatório também os explica, para o consumidor automatizado):

- **Alcance não é distância do enlace.** Onde o EEPROM informa alcance, ele indica o que o módulo *suporta*, não o comprimento real da fibra instalada. Nas plataformas que não expõem o campo, o alcance só pode ser inferido do modelo (SR ≈ 300 m, LR ≈ 10 km, ER ≈ 40 km, ZR ≈ 80 km).
- **Taxa de erro exige duas coletas.** Um snapshot traz contadores cumulativos desde o último boot ou limpeza. Para taxa real, compare dois snapshots do mesmo host em instantes diferentes — o `netsnap` foi feito para isso, já que cada arquivo carrega data no nome e nos metadados.
- **Ausência de vizinho LLDP não significa ausência de enlace.** Interface ativa sem vizinho declarado normalmente é vizinho sem LLDP habilitado, não porta livre.

---

## Personalizando os comandos

Todos os comandos ficam no dicionário `PERFIS` no topo do `netsnap.py`, organizados por plataforma e seção (`config`, `logs`, `basico`). Campos opcionais por perfil:

| Campo | Função |
|---|---|
| `driver` | `device_type` do Netmiko quando diferente da chave (ex.: FiberHome usa `generic`) |
| `prep` | comandos preparatórios executados após o login (ex.: desligar paginação); erros são ignorados |
| `timing` | usa leitura por temporização para CLIs com prompt fora do padrão |
| `contexto` | marca plataformas que exigem contexto privilegiado para comandos show (registrado no relatório) |
| `sair` | comandos de saída de contexto executados ao final da coleta |

Módulos de aplicação Linux ficam em `APPS_LINUX`, com um comando `deteccao` (que deve imprimir `PRESENTE`), as mesmas seções dos perfis e uma seção `extra` opcional para verificações específicas. O marcador `{S}` é substituído por `sudo -n ` quando disponível.

**Regra do projeto:** apenas comandos de leitura. Contribuições que adicionem comandos de escrita ou modo de configuração não serão aceitas.

---

### Acesso ao banco de dados do Zabbix e do Grafana

Hosts, alertas e dashboards não vivem em arquivo de configuração — vivem no banco. Para extraí-los, os módulos leem as credenciais do próprio arquivo de configuração local (`zabbix_server.conf`, `grafana.ini`) e executam **exclusivamente comandos `SELECT`**. Três garantias de projeto:

- Nenhuma query contém `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `TRUNCATE` ou `GRANT`; no SQLite o acesso usa `-readonly`.
- A senha é lida em tempo de execução para uma variável de ambiente do processo cliente (`MYSQL_PWD`/`PGPASSWORD`), portanto **não aparece na linha de comando** (`ps`) nem no relatório — o comando registrado mostra apenas `$DBP`/`$GW`.
- Nenhuma query seleciona colunas de segredo (senhas de datasource, tokens, `secure_json_data`).

Requisitos: `sudo` para ler os arquivos de configuração, e o cliente correspondente instalado no servidor (`mysql`, `psql` ou `sqlite3`). Faltando qualquer um, a seção informa o motivo em vez de aparecer vazia.

---

## Avisos importantes

- **O filtro de sensíveis é melhor esforço.** A remoção por regex cobre os padrões mais comuns (Junos `encrypted-password`, Huawei `irreversible-cipher`, communities SNMP, chaves e certificados), mas **revise o arquivo antes de compartilhar com terceiros ou enviar para serviços externos de IA**.
- Em roteadores com muitas subinterfaces (ex.: BNG com PPPoE), comandos de interface completos podem gerar arquivos grandes e demorar alguns minutos.
- Na OLT MA5800 a coleta básica fica no nível de placa/CPU/alarmes; sinal óptico por PON exige modo de configuração, o que viola a regra de somente leitura.
- Em servidores Linux, o netsnap testa `sudo -n` (não interativo) e o utiliza apenas nos comandos de leitura dos módulos de aplicação. Sem sudo, arquivos como `wanguard.conf` e `named.conf` podem retornar permissão negada; `journalctl` completo exige o grupo `systemd-journal` ou root.
- **Licenças aparecem em texto no relatório** quando encontradas — é o comportamento pretendido da seção *Inventário*, mas considere-as informação sensível ao compartilhar o arquivo.
- A verificação de RPZ/AnaBlock identifica zonas pelo padrão de nome (`rpz`, `block`, `anablock`) e pelo bloco `response-policy`. Se a sua nomenclatura for diferente, ajuste os filtros em `APPS_LINUX["bind9"]`. Um `rndc zonestatus` com serial carregado é a evidência de que a zona está ativa e sendo aplicada.
- Instâncias paralelas compartilham o mesmo usuário SSH: em equipamentos com limite baixo de sessões VTY simultâneas, reduza o número de instâncias.
- O arquivo `ips.txt` e a pasta `snapshots/` contêm informação de infraestrutura: **nunca devem ser versionados** (já constam no `.gitignore`).

---

## netdiag — diagnóstico da extração (ferramenta complementar)

O `netdiag.py` executa, um a um, **todos os comandos que o netsnap usaria** em um equipamento e mede cada resultado. Serve para descobrir onde a extração falha num firmware específico e para gerar um relatório enviável a quem mantém os perfis.

Importa os perfis diretamente do `netsnap.py` — não duplica nenhuma lista de comandos.

```bash
python3 netdiag.py 10.0.0.1                      # diagnóstico completo
python3 netdiag.py 10.0.0.1 10.0.0.2 --porta 2222
python3 netdiag.py 10.0.0.1 --secao optica       # apenas uma seção
python3 netdiag.py 10.0.0.1 --plataforma fiberhome   # força o perfil
python3 netdiag.py 10.0.0.1 --anonimizar         # seguro para compartilhar
```

**O que o relatório traz:**

- **Ambiente de execução** — versões de netdiag, netsnap, Netmiko, Python e sistema de origem
- **Detecção passo a passo** — teste TCP, o que o `SSHDetect` retornou de fato (antes do mapeamento de alias), sondas SmartAX e Linux, cada uma cronometrada
- **Versão e licença** identificadas; quando não há padrão conhecido para a plataforma, o relatório mostra as linhas que mencionam versão/firmware — que são exatamente o insumo para criar o padrão
- **Resultado de cada comando** com status, tempo e número de linhas:

| Status | Significado |
|---|---|
| `OK` | retornou conteúdo utilizável |
| `NAO_SUPORTADO` | comando recusado pelo firmware |
| `VAZIO` | executou sem erro, mas sem retorno |
| `ERRO` | exceção (timeout, sessão perdida) |
| `PAGINACAO` | retorno preso em `--More--`; corrigir o `prep` do perfil |

- **Amostras apenas dos comandos com problema** — o retorno bruto truncado, que mostra a sintaxe que o equipamento realmente espera
- **Comandos lentos** (acima de 30 s), candidatos a filtragem em equipamentos com muitas interfaces
- **Cobertura** por host: quantos dos comandos do perfil funcionaram
- Em Linux: se há `sudo` não interativo e quais aplicações foram detectadas — a causa mais comum de seções vazias

Saídas: um `.md` legível e um `.json` estruturado, ambos em `diagnosticos/`.

### Compartilhando o diagnóstico

Valores sensíveis são mascarados por padrão. Com `--anonimizar`, IPs, MACs e hostnames são substituídos por valores fictícios **consistentes** (o mesmo IP recebe sempre o mesmo substituto), preservando a estrutura para análise sem expor a rede real. Endereços de loopback e broadcast são mantidos por serem irrelevantes para identificação.

O parâmetro `--sensivel` desativa o mascaramento; use apenas em diagnóstico local, nunca em arquivo compartilhado.

---

## netcve — triagem de vulnerabilidades (ferramenta complementar)

O `netcve.py` lê os snapshots gerados pelo netsnap, extrai versões de software e indicadores de configuração insegura, consulta a base **NVD (NIST)** e o catálogo **CISA KEV**, e produz um relatório consolidado de exposição.

Não acessa equipamentos e não usa credenciais: opera apenas sobre os arquivos já coletados. Isso permite rodar a coleta numa rede isolada e a análise em outra máquina, com internet.

```bash
python3 netcve.py snapshots/                    # analisa a pasta de snapshots
python3 netcve.py snapshots/ --api-key SUA_CHAVE
python3 netcve.py snapshots/ --sem-rede         # só heurísticas locais
python3 netcve.py snapshots/ --csv              # gera CSV além do Markdown
```

**Chave da API NVD:** opcional e gratuita (<https://nvd.nist.gov/developers/request-an-api-key>). Sem chave o limite é de 5 requisições a cada 30 segundos (~6,5 s por consulta); com chave, 50 a cada 30 segundos. Pode ser passada em `--api-key` ou na variável de ambiente `NVD_API_KEY`. Versões repetidas no parque são consultadas uma única vez e o resultado fica em cache local por 7 dias.

**O que é analisado:**

| Fonte | Cobertura |
|---|---|
| Versões de sistema | Junos, Huawei VRP, Cisco IOS/IOS-XE/NX-OS/IOS-XR, RouterOS, kernel Linux |
| Versões de aplicação | BIND, OpenSSH, nginx, Apache |
| Configuração (heurísticas locais) | Telnet ativo, community SNMP padrão, SNMP v1/v2c, HTTP de gerência, serviços legados do RouterOS, `PermitRootLogin yes`, recursão DNS aberta, versão do BIND exposta, NTP sem autenticação |

### Limitações — leia antes de usar o resultado

A correspondência é feita **pela versão declarada**, não por verificação ativa. Consequências:

- **Falsos positivos são esperados.** Fabricantes retroportam correções mantendo o mesmo número de versão; o recurso vulnerável pode não estar habilitado; pode haver mitigação externa (ACL, firewall de borda).
- **Falsos negativos são esperados.** A cobertura de CPE na NVD é incompleta para equipamentos de rede — OLTs FiberHome e Huawei SmartAX, por exemplo, praticamente não têm CPE publicado. O netcve extrai a versão mas marca explicitamente *"Sem mapeamento CPE conhecido"* em vez de reportar "nenhuma vulnerabilidade".
- A fonte autoritativa é sempre o boletim do fabricante (Juniper SIRT, Cisco PSIRT, Huawei PSIRT, MikroTik).

Trate o relatório como **triagem para priorizar investigação**, não como laudo de vulnerabilidade. Os itens marcados **KEV** (catálogo CISA de exploração confirmada) são a prioridade real e merecem verificação imediata.

---

## Licença

Distribuído sob a licença [MIT](LICENSE).

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
>>>>>>> a11c8a2 (Initial Commit)
