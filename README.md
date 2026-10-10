# netsnap

Extrator de snapshot **multi-vendor** e **somente leitura** para equipamentos de rede e servidores em produção. Conecta via SSH, autodetecta a plataforma, coleta as informações escolhidas em paralelo e gera um arquivo **Markdown por host** — pronto para análise humana, ingestão em outra IA ou arquivamento.

> **Garantia de leitura:** o netsnap executa exclusivamente comandos `show` / `display` / `print` / `export` / leitura de sistema. Nunca entra em modo de configuração e nunca escreve nada no equipamento.

---

## Plataformas suportadas

| Plataforma | `device_type` | Exemplos |
|---|---|---|
| Juniper Junos | `juniper_junos` | MX80, MX104, MX204 |
| Huawei VRP V5 | `huawei` | S5700, S6720, S6730, S9700 (linha campus) |
| Huawei VRP V8 | `huawei_ce` | CE6800, CE6860, CE8800, NE8000 (CloudEngine/NE) |
| Huawei SmartAX | `huawei_smartax` | OLT MA5600/MA5800 (SSH ou Telnet) |
| FiberHome OLT | `fiberhome`* | AN551x, AN6000 (SSH ou Telnet) |
| Cisco NX-OS | `cisco_nxos` | Nexus |
| Cisco IOS / IOS-XE | `cisco_ios` | ASR 1000 |
| Cisco IOS-XR | `cisco_xr` | ASR 9000 |
| MikroTik RouterOS | `mikrotik_routeros` | CCR, RB |
| Linux | `linux` | Debian, Ubuntu, RHEL e derivados |

### Módulos de aplicação (detectados automaticamente em hosts Linux)

| Módulo | O que extrai |
|---|---|
| **BIRD** | Configuração completa (`bird.conf` e `conf.d/`), estado de todas as sessões com `show protocols all` — vizinho, tempo de sessão, rotas importadas e exportadas, motivo da última queda —, contagem de rotas, memória, símbolos e sockets na porta 179. Cobre BIRD 1 (`birdc`/`birdc6`) e BIRD 2 (`birdc`/`birdcl`) |
| **SmokePing** | `config` e `config.d/` sem comentários, com destaque para `Targets` (a topologia medida), contagem de alvos, estado do serviço e volume da base RRD |
| **ISP-Stack** | Identidade do provedor (`provider.conf`) e módulos efetivamente instalados (`/etc/isp-stack/state/`); configuração de Unbound com adblock, Chrony, SNMP, Prometheus com alvos e regras, Alertmanager, Blackbox, Routinator, Apache com os vhosts do stack, jump host, unidades `isp-*` e endurecimento (fail2ban, unattended-upgrades, auditd) |
| **ISP-Stack — estado operacional** | Serviços e timers ativos, portas do stack em escuta, `unbound-control status` e estatísticas, `chronyc tracking/sources`, status e métricas do Routinator (sem disparar validação), alvos e alertas do Prometheus, estado do Alertmanager, última execução do backup e certificados do certbot |
| **ISP-Stack — conformidade** | Executa `install.sh --audit` e `--verify`, que são as entradas **não interativas** do próprio stack, para obter o diagnóstico oficial da instalação |
| **WANGuard** | Configuração (descoberta por glob — o nome do arquivo muda entre versões; arquivos de credencial são pulados), unidades systemd e processos ativos, endereçamento, mitigação em uso (`iptables`, `nftables`, `ipset`), sessões BGP de blackhole/flowspec (BIRD, FRR, ExaBGP), log de anomalias, binários e versão |
| **WANGuard — configuração operacional** | Toda a configuração do Wanguard 9 vive no MariaDB. Consulta somente leitura a: componentes (server, sensor, flow, sniff, snmp, filter, console, BGP), interfaces monitoradas com tipo de enlace e velocidade, zonas de IP e prefixos, perfis de detecção e limiares, respostas automáticas, roteadores com blackhole e **Flowspec**, listas brancas e exceções, mitigação ativa no instante, **as 1.000 anomalias mais recentes** com distribuição por tipo e por dia, e descoberta automática de tabelas não previstas |
| **Zabbix** | `zabbix_server.conf` / `zabbix_proxy.conf` / agente **sem linhas comentadas**, includes, frontend e vhost, scripts externos e de alerta, estado dos serviços e portas, versões e pacotes |
| **Zabbix — inventário monitorado** | Consulta ao banco (somente `SELECT`): contagem de hosts/itens/triggers, **lista de hosts com IP e estado**, grupos, templates, **problemas ativos com severidade**, ações, tipos de mídia, dashboards e proxies |
| **Grafana** | `grafana.ini` sem comentários, provisionamento declarativo (`provisioning/datasources`, `dashboards`, `alerting`), plugins, `/api/health`, versões e pacotes |
| **Grafana — conteúdo** | Consulta ao banco (somente `SELECT`, SQLite/MySQL/PostgreSQL): **dashboards e pastas** com uid e versão, **datasources** com tipo e URL, **regras de alerta** e estado, dashboards provisionados e usuários |
| **BIND9** | Configuração efetiva (`named-checkconf -p`), `named.conf` e includes, lista e contagem de zonas, `rndc status`, versão e pacotes, logs do serviço |
| **BIND9 — bloqueio DNS (RPZ / AnaBlock)** | Identifica **qual mecanismo está em uso** — RPZ (bloco `response-policy`) ou sinkhole por zona, técnica do AnaBlock, que declara cada domínio bloqueado como zona master apontando para um arquivo único. Traz o alvo do sinkhole, a lista instalada com contagem de zonas, o script e o cron de atualização, e a **prova de efetividade por consulta real**: `dig` nos domínios de teste do próprio AnaBlock, numa amostra da lista instalada e num domínio de controle fora dela |

\* O Netmiko não possui driver nativo para FiberHome; o netsnap usa o driver `generic` com leitura por temporização. Como a CLI FiberHome exige contexto privilegiado (`enable`, e em várias famílias também `config`) **mesmo para comandos `show`**, o perfil acessa esse contexto — executando exclusivamente comandos de leitura e saindo ao final. Isso está registrado no cabeçalho de cada relatório FiberHome. Por variar bastante entre famílias e firmwares, o perfil executa um conjunto amplo de comandos candidatos; os não suportados são marcados e não poluem a saída. Ajuste a lista em `PERFIS` conforme o seu parque.

---

## Funcionalidades

- **Zero preparação**: cria a pasta de saída na primeira execução sem exigir privilégios de administrador (se não houver permissão na pasta do script, usa `~/netsnap_snapshots` automaticamente)
- **Coleta paralela**: de 1 a 10 instâncias simultâneas (padrão 5), acelerando a varredura de ranges e blocos
- **Dois modos de varredura**:
  - **FAST** — ping ICMP em todos os alvos antes de qualquer SSH; IPs sem resposta são descartados de imediato. Ideal para ranges/CIDR com buracos. Equipamentos que bloqueiam ICMP serão pulados
  - **BUSCA PROFUNDA** — tenta conexão em todos os IPs, sem filtro prévio
- **Autodetecção individual por host** — identificou, segue direto com a extração; host acessível mas não reconhecido entra numa **fila de pendentes** consultada ao final da fase paralela (nenhuma instância fica parada aguardando o operador). A lista pode misturar fabricantes livremente. Servidores Linux são reconhecidos por sonda própria (`uname`); OLTs SmartAX são distinguidas de switches VRP automaticamente
- **Aceita IP, nome DNS, CIDR e ranges**: `10.0.0.5`, `olt-centro.isp.net`, `10.0.0.0/24`, `10.0.0.1-10.0.0.100`, `10.0.0.1-100`, IPv6 (`2001:db8::1`, `[2001:db8::1]:2222`). Em `/31` e `/127` os dois endereços entram (enlace ponto a ponto). Além do ICMP do modo FAST, cada alvo passa por teste TCP rápido (3 s) antes do SSH
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
- **Filtro de dados sensíveis (opcional)** — remove senhas e hashes (inclusive com qualificador: `password irreversible-cipher $1c$...`, `enable secret 9 ...`, `authentication-key 1 type md5 value "$9$..."`), chaves de BGP/OSPF/NTP/TACACS/RADIUS, communities SNMP (v1/v2c e credenciais v3), chaves WireGuard, chaves SSH e blocos de certificado. Comunidades **BGP** (`policy-options community X members ...`) são preservadas, por não serem segredo e serem necessárias para ler as políticas. No MikroTik usa também o mecanismo nativo (`/export hide-sensitive`, com recuo para `/export` no RouterOS v7, que já oculta por padrão). O log de depuração é sempre sanitizado, independentemente da opção
- **Modo interativo** ou **modo lote** (arquivo de entradas)
- **Resumo final** com sucessos, pulados, falhas (com motivo) e tempo total

---

## Telnet

Boa parte do parque de OLTs não oferece SSH — MA5800 e AN551x costumam sair de fábrica apenas com Telnet, e em muitos provedores continuam assim. O protocolo é escolhido no menu inicial, com porta padrão 23.

Como não há banner de protocolo para ler, a identificação usa o **texto de login** que o equipamento apresenta antes da autenticação: o SmartAX pede `>>User name:`, o VRP de switch pede `Username:`, as OLTs FiberHome apresentam `Login:`, e muitas trazem o modelo no banner. A negociação de opções do Telnet (bytes IAC, RFC 854) é descartada antes da análise. Sem pista no prompt, os perfis mais prováveis nesse protocolo são testados em ordem — o Netmiko não autodetecta por Telnet.

| Plataforma | driver SSH | driver Telnet |
|---|---|---|
| Huawei SmartAX (MA5800) | `huawei_smartax` | `huawei_olt_telnet` |
| FiberHome (AN551x) | `generic` | `generic_telnet` + login próprio |
| MikroTik / Linux | nativos | `generic_telnet` + login próprio |
| Huawei VRP V5 / V8 | `huawei` / `huawei_vrpv8` | `huawei_telnet` |
| Cisco IOS / NX-OS / XR | nativos | `cisco_*_telnet` |
| Juniper Junos | `juniper_junos` | `juniper_junos_telnet` |

O driver `generic_telnet` do Netmiko é o de servidor de terminal e, por projeto, **não envia usuário nem senha**. Era essa a causa da falha observada na OLT FiberHome: o pedido de `Login:` ficava sem resposta, os comandos preparatórios eram digitados no campo de usuário e o equipamento encerrava a sessão. O netsnap faz esse login por conta própria, com duas proteções contra bloqueio de conta: as credenciais são enviadas **uma única vez** (um novo pedido de usuário ou senha é tratado como recusa, sem nova tentativa) e a negociação de opções é respondida antes da leitura do banner, porque vários equipamentos só exibem o pedido de login depois disso.

Alguns equipamentos exigem uma tecla depois da autenticação — a OLT FiberHome apresenta `--Press any key to continue Ctrl+c to stop--` antes de liberar a CLI. Sem enviar essa tecla, esse aviso é capturado como se fosse o prompt e o primeiro comando derruba a sessão. A coleta reconhece o pedido, envia um retorno e relê o prompt.

Como cada tentativa de identificação por Telnet é um login completo, e OLT costuma ter limite baixo de sessões simultâneas e bloqueio por tentativas, o número de perfis testados às cegas é reduzido a dois, com intervalo entre eles. Não identificando, o equipamento entra na fila de escolha manual em vez de acumular tentativas.

Se o equipamento encerrar a sessão no meio da coleta, os comandos restantes não são enviados: o snapshot registra `session_lost: true` e traz uma nota informando que as seções ausentes indicam interrupção, não recurso inexistente.

**O Telnet transmite usuário, senha e toda a sessão em texto claro.** O menu avisa na seleção, o snapshot registra `transport: telnet` nos metadados, e o documento traz uma nota informando que a sessão que o originou era legível por qualquer sistema no caminho de rede. Use apenas em rede de gerência confiável e prefira SSH onde a plataforma suportar.

---

## Requisitos

- Python 3.8+
- [Netmiko](https://github.com/ktbyers/netmiko)
- Acesso SSH ou Telnet (leitura) aos hosts

```bash
pip install netmiko
```

O `netsnap_transporte.py` implementa SSH e Telnet sem dependências externas (ver `DEPENDENCIAS.md`), mas **ainda não está integrado ao `netsnap.py`**, que continua usando o Netmiko.

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
3. Modo de depuração? [s/N]   (omitido quando executado com --debug)
4. Protocolo: SSH ou Telnet
5. Modo de varredura: FAST (ICMP prévio) ou BUSCA PROFUNDA [1-2]
6. Instâncias simultâneas [1-10, padrão 5]
7. Usuário
8. Senha
9. Porta [22 para SSH, 23 para Telnet]
10. Alvos (IP, nome, IP:porta, CIDR ou range) — ENTER abre o menu de sessão
```

Ao pressionar ENTER sem informar alvo, aparece o menu:

```
  1) Nova coleta — reconfigurar tudo (inclusive usuário e senha)
  2) Continuar nesta sessão — informar mais alvos
  3) Sair
```

A opção 1 volta à tela de configuração sem encerrar o programa, útil quando o próximo grupo de equipamentos usa credenciais diferentes. Cada sessão gera seu próprio resumo e, ao sair, é impresso um resumo geral com todas elas.

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
10.200.1.1            # OLT Centro
olt-norte.isp.net
10.10.0.5

# Enlace ponto a ponto e IPv6
100.64.0.0/31
[2001:db8::10]:2222
```

Comentários podem ocupar a linha inteira ou vir depois da entrada. Arquivos salvos com BOM (Bloco de Notas do Windows) são aceitos. Em IPv6 a porta só é reconhecida entre colchetes: `2001:db8::1:22` é um endereço válido, e separar o `:22` apontaria para outro host.

Execute:

```bash
python3 netsnap.py ips.txt
```

Expansões acima de 256 alvos pedem confirmação antes de iniciar.

### Saída

Um arquivo por host em `snapshots/` (ao lado do script) ou `~/netsnap_snapshots`:

```
snapshots/
├── BRAS-NORTE_172.16.0.1_20260722_141002.md
├── SW-CENTRO_10.200.0.10_20260722_141130.md
└── srv-zabbix_10.10.0.5_20260722_141355.md
```

Cada arquivo contém cabeçalho de metadados (data, plataforma, modo de extração, tratamento de sensíveis) e a saída de cada comando em bloco de código.

---

## Volume e legibilidade da saída

Toda saída passa por normalização antes de ir para o snapshot, porque o destino é leitura por pessoas e por modelos de linguagem:

- **Códigos ANSI são removidos.** O `journald` colore a saída, e as sequências de escape aparecem no meio do texto sem acrescentar informação — atrapalham tanto a leitura quanto a tokenização.
- **Saídas excessivas são truncadas com aviso explícito.** O teto padrão é 512 KB por comando, mas a seção *Configuração* tem 8 MB (`LIMITE_POR_SECAO`): truncar a configuração inutilizaria o snapshot para reconstruir ou auditar o equipamento, e um roteador de borda com políticas de BGP passa de 400 KB. O corte aparece no documento como `[SAÍDA TRUNCADA PELO netsnap — N bytes no total, M linha(s) omitida(s)]`, nunca de forma silenciosa.
- **Comandos que explodem em escala têm tratamento próprio.** Em servidor de bloqueio DNS, `named-checkconf -p` pode devolver centenas de milhares de linhas (84 mil zonas observadas em produção, 8 MB). A coleta separa a configuração global — `options`, `acl`, `logging`, `response-policy` com as zonas RPZ — das declarações de zona em massa, que viram contagem e amostra.

---

## Modo de depuração

Ligado pelo menu (`Gerar log de depuração da coleta?`) ou por `python3 netsnap.py --debug`, gera um `_debug_*.log` **separado do snapshot**, com uma linha por evento:

```
19:28:53.864 | 203.0.113.99      | banner                 | 'SSH-2.0-OpenSSH_8.9p1 Ubuntu' em 0.09s
19:28:53.958 | 203.0.113.99      | banner->palpite        | linux (confianca media)
19:28:54.612 | 203.0.113.99      | identificado           | linux em 0.75s (via banner)
19:28:55.104 | 203.0.113.99      | sudo                   | disponivel
19:28:55.221 | 203.0.113.99      | envia comando          | ip route show table all
19:28:55.398 | 203.0.113.99      | retorno                | 0.18s | 412 bytes | 9 linhas | default via ...
```

Registra a identificação passo a passo (banner recebido, palpite, confirmação, SSHDetect, alias, sondas), **cada comando enviado ao equipamento** com tempo, bytes, linhas e uma amostra do retorno, além de detecção de sudo e de aplicações. Erros aparecem como `ERRO no comando` com o tipo da exceção. É o arquivo a anexar quando algo não funcionar.

---

## Equipamentos com muitas subinterfaces (BNG/BRAS)

Num BRAS com PPPoE, as sessões de assinante dominam a saída: um MX80 em produção apresentou 1.321 interfaces `pp0.N` e 54 `demux0.N` num total de 3.993 linhas de `show interfaces terse` — 282 KB de conteúdo efêmero, que muda a cada minuto e não descreve a topologia.

O perfil Junos usa **filtro positivo** pelas interfaces de infraestrutura (`ge-`, `xe-`, `et-`, `ae`, `irb`, `lo0`, `si-`, `demux0`, `lc-`, `pfe`, `pfh`), reduzindo a saída em 98% sem perder nenhuma interface física. Um filtro negativo não serviria: o `terse` usa linhas de continuação para famílias adicionais (inet6), e remover só a linha do nome deixaria milhares de linhas órfãs. As sessões entram como **contagem** em comando separado, e `show subscribers summary` e `show pppoe statistics` trazem o quadro agregado.

---

## Famílias Huawei

As três linhas Huawei compartilham o driver `huawei` do Netmiko, mas a sintaxe diverge o bastante para exigir perfis separados. O netsnap decide por `display version`, numa única conexão:

| Família | Critério | Diferenças observadas em campo |
|---|---|---|
| `huawei` (VRP V5) | `Version 5.x` | aceita `display cpu-usage` e `display memory-usage`; recusa `display interface counters errors` com *"Wrong parameter"* |
| `huawei_ce` (VRP V8) | `Version 8.x`, ou modelo `CE####`/`NE####` | recusa `cpu-usage`, `memory-usage` e `transceiver verbose` com *"Unrecognized command"*; o estado de hardware vem de `display health` |
| `huawei_smartax` | modelo `MA5###` ou `SmartAX` | OLT, comandos de placa e PON |

Um CE6860 e um S6730 no mesmo anel, com o mesmo perfil, produziam 7 e 5 comandos recusados respectivamente. Com perfis próprios, cada um recebe a sintaxe que entende.

---

## Velocidade da identificação

A identificação passou a usar três níveis, do mais barato ao mais caro:

1. **Banner SSH** — o servidor anuncia sua identificação antes de qualquer autenticação (RFC 4253). Ler essa linha custa uma conexão TCP de milissegundos. `SSH-2.0-ROSSSH` é MikroTik com certeza; `OpenSSH_8.9p1 Ubuntu` indica Linux; `Cisco-1.25` indica IOS.
2. **Confirmação** — um comando em uma conexão, quando o banner sugere mas não prova.
3. **SSHDetect do Netmiko** — só quando os dois anteriores não resolvem.

O ganho é maior justamente onde era pior: um servidor Linux antes passava pelo SSHDetect (que autentica e testa comandos de vários fabricantes, todos falhando), depois por uma sonda `uname` em conexão separada, e só então pela conexão de coleta — três conexões e dezenas de segundos. Agora resolve com a leitura do banner e uma confirmação.

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

### ISP-Stack

O [ISP-Stack](https://github.com/victorhugormoura/ISP-Stack) instala os módulos de forma seletiva, e o netsnap reflete isso: a detecção usa `/etc/isp-stack`, e o inventário lista `state/`, onde o instalador registra um arquivo por módulo instalado. Assim o relatório distingue **módulo ausente** de **módulo com falha** — sem essa lista, as duas situações produziriam a mesma saída vazia.

Os verificadores do próprio stack são chamados apenas por `install.sh --audit` e `install.sh --verify`. Executar `audit.sh` diretamente abriria o menu interativo e chegaria a perguntar se deve gravar o relatório em `/var/log/isp-stack` — escrita no servidor, o que o netsnap não faz. Pelas flags, o `install.sh` invoca `audit_executar_sem_perguntar` e `verify_executar`, que apenas leem e imprimem; o stdin é fechado (`</dev/null`) e há timeout para o caso de alguma versão futura voltar a perguntar algo.

As consultas HTTP são todas a `127.0.0.1` e apenas de leitura: `GET` em `/status` e `/metrics` do Routinator, `/api/v1/targets` e `/api/v1/alerts` do Prometheus, `/api/v2/status` do Alertmanager.

---

### Tempo reportado

O índice e o resumo informam o **tempo de coleta**: varredura, detecção e execução dos comandos. O tempo em que o programa fica parado esperando o operador digitar um alvo ou escolher no menu não entra na conta.

A diferença não é pequena. Numa execução medida, o relógio de parede marcou 1007 s e a coleta efetiva foram 25 s — os outros 982 s foram o prompt aguardando resposta. Reportar o relógio de parede tornaria impossível comparar duas coletas ou identificar um comando lento.

Quando a diferença passa de cinco segundos, o resumo mostra as duas medidas: `Coleta: 25s | Sessão: 1007s`.

---

### Logs com repetição

Serviço em falha repete a mesma mensagem centenas de vezes. Num servidor WANGuard real, 285 das 300 linhas coletadas eram o mesmo erro de conexão com o ClickHouse, cada uma arrastando o comando SQL inteiro: 97 KB para dizer uma coisa só.

As seções de log em hosts Linux passam por um filtro que trunca linhas muito longas, agrupa as que têm a mesma assinatura (dígitos normalizados) e informa quantas foram omitidas — `[+35 linha(s) semelhante(s) omitida(s)]`. No caso acima a saída caiu 89% e a repetição ficou **mais** visível, não menos.

---

### WANGuard: leitura do banco

O Wanguard grava endereços IP como `VARBINARY`. Um despejo direto produz bytes nulos ilegíveis em vez do endereço — a zona de IP inteira sai como lixo. O netsnap monta o `SELECT` a partir do `DESCRIBE` e aplica três transformações na origem:

- colunas binárias recebem `INET6_NTOA`, devolvendo o IP legível;
- marcas de tempo Unix recebem `FROM_UNIXTIME`;
- colunas cujo nome indique segredo são excluídas antes da consulta, porque a saída do mysql é tabular e um valor sob a coluna `password` não seria detectado pelo sanitizador, que procura par chave=valor.

O que fica de fora, por decisão: séries temporais e dados de fluxo (`top_bin_*`, `top_live_*`, `sensorstats`, `events`, `as_numbers`, `ipacct*`), que somam dezenas de gigabytes e alimentam gráficos; as 2.424 tabelas de accounting diário, que entram apenas como contagem; e as tabelas de autenticação de operador (`company_staff`, `httpauth`, `ldapauth`, `radiusauth`, `samlauth`).

A configuração de **Flowspec** não tem tabela própria: vive nas colunas `exa_flowspec`, `max_flowspec`, `flowspec_counters`, `exa_nexthop`, `exa_localpref`, `exa_rd`, `exa_direction` e `srtbh` da tabela `router`, junto do blackhole.

---

### Acesso ao banco de dados do Zabbix e do Grafana

Hosts, alertas e dashboards não vivem em arquivo de configuração — vivem no banco. Para extraí-los, os módulos leem as credenciais do próprio arquivo de configuração local (`zabbix_server.conf`, `grafana.ini`) e executam **exclusivamente comandos `SELECT`**. Três garantias de projeto:

- Nenhuma query contém `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `TRUNCATE` ou `GRANT`; no SQLite o acesso usa `-readonly`.
- A senha é lida em tempo de execução para uma variável de ambiente do processo cliente (`MYSQL_PWD`/`PGPASSWORD`), portanto **não aparece na linha de comando** (`ps`) nem no relatório — o comando registrado mostra apenas `$DBP`/`$GW`.
- Nenhuma query seleciona colunas de segredo (senhas de datasource, tokens, `secure_json_data`).

Requisitos: `sudo` para ler os arquivos de configuração, e o cliente correspondente instalado no servidor (`mysql`, `psql` ou `sqlite3`). Faltando qualquer um, a seção informa o motivo em vez de aparecer vazia.

---

## Avisos importantes

- **Chave SSH dos equipamentos.** No primeiro acesso a chave do servidor SSH fica registrada em `~/.netsnap_known_hosts` (no Windows, `%USERPROFILE%\.netsnap_known_hosts`). Se ela mudar, a coleta daquele equipamento é recusada antes de enviar a senha — pode ser interceptação. Se o equipamento foi trocado ou teve a chave refeita, apague a linha dele nesse arquivo.
- **O filtro de sensíveis é melhor esforço.** A remoção por regex cobre os padrões mais comuns (Junos `encrypted-password`, Huawei `irreversible-cipher`, communities SNMP, chaves e certificados), mas **revise o arquivo antes de compartilhar com terceiros ou enviar para serviços externos de IA**.
- Em roteadores com muitas subinterfaces (ex.: BNG com PPPoE), comandos de interface completos podem gerar arquivos grandes e demorar alguns minutos.
- Na OLT MA5800 a coleta básica fica no nível de placa/CPU/alarmes; sinal óptico por PON exige modo de configuração, o que viola a regra de somente leitura.
- Em servidores Linux, o netsnap testa `sudo -n` (não interativo) e o utiliza apenas nos comandos de leitura dos módulos de aplicação. Sem sudo, arquivos como `wanguard.conf` e `named.conf` podem retornar permissão negada; `journalctl` completo exige o grupo `systemd-journal` ou root.
- **Licenças aparecem em texto no relatório** quando encontradas — é o comportamento pretendido da seção *Inventário*, mas considere-as informação sensível ao compartilhar o arquivo.
- A verificação de RPZ/AnaBlock identifica zonas pelo padrão de nome (`rpz`, `block`, `anablock`) e pelo bloco `response-policy`. Se a sua nomenclatura for diferente, ajuste os filtros em `APPS_LINUX["bind9"]`. Um `rndc zonestatus` com serial carregado é a evidência de que a zona está ativa e sendo aplicada.
- Instâncias paralelas compartilham o mesmo usuário SSH: em equipamentos com limite baixo de sessões VTY simultâneas, reduza o número de instâncias.
- O arquivo `ips.txt` e a pasta `snapshots/` contêm informação de infraestrutura: **nunca devem ser versionados** (já constam no `.gitignore`).

---

## Painel web local (netsnap_web)

Interface no navegador para tudo o que as ferramentas fazem pela linha de comando. Roda no próprio PC e só aceita conexões dele mesmo.

```bash
python3 netsnap_web.py                 # abre o navegador
python3 netsnap_web.py --porta 9000    # outra porta (padrão 8765; se ocupada, tenta as seguintes)
python3 netsnap_web.py --sem-navegador # só mostra o endereço
```

O terminal mostra o endereço com o token desta execução (`http://127.0.0.1:8765/#t=...`). Sem o token o painel não responde; ele muda a cada vez que o painel inicia. Ctrl+C encerra o painel e interrompe as coletas em andamento.

| Tela | O que faz |
|---|---|
| Visão geral | Execuções da sessão, últimas coletas, agendamentos e falhas recentes |
| Nova coleta | Mesmas opções do modo interativo; acompanha cada equipamento ao vivo |
| Execuções | Estado por equipamento, saída completa e índice da coleta; equipamentos não identificados são resolvidos ali, escolhendo a plataforma |
| Snapshots | Leitura por seção e comando, com busca nas saídas e download do `.md` |
| Inventário | Snapshot mais recente de cada equipamento: plataforma, modelo, versões, CVEs da última triagem, quantidade de coletas; exporta CSV |
| Comparar coletas | Diferença comando a comando entre duas coletas do mesmo equipamento (por padrão, só configuração e inventário) |
| Topologia | Desenho da rede confirmada (baixa em PNG e PDF), equipamentos sem vizinhança com o comando para ativar o LLDP na plataforma, enlaces LLDP/CDP e L3, vizinhos ainda não coletados (os que anunciam endereço de gerência podem ser coletados direto dali) e o JSON da topologia |
| Vulnerabilidades | Roda o netcve sobre a pasta de snapshots e mostra o relatório |
| Diagnóstico | Roda o netdiag e mostra o relatório |
| Agendamentos | Coletas recorrentes (diárias num horário ou a cada N horas) enquanto o painel estiver aberto |

**Segurança**

- Escuta só em `127.0.0.1`. Toda chamada exige o token, o que impede que outra página aberta no mesmo navegador dispare coletas; o cabeçalho `Host` é conferido contra DNS rebinding.
- A senha dos equipamentos vai do navegador para o processo de coleta pela entrada padrão. Não é gravada em disco, não aparece na linha de comando nem no log.
- Agendamentos são salvos em `snapshots/_agendamentos.json` **sem a senha**. Ela fica só na memória: depois de reiniciar o painel, cada agendamento aparece como "aguardando senha" até ser informada de novo.
- Em Linux e macOS, arquivos criados pelo painel e pelas coletas ficam legíveis só pelo dono.

**Dependências:** o painel usa apenas a biblioteca padrão e não carrega nada da internet (funciona em rede de gerência isolada). Coleta e diagnóstico continuam exigindo o Netmiko; sem ele o painel abre em modo consulta, com snapshots, inventário, comparação, topologia e vulnerabilidades.

**Execução:** cada coleta, diagnóstico ou triagem roda num processo separado. As execuções ficam na memória do painel e somem ao reiniciá-lo; os arquivos gerados permanecem na pasta.

## Topologia (netsnap_topologia e netsnap_desenho)

Monta o grafo da rede a partir do snapshot mais recente de cada equipamento, com duas fontes:

- **LLDP/CDP** (seção *Vizinhança L2*): quem cada equipamento vê em cada porta.
- **L3** (seção *Configuração*): dois equipamentos coletados com endereço na mesma sub-rede ponto a ponto (/29 a /31 em IPv4, /112 a /127 em IPv6) estão ligados naquela interface. Cobre roteadores sem LLDP — caso comum em bordas Juniper. Endereços lidos da configuração Junos, Huawei VRP, Cisco e MikroTik.

```bash
python3 netsnap_topologia.py snapshots/                       # grava snapshots/_topologia_<data>.json
python3 netsnap_topologia.py snapshots/ --saida rede.json
python3 netsnap_topologia.py snapshots/ --desenho rede.pdf    # desenho dos enlaces confirmados (ou .svg)
python3 netsnap_topologia.py snapshots/ --desenho rede.pdf --todos   # inclui os vistos por um lado só
```

**Confirmação.** Um enlace LLDP/CDP é confirmado quando os dois lados foram coletados e se veem. A porta anunciada pelo vizinho é comparada já normalizada (`XGE0/0/3` = `XGigabitEthernet0/0/3`, `Gi0/1` = `GigabitEthernet0/1`, `xe-0/0/0.0` = `xe-0/0/0`); quando o vizinho Junos anuncia o índice SNMP em vez do nome, vale a descrição da porta, resolvida pelo `show interfaces descriptions` do próprio vizinho. Enlace L3 é sempre confirmado: vem das duas configurações.

**Mesmo equipamento, vários endereços.** Um roteador coletado pelo IP de cada interface vira um nó só (mesmo hostname e plataforma), com os endereços listados. Nomes de fábrica (`MikroTik`, `HUAWEI`) continuam separados por endereço.

**Sem vizinhança.** Equipamento sem nenhum vizinho LLDP/CDP aparece com o motivo provável (LLDP desligado, sem vizinhos, seção não coletada) e o comando para ativar o protocolo na plataforma. O mesmo aviso sai no log da coleta e no cabeçalho do snapshot.

**Desenho.** O painel mostra o desenho dos enlaces confirmados e baixa em PNG e PDF; a opção *Incluir enlaces vistos por um lado só* acrescenta, em pontilhado, os demais. O PDF é vetorial e gerado sem dependências; o PNG sai do mesmo desenho, convertido no navegador. Linha cheia: LLDP/CDP; tracejada: L3 ponto a ponto. Vários enlaces entre o mesmo par (membros de LAG) viram uma linha, com as portas nas pontas. A mesma rede gera sempre o mesmo desenho.

**Uma rede por pasta.** A topologia junta todos os snapshots da pasta. Snapshots de clientes diferentes na mesma pasta misturam endereços privados repetidos (uma /30 em 10.x nos dois clientes vira enlace) e hostnames iguais (dois `BRAS` viram um nó). Para várias redes, use uma cópia do netsnap para cada uma, ou passe ao `netsnap_topologia.py` a pasta de cada cliente.

Limites: enlace sem LLDP/CDP e sem endereçamento ponto a ponto entre equipamentos coletados não aparece — ausência no desenho não significa ausência de cabo. Formatos validados com saída real: Huawei VRP (LLDP) e configuração Junos (L3). LLDP de Junos, Cisco (IOS, NX-OS, XR, CDP), MikroTik e lldpd seguem a sintaxe documentada e foram testados com exemplos.

## netdiag — diagnóstico da extração (ferramenta complementar)

> As três ferramentas evoluem juntas: o `netdiag` importa os perfis do `netsnap`, e o `netcve` depende do formato de saída dele. Mantenha as três na mesma versão do repositório.


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

Um caso real ilustra por que a verificação por consulta importa: em dois recursivos do mesmo provedor, o primeiro tinha 86.955 zonas carregadas e respondia `127.0.0.1` ao domínio de teste; o segundo tinha o mesmo `anablock.conf` no disco, com 48.895 zonas, atualizado diariamente pelo mesmo cron — mas apenas 128 zonas carregadas e o domínio de teste resolvendo para o IP real. O arquivo existia e crescia; faltava o `include` em `named.conf`. Nenhuma inspeção de configuração isolada acusaria isso, e por isso a coleta também compara zonas carregadas com zonas em arquivo e confere o `include`.

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
python3 netcve.py snapshots/ --todos            # inclui coletas antigas do mesmo host
python3 netcve.py snapshots/ --inseguro         # ignora validação TLS (ver abaixo)
```

**Coletas repetidas:** por padrão, quando a pasta tem vários snapshots do mesmo host, apenas o mais recente é analisado — evita linhas duplicadas no relatório e consultas desnecessárias à NVD. Use `--todos` para incluir o histórico.

**Sem a seção Inventário:** um snapshot coletado apenas no modo *Configuração* raramente declara a versão do sistema. O netcve avisa quais hosts estão nessa condição e ainda tenta deduzir a versão da própria configuração — em Junos, por exemplo, o `display set` traz `set version`. Para triagem completa, colete com *Inventário* ou *Extração total*.

**Falha de certificado TLS:** se as consultas falharem com `CERTIFICATE_VERIFY_FAILED ... certificate has expired`, o problema costuma estar no repositório de autoridades da estação, não no servidor. O netcve usa o pacote `certifi` automaticamente quando instalado (`pip install --upgrade certifi`) e, ao detectar essa falha, interrompe as consultas e explica as opções em vez de repetir o erro para cada versão.

**Chave da API NVD:** opcional e gratuita (<https://nvd.nist.gov/developers/request-an-api-key>). Sem chave o limite é de 5 requisições a cada 30 segundos (~6,5 s por consulta); com chave, 50 a cada 30 segundos. Pode ser passada em `--api-key` ou na variável de ambiente `NVD_API_KEY`. Versões repetidas no parque são consultadas uma única vez e o resultado fica em cache local por 7 dias.

**O que é analisado:**

| Fonte | Cobertura |
|---|---|
| Versões de sistema | Junos, Cisco IOS/IOS-XE/NX-OS/IOS-XR, RouterOS, kernel Linux (consultados na NVD); Huawei VRP e OLTs (extraídos e listados, sem consulta — ver limitações) |
| Versões de aplicação | BIND, OpenSSH, nginx, Apache |
| Configuração (heurísticas locais) | Telnet ativo, community SNMP padrão, SNMP v1/v2c, HTTP de gerência, serviços legados do RouterOS, `PermitRootLogin yes`, recursão DNS aberta, versão do BIND exposta, NTP sem autenticação |

### Limitações — leia antes de usar o resultado

A correspondência é feita **pela versão declarada**, não por verificação ativa. Consequências:

- **Falsos positivos são esperados.** Fabricantes retroportam correções mantendo o mesmo número de versão; o recurso vulnerável pode não estar habilitado; pode haver mitigação externa (ACL, firewall de borda).
- **Falsos negativos são esperados.** A cobertura de CPE na NVD é incompleta para equipamentos de rede — OLTs FiberHome e Huawei SmartAX, por exemplo, praticamente não têm CPE publicado. O Huawei VRP não existe na NVD como produto único: os CPEs são por modelo (`s6730-h_firmware`, por exemplo), e a consulta genérica não retornava nada. Nesses casos o netcve extrai a versão mas marca explicitamente *"Sem mapeamento CPE conhecido"* em vez de reportar "nenhuma vulnerabilidade".
- **"Não consultado" não é "zero".** No modo `--sem-rede`, ou quando a consulta falha, a coluna de CVEs mostra *não consultado*.
- **Kernel de distribuição.** A versão do kernel é consultada pela numeração upstream (`5.4.0`); distribuições como Ubuntu e RHEL retroportam correções, então a lista tende a superestimar a exposição. Confira no boletim de segurança da distribuição.
- **A versão é lida do próprio equipamento.** A busca começa pela seção *Inventário* e ignora *Vizinhança* e *Logs*, que descrevem outros equipamentos — em versões anteriores, a versão de um vizinho LLDP podia ser atribuída ao host.
- **Community SNMP padrão** só é detectável em snapshots coletados com dados sensíveis incluídos; com a sanitização ativa, o valor chega mascarado.
- A fonte autoritativa é sempre o boletim do fabricante (Juniper SIRT, Cisco PSIRT, Huawei PSIRT, MikroTik).

Trate o relatório como **triagem para priorizar investigação**, não como laudo de vulnerabilidade. Os itens marcados **KEV** (catálogo CISA de exploração confirmada) são a prioridade real e merecem verificação imediata.

---

## Licença

Distribuído sob a licença [MIT](LICENSE).

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
