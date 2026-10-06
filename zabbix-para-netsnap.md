# Converter lista de hosts do Zabbix em arquivo de alvos do netsnap

Instruções para transformar qualquer exportação de hosts do Zabbix em um único arquivo `.txt` que o netsnap consegue ler.

**Entrega esperada:** um arquivo de texto puro, um alvo por linha, sem cabeçalho, sem aspas, sem vírgulas, sem numeração.

---

## Formato aceito pelo netsnap

Cada linha é um destes formatos:

```
10.0.0.5              IP simples (usa a porta SSH padrão informada na execução)
10.0.0.5:2222         IP com porta SSH específica
10.0.0.0/24           bloco CIDR (expande para todos os hosts)
10.0.0.0/24:2222      bloco com porta SSH específica
10.0.0.1-10.0.0.100   intervalo completo
10.0.0.1-100          intervalo abreviado (só o último octeto)
olt-centro.isp.net    nome DNS (resolvido na conexão)
2001:db8::1           IPv6 (porta só entre colchetes: [2001:db8::1]:2222)
# texto                comentário — a linha é ignorada
10.0.0.5  # texto      comentário após a entrada também é aceito
```

Linhas em branco são ignoradas. Ordem não importa.

---

## A armadilha principal: porta

**A porta no arquivo do netsnap é a porta SSH. A porta do Zabbix não é.**

O Zabbix registra `10050` (agente), `161` (SNMP), `10051` (proxy), `623` (IPMI) ou `12345` (JMX). Nenhuma dessas serve — o netsnap conecta por SSH.

- Se todos os equipamentos usam a mesma porta SSH: **não escreva porta nenhuma** no arquivo. O netsnap pergunta a porta padrão na execução.
- Escreva `IP:porta` apenas quando souber que aquele host específico usa porta SSH diferente das demais.
- Nunca copie o campo `port` do Zabbix para o arquivo.

---

## Regras de conversão

1. **Extraia o endereço da interface principal** de cada host (`main = 1`). Se houver várias interfaces, prefira a de gerência.
2. **Prefira o IP ao DNS.** Se o host só tiver nome DNS, mantenha o nome — o netsnap resolve, mas registre isso num comentário, porque nome que não resolve vira falha de coleta.
3. **Descarte:**
   - templates (`status = 3`)
   - proxies (`status = 5` ou `6`)
   - hosts sem endereço
   - hosts que não aceitam SSH: nobreaks, sensores, câmeras, ONUs, servidores Windows sem OpenSSH, appliances só-SNMP
4. **Hosts desabilitados** (`status = 1`): pergunte se devem entrar. Por padrão, exclua.
5. **Remova duplicatas.** É comum o mesmo equipamento aparecer em vários grupos.
6. **Agrupe por grupo do Zabbix** usando comentários — facilita revisar antes de rodar.
7. **Ordene por endereço** dentro de cada grupo.

---

## Entradas possíveis

### Saída do módulo Zabbix do próprio netsnap

Campos separados por tabulação, nesta ordem: `host`, `name`, `estado`, `ip`, `dns`, `port`.

```
BRAS-NORTE	BRAS Norte	monitorado	198.51.100.13		161
OLT-CENTRO	OLT Centro	monitorado	10.200.1.1		161
SW-VELHO	Switch antigo	desabilitado	10.0.0.9		10050
```

Use a **quarta** coluna. Ignore a sexta.

### Exportação CSV do frontend

Colunas variam por versão. Localize a que contém endereços IPv4 e use apenas ela.

### JSON da API (`host.get` com `selectInterfaces`)

O endereço está em `interfaces[].ip`, com `main: "1"`. Quando `useip` for `"0"`, o Zabbix usa o campo `dns`.

### Texto colado da interface web

Extraia o que casar com um padrão de IPv4 e descarte o resto.

---

## Exemplo completo

**Entrada** (saída do módulo Zabbix do netsnap):

```
BRAS-NORTE	BRAS Norte	monitorado	198.51.100.13		161
BRAS-SUL	BRAS Sul	monitorado	198.51.100.14		161
OLT-CENTRO	OLT Centro	monitorado	10.200.1.1		161
NOBREAK-SALA1	Nobreak sala 1	monitorado	10.200.9.5		161
SW-VELHO	Switch antigo	desabilitado	10.0.0.9		10050
Template Net Juniper	Template Net Juniper	template		
BRAS-NORTE	BRAS Norte	monitorado	198.51.100.13		161
```

**Saída** (`alvos.txt`):

```
# Gerado a partir da lista de hosts do Zabbix
# Excluídos: 1 template, 1 host desabilitado (SW-VELHO),
#            1 duplicata (BRAS-NORTE), 1 equipamento sem SSH (NOBREAK-SALA1)

# BRAS
198.51.100.13
198.51.100.14

# OLTs
10.200.1.1
```

---

## Como usar o resultado

```bash
python3 netsnap.py alvos.txt
```

Se algum grupo usar porta SSH diferente, gere **um arquivo por grupo** em vez de misturar portas no mesmo arquivo — o netsnap pergunta a porta padrão uma vez por execução.

---

## Antes de entregar, confira

- [ ] Uma entrada por linha, sem cabeçalho, aspas, vírgulas ou numeração
- [ ] Nenhuma porta do Zabbix (10050, 10051, 161, 623) escrita no arquivo
- [ ] Sem templates, proxies nem duplicatas
- [ ] Todo endereço é IPv4/IPv6 válido ou nome DNS resolvível
- [ ] Equipamentos sem SSH removidos
- [ ] Comentário no topo dizendo o que foi excluído e por quê
- [ ] Se o total passar de 256 alvos, avise: o netsnap pede confirmação nesse caso

Se algo for ambíguo — host só com DNS, grupo que talvez não aceite SSH, dúvida sobre incluir desabilitados — **liste as dúvidas junto com o arquivo** em vez de decidir sozinho. Alvo errado no arquivo vira tentativa de login em equipamento de produção.
