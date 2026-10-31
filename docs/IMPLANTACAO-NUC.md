# Implantação numa máquina Windows 11 (NUC) com Claude Code

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com

Cenário: uma VM ou máquina Windows 11 que alcança as redes de gerência dos
clientes, onde rodam as coletas, a triagem de vulnerabilidades e a análise por
IA, com o Claude Code para operar e evoluir as ferramentas. Começa só com
leitura.

## 1. Onde roda cada parte

| Parte | Windows 11 nativo | Linux (VM na NUC ou WSL2) |
|---|---|---|
| Coleta pelo painel local (`netsnap_web.py`) | sim | sim |
| `netcve.py` (NVD, OSV, KEV, EPSS, catálogo) | sim | sim |
| `netsnap_ia.py` (análise por IA) | sim | sim |
| Servidor multiusuário (`servidor/`: cofre, agendador, TOTP) | não | sim (systemd) |
| Sandbox de comandos do Claude Code | não suportado no Windows nativo | suportado (WSL2 e Linux) |

Recomendação, em ordem:

1. **Agora:** tudo em Windows nativo (seção 2). O painel local, o netcve e o
   netsnap_ia foram testados com Python para Windows, inclusive em pasta com
   espaço e acento.
2. **Para agendamento e vários técnicos:** uma VM Ubuntu Server 24.04 na NUC,
   na mesma rede da VM Windows, com o `servidor/` (seção 3). É o caminho com
   systemd de verdade.
3. **WSL2 só se não der para criar outra VM.** Dentro de uma VM Windows, o
   WSL2 exige virtualização aninhada habilitada no hipervisor da NUC.
   `[validar na NUC]`

## 2. Windows 11 nativo

PowerShell (usuário comum, não administrador):

```powershell
# Python 3.12 ou mais novo (python.org) com a opção "Add to PATH"; depois:
py -m pip install --upgrade netmiko certifi

# Código
git clone https://github.com/victorhugormoura/NETSNAP.git C:\netsnap
cd C:\netsnap
py netsnap.py --version

# Pasta privada (fora do repositório): skills completas e chaves
New-Item -ItemType Directory C:\netsnap-privado\contextos -Force
[Environment]::SetEnvironmentVariable("NETSNAP_CONTEXTOS", "C:\netsnap-privado\contextos", "User")
```

Contextos privados: copie as skills para `C:\netsnap-privado\contextos`
com o nome da plataforma. Uma pasta inteira também serve (todos os `.md`
dentro entram, em ordem alfabética):

```
C:\netsnap-privado\contextos\junos\SKILL.md
C:\netsnap-privado\contextos\junos\references\...      (opcional)
C:\netsnap-privado\contextos\mikrotik\mikrotik-kb.md
```

Não copie a pasta de casos reais da skill nem nada com endereçamento de cliente para o
repositório. Na pasta privada, avalie o tamanho: o contexto é cortado em
150 mil caracteres por plataforma.

Uso diário:

```powershell
py netsnap_web.py                                   # coleta pelo navegador
py netcve.py snapshots --json --csv                 # triagem (NVD, OSV, KEV, EPSS)
$env:ANTHROPIC_API_KEY = "<chave>"                  # só nesta janela
py netsnap_ia.py snapshots --simular                # confira o que seria enviado
py netsnap_ia.py snapshots                          # análise por IA
```

Para não mandar dado para fora da rede, use um modelo local com API
compatível com OpenAI (Ollama, LM Studio, vLLM):

```powershell
py netsnap_ia.py snapshots --provedor openai --url http://127.0.0.1:11434/v1 --modelo <modelo>
```

## 3. Servidor multiusuário numa VM Linux

Na VM Ubuntu Server 24.04 (rede em ponte com as VLANs de gerência):

```bash
git clone https://github.com/victorhugormoura/NETSNAP.git && cd NETSNAP
./servidor/montar.sh --zip
cd servidor/build/netsnap-servidor && sudo ./instalar.sh
```

Manual completo em `servidor/LEIA-ME.md`. O que nunca foi testado: systemd
real como PID 1, Debian 12 e Ubuntu 22.04, Let's Encrypt, TPM2 físico.
Confira `systemctl status netsnap-servidor` e uma coleta logo depois da
instalação.

### Alternativa: WSL2 `[validar na NUC]`

```powershell
wsl --install -d Ubuntu-24.04
```

`%UserProfile%\.wslconfig` (rede espelhada, Windows 11 22H2+, para o WSL
alcançar as mesmas redes e receber conexões da LAN):

```ini
[wsl2]
networkingMode=mirrored
```

Liberação de entrada no firewall do Hyper-V para o painel (PowerShell como
administrador; a porta é a escolhida no instalador):

```powershell
New-NetFirewallHyperVRule -Name "netsnap-https" -DisplayName "netsnap HTTPS" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 443
```

Dentro do WSL, `/etc/wsl.conf` precisa de `[boot]` com `systemd=true`. O
WSL desliga a VM quando não há processo usando a distribuição; para um
servidor 24 horas, a VM Linux da seção 3 é mais previsível.

## 4. Claude Code na máquina

PowerShell, sem administrador:

```powershell
irm https://claude.ai/install.ps1 | iex
claude --version
```

O Git for Windows é recomendado (o Claude Code usa o Git Bash para comandos;
sem ele, usa o PowerShell). Rode `claude` dentro de `C:\netsnap` e faça o
login pelo navegador.

### Permissões: só leitura

`C:\netsnap\.claude\settings.local.json` (não vai para o Git) deixa o Claude
Code rodar a triagem e a análise, ler snapshots e o código, e o impede de
abrir sessão em equipamento ou de apagar arquivos. Ajuste ao uso:

```json
{
  "permissions": {
    "allow": [
      "Bash(py netcve.py *)",
      "Bash(py netsnap_ia.py *)",
      "Bash(python netcve.py *)",
      "Bash(python netsnap_ia.py *)",
      "Bash(git status)",
      "Bash(git diff *)",
      "Bash(git log *)",
      "PowerShell(py netcve.py *)",
      "PowerShell(py netsnap_ia.py *)",
      "Read(./**)"
    ],
    "deny": [
      "Bash(ssh *)", "Bash(telnet *)", "Bash(plink *)", "Bash(scp *)",
      "Bash(rm *)", "Bash(git push *)",
      "PowerShell(ssh *)", "PowerShell(telnet *)", "PowerShell(plink *)",
      "PowerShell(Remove-Item *)", "PowerShell(git push *)",
      "Read(//C:/netsnap-privado/chaves/**)"
    ]
  }
}
```

A regra `Read(//C:/...)` usa o caminho absoluto com `//`; confira com
`/permissions` dentro do Claude Code se ela aparece como esperado no
Windows `[validar na NUC]`.

Regra de ouro: as senhas dos equipamentos não passam pelo chat. A coleta é
feita pelo netsnap (que pede a senha no terminal ou no painel, ou usa o
cofre do servidor); o Claude Code trabalha sobre os snapshots, que já saem
com os segredos mascarados.

## 5. Contas só leitura nos equipamentos

Crie uma conta dedicada por equipamento, restrita à origem da NUC, e
confira com uma coleta de teste antes de usar no parque. As linhas marcadas
`[validar em lab]` não foram conferidas em equipamento.

Junos (classe só leitura; mostra a configuração sem os segredos):

```
set system login class NETSNAP-RO permissions [ view view-configuration ]
set system login user netsnap class NETSNAP-RO authentication plain-text-password
```

Confira `show log messages` com essa classe: se for negado, acrescente a
permissão necessária ao log `[validar em lab]`.

RouterOS 7 (grupo só leitura, preso ao IP da NUC):

```
/user group add name=netsnap-ro policy=ssh,read,!write,!policy,!password,!sensitive,!reboot,!test,!sniff,!local,!telnet,!ftp,!winbox,!web,!api,!romon,!rest-api
/user add name=netsnap group=netsnap-ro address=<IP-da-NUC>/32 password="<senha-forte>"
```

Sem `sensitive`, confira se `/export show-sensitive` ainda devolve a
configuração (com os segredos ocultos) ou se é negado `[validar em lab]`.

Huawei VRP, Cisco e OLTs: as contas serão preparadas com a mesma
conferência em laboratório antes de entrar aqui.

## 6. Saídas para integração (painel Infinity, outros sistemas)

| Arquivo | Formato | Gerado por |
|---|---|---|
| `_cve_triagem_<data>.json` | `netcve/1` | `netcve.py --json` |
| `_ia_analise_<data>.json` | `netanalytic-achados/1` | `netsnap_ia.py` |
| pacote `.zip` do servidor | `netsnap-analise/1` | agendamento com análise |

Os três são JSON estável, pensados para serem lidos por um painel.
