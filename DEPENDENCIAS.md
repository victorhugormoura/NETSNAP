# Dependências do netsnap

## O problema

O netsnap depende do Netmiko, cuja árvore é:

```
netmiko → paramiko → cryptography → cffi        (extensão em C)
                   → bcrypt                      (extensão em Rust)
                   → pynacl                      (extensão em C)
        → ntc-templates, textfsm, pyyaml, ruamel.yaml, rich, scp, pyserial
```

As três extensões compiladas são a origem do trabalho de instalação: em distribuições sem *wheel* pronta para a arquitetura ou a versão do Python, o pip tenta compilar, e aí é preciso toolchain de C, toolchain de Rust, cabeçalhos do OpenSSL e do Python. É o que obriga a compilar tudo do zero.

## A solução adotada

`netsnap_transporte.py` implementa o acesso aos equipamentos **usando apenas a biblioteca padrão**. Quando o coletor for migrado para ele (ver *Estado da integração*, no fim), o Netmiko passa a ser opcional.

| Transporte | Como funciona | Dependência |
|---|---|---|
| **Telnet** | Cliente completo implementado aqui: TCP mais negociação de opções da RFC 854 | nenhuma |
| **SSH (Unix)** | Conduz o binário `ssh` do sistema por um pseudoterminal (`pty`, `termios`, `select` — tudo stdlib) | cliente OpenSSH |
| **SSH (Windows)** | Conduz o binário `ssh` fornecendo a senha por `SSH_ASKPASS` | cliente OpenSSH |
| **SSH (chave)** | Autenticação por chave pública, sem senha | cliente OpenSSH |

O cliente OpenSSH vem instalado por padrão em Linux, macOS, BSD e no Windows 10/11 (Configurações → Aplicativos → Recursos opcionais → Cliente OpenSSH). Não é um pacote Python: não compila nada, não depende da versão do interpretador.

Verifique o que está disponível na máquina com:

```bash
python3 netsnap_transporte.py
```

## Por que não implementar SSH em Python puro

Seria a única forma de zerar também a dependência do binário `ssh`, e **não é viável de forma responsável**. O protocolo exige troca de chaves Diffie-Hellman ou Curve25519, cifras de bloco (AES) e HMAC. A biblioteca padrão oferece resumo criptográfico (`hashlib`, `hmac`), mas não AES nem curvas elípticas. Implementá-los em Python puro produziria código lento e, sobretudo, uma implementação criptográfica caseira e não auditada — exatamente o tipo de coisa que não deve existir numa ferramenta que se conecta a equipamentos de produção com credenciais de administrador.

Delegar ao OpenSSH do sistema entrega o oposto: uma implementação madura, auditada e mantida, que já está na máquina.

Telnet não tem esse problema porque não tem criptografia nenhuma — é texto sobre TCP, e a implementação cabe em algumas centenas de linhas verificáveis. Implementá-lo também resolve a remoção de `telnetlib` da biblioteca padrão no Python 3.13 (PEP 594).

## Compatibilidade com equipamentos antigos

Switches, OLTs e roteadores em produção costumam oferecer apenas algoritmos que o OpenSSH recente desabilitou por padrão. O transporte solicita explicitamente os mais comuns — `diffie-hellman-group1-sha1`, `ssh-rsa`, `aes128-cbc`, `hmac-sha1`, entre outros.

**A lista não pode ser fixa.** O OpenSSH aborta com `Bad key types` ao receber o nome de um algoritmo que não implementa, e o OpenSSH 10 removeu o DSA por completo. Pedir `ssh-dss` a partir de um Debian 13 impediria *toda* conexão, a cada host. Por isso o transporte consulta `ssh -Q kex/key/cipher/mac` uma vez por execução e solicita apenas o que aquele cliente reconhece.

O diagnóstico mostra o resultado dessa negociação:

```
algoritmos_legados_ativos  diffie-hellman-group14-sha1, ssh-rsa, aes128-cbc, hmac-sha1, ...
removidos_nesta_versao     ssh-dss, diffie-hellman-group1-sha1
```

Se algum equipamento ainda recusar, o erro indica qual algoritmo falta; as listas ficam em `LEGADO_KEX`, `LEGADO_CHAVE`, `LEGADO_CIFRA` e `LEGADO_MAC`, no topo do arquivo, e só entram na conexão os que o `ssh -Q` reconhecer.

Pela mesma razão, o transporte usa `PubkeyAcceptedKeyTypes`, e não o nome novo `PubkeyAcceptedAlgorithms`: o nome novo só existe a partir do OpenSSH 8.5, e opção desconhecida também aborta o cliente — o que impediria toda conexão a partir do Windows 10 (OpenSSH 8.1), Ubuntu 20.04 (8.2) ou RHEL 8 (8.0). As versões novas continuam aceitando o nome antigo.

No Windows, a senha é entregue por `SSH_ASKPASS` com `SSH_ASKPASS_REQUIRE=force`, recurso do OpenSSH 8.4 em diante. Com cliente mais antigo, o transporte recusa a conexão com uma mensagem clara em vez de deixar o `ssh` pedir a senha no console.

Esse é, aliás, um ganho sobre o Netmiko: ajustar algoritmos passa a ser configuração do OpenSSH, em vez de depender do que o Paramiko compilou.

## Os dois transportes convivem

O Netmiko continua suportado como transporte alternativo, sob a mesma interface: quem chama não distingue um do outro, e as duas rotas devolvem os mesmos erros (`ErroAutenticacao`, `ErroConexao`).

```python
import netsnap_transporte as tr

tr.conectar(ip, usuario, senha, 22, "ssh")                       # automático
tr.conectar(ip, usuario, senha, 22, "ssh", transporte="nativo")  # força nativo
tr.conectar(ip, usuario, senha, 22, "ssh", transporte="netmiko",
            driver="juniper_junos")                              # força netmiko
```

A escolha automática prefere o nativo, por não exigir instalação; o Netmiko entra apenas quando o cliente OpenSSH está ausente e o Netmiko presente. `transporte_padrao()` informa qual seria usado, e o diagnóstico mostra se o Netmiko está instalado.

Manter os dois tem valor prático: diante de um equipamento que se comporte de forma estranha, dá para repetir a coleta pelo outro transporte e comparar — isolando se o problema está no equipamento ou na camada de acesso.

Validado lado a lado contra o mesmo servidor: prompt idêntico, saída idêntica, exceções equivalentes.

## Requisitos depois da integração

| Item | Situação |
|---|---|
| Python 3.8+ | presente em qualquer sistema atual |
| Cliente OpenSSH | presente por padrão; necessário só para SSH |
| Pacotes Python | **nenhum** (Netmiko é opcional) |
| Compilador | **nenhum** |

Com a integração concluída, a instalação passa a ser copiar os arquivos `.py` e executar. Hoje o `netsnap.py` e o `netdiag.py` ainda exigem o Netmiko.

## Estado da integração

O `netsnap_transporte.py` está validado de forma isolada (SSH por pty e por askpass contra um sshd local; SSH a partir do Windows contra um MX104 em campo; Telnet apenas contra servidor de teste, ainda sem validação em OLT real), mas **o `netsnap.py` ainda usa o Netmiko**. A migração do coletor para esta camada é o próximo passo; até lá, o Netmiko continua sendo requisito do `netsnap.py` e do `netdiag.py`.
