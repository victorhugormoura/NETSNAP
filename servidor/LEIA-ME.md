# netsnap servidor 1.0.2

O netsnap como servidor Linux. Os técnicos entram por uma página web, com senha e um código do aplicativo autenticador, e coletam dali, sem instalar nada no próprio computador. As senhas dos equipamentos ficam num cofre cifrado no servidor. O agendador extrai configuração, logs, estado, interfaces, vizinhança e inventário todo dia, em dias da semana escolhidos, a cada N dias ou a cada N horas. Ao fim de cada execução ele gera um **pacote de análise** para a IA do NETANALYTIC.

Continua somente leitura: nenhum comando altera os equipamentos.

---

## 1. Como funciona

```
 navegador do técnico
        │  HTTPS (TLS 1.2/1.3, HSTS)
        ▼
 Nginx ou Apache  ── certificado: CA interna, Let's Encrypt ou próprio
        │  limite de tentativas de login, restrição por rede (opcional)
        │  socket Unix /run/netsnap/netsnap.sock (só o grupo www-data e o root)
        ▼
 netsnap-servidor (systemd, usuário "netsnap", sem privilégios)
        │  login + TOTP, papéis, sessões, CSRF, auditoria encadeada
        │  cofre AES-256-GCM, cada credencial presa às suas redes
        │                     ◄── chave-mestra entregue pelo systemd
        │  agendador          ──► pacote de análise (.zip)
        ▼
 processo de coleta (netsnap)  ── SSH/Telnet ──►  equipamentos
```

| Onde | O quê |
|---|---|
| `/opt/netsnap/app` | programa (root, somente leitura para o serviço) |
| `/opt/netsnap/venv` | Python isolado com netmiko e cryptography, instalados com conferência de hash |
| `/etc/netsnap/servidor.conf` | configuração do serviço |
| `/etc/netsnap/instalacao.conf` | escolhas do instalador (servidor web, nomes, porta, redes, certificado) |
| `/etc/netsnap/credenciais/` | chave-mestra (root, 0400), selada pelo `systemd-creds` quando o systemd é 250 ou mais novo |
| `/etc/netsnap/pki/` | certificado HTTPS e, no modo CA interna, a CA |
| `/var/lib/netsnap/` | banco (usuários, cofre, agendamentos, auditoria), snapshots, diagnósticos e pacotes de análise |
| `/usr/local/sbin/netsnapctl` | administração pelo terminal |
| `/run/netsnap/netsnap.sock` | socket por onde o Nginx/Apache fala com o serviço |

---

## 2. Requisitos

- Debian 12 ou mais novo, ou Ubuntu 22.04 ou mais novo, com systemd.
- Acesso de root e internet durante a instalação (pacotes do sistema e do PyPI).
- Do servidor até os equipamentos: SSH (ou Telnet) e ICMP liberados, como numa coleta normal.
- Até os técnicos: a porta HTTPS escolhida, padrão 443. Para Let's Encrypt, também a porta 80 aberta para a internet e um nome DNS público.
- Hardware: 2 vCPU e 2 GB de RAM atendem dezenas de equipamentos por execução. Cada login usa 128 MB por alguns décimos de segundo (scrypt), e no máximo dois logins são calculados ao mesmo tempo (um por IP). Calcule o disco pela retenção: um snapshot completo tem de 50 KB a alguns MB.

---

## 3. Instalação

O pacote `netsnap-servidor-<versão>.zip` fica anexado em cada *release* do repositório no GitHub, com o SHA-256 na descrição. Para montar a partir do código, na raiz do repositório:

```bash
./servidor/montar.sh --zip      # gera servidor/dist/netsnap-servidor-<versão>.zip e mostra o sha256
```

O mesmo commit gera sempre o mesmo zip (ordem, datas e permissões fixas), então o SHA-256 pode ser conferido montando de novo a partir do mesmo commit em outra máquina. No servidor:

```bash
sha256sum netsnap-servidor-1.0.2.zip   # compare com o sha256 mostrado pelo montar.sh
unzip netsnap-servidor-1.0.2.zip
cd netsnap-servidor
sudo ./instalar.sh
```

O instalador pergunta, sempre com um padrão que o Enter aceita:

1. **Nome principal** do painel (DNS ou IP) e **outros nomes/IPs**. Todos entram no certificado e na lista de nomes aceitos.
2. **Servidor web**: Nginx (recomendado) ou Apache.
3. **Porta HTTPS** e **redes permitidas** (CIDR). Restringir às redes de gerência e à VPN é a recomendação.
4. **Certificado**:
   - *CA interna*: o servidor cria uma CA própria e emite o certificado. Funciona com IP. Os técnicos instalam a CA uma vez (seção 4). A CA só vale para os nomes deste servidor (*Name Constraints*): mesmo que a chave dela vaze, um certificado emitido com ela para outro site é recusado pelo navegador. A renovação é automática (timer diário; renova a 30 dias do vencimento).
   - *Let's Encrypt*: exige nomes DNS públicos (sem IP) e a porta 80 aberta. A renovação fica com o `certbot.timer` do sistema.
   - *Importar*: arquivos PEM do certificado, da chave e, se preciso, da cadeia.
5. **Retenção** de snapshots, **execuções simultâneas** e se o **Telnet** é permitido.
6. **Fuso horário** (os agendamentos usam o horário do servidor) e, se o `ufw` estiver ativo, a liberação das portas.

Em seguida ele instala os pacotes e cria o usuário de serviço, a chave-mestra, o banco, o serviço systemd, o certificado e o site do Nginx ou Apache. No fim, confere o HTTPS de ponta a ponta. Então:

- cria a **sua conta de administrador** e cadastra a verificação em duas etapas ali mesmo no terminal, com QR code e códigos de recuperação;
- oferece exportar a **cópia da chave-mestra** (seção 7). Faça.

Se algo falhar no meio, corrija e rode o instalador de novo: ele detecta a instalação, retoma e não apaga dados.

**Atualizar:** extraia a versão nova e rode `sudo ./instalar.sh` → *Atualizar o programa*. Dados, usuários, cofre, configuração e chave são mantidos. Se o serviço não subir com a versão nova, o instalador volta para a anterior.

**Mudar nomes, porta, servidor web ou certificado:** `sudo ./instalar.sh` → *Refazer a configuração*.

---

## 4. Primeiro acesso dos técnicos

1. Com a CA interna, instale a CA no computador do técnico. Ela pode ser baixada pelo link na tela de login ou em `/etc/netsnap/pki/ca.crt`. Antes de instalar, compare a impressão SHA-256 do arquivo baixado com a que o administrador passou por outro canal (ela aparece no fim da instalação e em `netsnapctl status`): a tela de login mostra a impressão servida, mas, se a conexão estiver interceptada, essa também pode ser falsa. Para ver o SHA-256 do arquivo: `sha256sum` ou `openssl x509 -in ca.crt -noout -fingerprint -sha256` no Linux e no macOS, `certutil -hashfile ca.crt SHA256` no Windows (a janela de certificado do Windows mostra só o SHA-1).
   - **Windows:** `certmgr.msc` → *Autoridades de Certificação Raiz Confiáveis* → *Certificados* → *Todas as tarefas* → *Importar*. Chrome e Edge passam a confiar.
   - **Firefox:** *Configurações* → *Privacidade e Segurança* → *Certificados* → *Ver certificados* → *Autoridades* → *Importar* → marque "identificar sites".
   - **Linux:** `sudo cp netsnap-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
   - **macOS:** abra o arquivo, adicione ao *Sistema* no Acesso às Chaves e marque *Sempre confiar*.
2. O administrador cria o usuário em **Usuários** e define uma senha provisória (há botão para gerar uma). Passe-a ao técnico por um canal seguro.
3. No primeiro login, o técnico:
   - cadastra o aplicativo autenticador (Google Authenticator, Microsoft Authenticator, Authy, FreeOTP ou o gerenciador de senhas);
   - guarda os 10 códigos de recuperação;
   - define a senha pessoal.

**Perfis:**

| | Leitura | Técnico | Administrador |
|---|:-:|:-:|:-:|
| Snapshots, inventário, comparação, topologia, vulnerabilidades, pacotes de análise | sim | sim | sim |
| Coletar, diagnosticar, agendar | | sim | sim |
| Usar o cofre e guardar credenciais | | sim | sim |
| Alterar ou remover a credencial de outra pessoa | | | sim |
| Desligar a verificação TLS das bases de CVE | | | sim |
| Usuários, auditoria, remover pacotes | | | sim |

Senha: 12 ou mais caracteres misturando três tipos (minúsculas, maiúsculas, números, símbolos), ou uma frase com 16 ou mais. Há dois bloqueios:
- **Conta + origem:** cinco erros seguidos (senha ou código) vindos do mesmo IP, ou da mesma /64 em IPv6, bloqueiam aquela conta para aquela origem por 15 minutos, dobrando a cada novo bloqueio até 24 horas. Quem erra de outro lugar não tranca o dono da conta, e erros de um navegador desconhecido na mesma saída de NAT/VPN não trancam o navegador já conhecido do dono.
- **Conta inteira:** 30 erros de origens variadas bloqueiam a conta por 15 minutos, sem acumular. Esse bloqueio não vale para um navegador onde o usuário já entrou com sucesso (cookie de dispositivo, 180 dias). Quem tenta trancar o administrador de fora não o impede de entrar do computador de sempre.

O administrador desbloqueia em **Usuários**. A sessão expira após 30 minutos sem uso ou 12 horas no total (ajustável).

---

## 5. Uso

**Cofre de credenciais.** Guarde ali usuário e senha dos equipamentos, de preferência um usuário só de leitura, e as **redes onde a credencial pode ser usada** (CIDR, obrigatório). A senha nunca volta para o navegador: quem coleta escolhe a credencial pelo nome, e o servidor a entrega apenas ao processo de coleta.

As redes também barram outro caminho: sem elas, alguém com perfil técnico apontaria a coleta para um servidor próprio (um SSH falso ou um `nc` na porta do Telnet) e receberia a senha. O servidor confere cada alvo de coletas, diagnósticos e agendamentos, inclusive a cada disparo. Nomes DNS são resolvidos uma vez, conferidos e trocados pelo IP, para o coletor não consultar o DNS de novo. Qualquer alvo fora das redes recusa a execução inteira.

Mais regras do cofre:
- O Telnet só é aceito numa credencial marcada para isso.
- Só um administrador muda as redes, ou a permissão de Telnet, de uma credencial.

Na tela de coleta também dá para digitar usuário e senha só para aquela execução, sem passar pelo cofre.

**Nova coleta.** É a mesma tela do painel local, com a credencial vinda do cofre. A opção de incluir senhas no snapshot fica desligada no servidor (`permitir_dados_sensiveis`).

**Agendamentos.** Cada agendamento tem nome, alvos, o que extrair (o padrão é *Extração total*: configuração, logs, estado, interfaces e ópticas, vizinhança e inventário), credencial, protocolo e frequência:

- todo dia num horário;
- em dias da semana marcados;
- a cada N dias (7 = semanal) a partir de uma data;
- a cada N horas.

O servidor executa sozinho, sem ninguém conectado. Se o limite de execuções simultâneas estiver ocupado, ele tenta de novo 15 segundos depois sem perder a vez. Depois de um desligamento, um agendamento atrasado roda uma vez assim que o serviço volta.

**Pacotes de análise.** Com "Gerar pacote de análise" marcado, cada execução concluída gera um `.zip`, baixado em **Pacotes de análise**:

| Arquivo | Conteúdo |
|---|---|
| `manifesto.json` | execução, totais, hosts que falharam e motivo |
| `resumo.json` | por equipamento (detalhes abaixo) |
| `RESUMO.md` | o mesmo resumo em tabela, para o NOC |
| `PROMPT.md` | instruções para a IA: o que avaliar, regras (evidência citada, sintaxe por plataforma, correção só como proposta com reversão e confirmação humana) e o formato JSON da resposta (`netanalytic-achados/1`) |
| `snapshots/` | os snapshots da execução, já sem segredos |
| `mudancas/` | `diff` da configuração desde a coleta anterior do mesmo equipamento |

Em `resumo.json`, cada equipamento traz:
- plataforma, modelo e versões;
- apontamentos de configuração, pelas heurísticas do netcve;
- logs por gravidade (crítico, erro, queda, aviso) com as mensagens mais repetidas;
- linhas com contadores de erro diferentes de zero (CRC, FCS, drops, discards, bit errors…) já com a interface;
- comandos sem saída, sessão interrompida;
- tamanho da mudança de configuração.

As linhas de contador e a contagem de logs são **heurísticas**: apontam onde olhar, e a IA confirma no snapshot.

**Retenção.** Snapshots mais antigos que o configurado são apagados, mas **o último de cada equipamento nunca sai**. Pacotes e histórico de execuções têm retenção própria (365 dias, padrão).

---

## 6. Administração (`sudo netsnapctl`)

Sem argumentos, abre um menu. Comandos diretos:

| Comando | Para quê |
|---|---|
| `netsnapctl status` | serviço, endereço, certificado (validade, nomes, impressão da CA), contagens, agendamentos, disco |
| `netsnapctl usuario criar\|listar\|senha\|totp\|desbloquear\|ativar\|desativar\|remover [nome]` | contas; `senha` gera uma senha provisória, e `totp` obriga a cadastrar o autenticador de novo |
| `netsnapctl certificado [ca-interna\|letsencrypt\|importar\|renovar\|mostrar]` | sem argumento, abre o menu |
| `netsnapctl web configurar` | regera o site do Nginx ou Apache a partir de `instalacao.conf`, testa (`nginx -t` / `apache2ctl configtest`) antes de recarregar e mantém o anterior se o teste falhar |
| `netsnapctl chave exportar [arquivo]` / `importar <arquivo>` | cópia da chave-mestra protegida por frase |
| `netsnapctl backup criar [pasta]` / `restaurar <arquivo>` | backup cifrado completo |
| `netsnapctl auditoria verificar` | recalcula a cadeia HMAC da auditoria |

Para ver o log: `journalctl -u netsnap-servidor -f`. Cada requisição aparece com IP, usuário, rota, código e tempo. Um erro interno mostra uma referência que aparece também no log.

---

## 7. Segurança: o que protege o quê

**Chave-mestra (256 bits).** Ela nunca é gravada em claro no espaço do serviço. Em systemd 250 ou mais novo (Debian 12, Ubuntu 24.04), fica selada pelo `systemd-creds`. Com TPM2 presente, ela fica atrelada ao TPM desta máquina; sem TPM2, à chave do host em `/var/lib/systemd/credential.secret`. No Ubuntu 22.04 (systemd 249) é um arquivo legível só pelo root. Nos dois casos o systemd a entrega ao serviço num diretório em memória (`LoadCredential`), e o serviço nunca lê `/etc/netsnap/credenciais`. Ressalva: o processo de coleta, que interpreta a saída dos equipamentos, roda com o mesmo usuário do serviço e conseguiria ler esse diretório e o banco. Isolá-lo exige um usuário à parte para a coleta (segunda unidade sem `LoadCredential`), ainda não implementado.

**Cofre.** Usa AES-256-GCM com nonce aleatório e contexto autenticado. Copiar a senha cifrada de uma credencial para outra não funciona: a decifração falha. Usuário e senha do equipamento ficam cifrados juntos.

**Senhas do painel.** O hash é scrypt (N=2^17, r=8, p=1, o mínimo da OWASP), e o próprio hash ainda vai cifrado com a chave-mestra. Quem copiar só o banco não consegue atacar as senhas offline. Um login com usuário inexistente leva o mesmo tempo que um com usuário válido.

**Segundo fator.** TOTP (RFC 6238) sem reuso: o mesmo código não vale duas vezes, nem em abas diferentes. Os 10 códigos de recuperação são de uso único.

**Sessão.**
- Cookie `__Host-netsnap` com `Secure`, `HttpOnly` e `SameSite=Strict`.
- No banco fica só um HMAC do token.
- Toda alteração exige o token CSRF da sessão, e a origem é conferida.
- Trocar a senha, desativar a conta ou mudar o perfil encerra as outras sessões.

**Rede.**
- O serviço não abre porta TCP. Ele escuta num socket Unix criado pelo systemd (`netsnap-servidor.socket`, dono `netsnap`, grupo `www-data`, permissão 0660). Só o Nginx/Apache, o root e o que roda no grupo `www-data` conectam. Assim um usuário comum da máquina não chega à API nem forja o IP de origem. Se houver outros aplicativos web no mesmo servidor rodando como `www-data` (PHP-FPM, por exemplo), eles também alcançariam o socket: prefira um servidor dedicado.
- O serviço confere o cabeçalho `Host`.
- O IP do cliente vem do `X-Real-IP` gravado pelo proxy; o cabeçalho forjado pelo cliente é sobrescrito.
- Limites de login:
  - no Nginx: 30 por minuto por IP, rajada de 20;
  - no serviço: 60 a cada 5 minutos por IP (por /64 em IPv6);
  - bloqueios por conta+origem e por conta (seção 4);
  - no máximo dois cálculos de senha ao mesmo tempo e um por IP: a segunda tentativa simultânea do mesmo IP recebe 429, e o excesso geral, 503, em vez de fila infinita;
  - no Apache não há limite equivalente ao do Nginx: valem os do serviço.
- Restrição por rede (`allow`/`Require ip`) no proxy, opcional.

**Processo.** O systemd isola o serviço:
- `NoNewPrivileges`, `ProtectSystem=strict` (só `/var/lib/netsnap` é gravável), `ProtectHome`, `PrivateTmp`, `PrivateDevices`;
- filtro de chamadas de sistema `@system-service`, nenhuma *capability*, `UMask=0077`, sem *core dump*.

As senhas vão ao processo de coleta pela entrada padrão, nunca por argumento nem por variável de ambiente.

**Chaves SSH dos equipamentos.** A primeira coleta registra a chave em `/var/lib/netsnap/.netsnap_known_hosts`. Se a chave mudar depois, a conexão é recusada antes de enviar a senha.

**Auditoria.** Registra:
- logins, falhas e bloqueios (nome de usuário inexistente fica mascarado: dois caracteres, tamanho e um resumo, para uma senha digitada no campo errado não ir para o registro);
- uso de códigos de recuperação;
- usuários, credenciais, coletas, agendamentos e downloads.

Cada registro leva um HMAC do anterior e o próprio número, e o fim da trilha tem uma âncora assinada com a chave-mestra. Editar, apagar uma linha do meio ou cortar o final direto no banco é detectado em **Auditoria → Verificar integridade** ou com `netsnapctl auditoria verificar`. Cada registro também é copiado para o journald (`auditoria #N ... hash=...`). Assim, se o banco inteiro for trocado por uma versão antiga, o log do sistema ainda mostra a sequência original.

### O que isto não protege

- **Root no servidor lê tudo**: chave, banco, snapshots. O usuário `netsnap` (o próprio serviço) também tem a chave na memória. Proteja o acesso administrativo ao próprio servidor (SSH por chave, poucos administradores).
- **Redes da credencial.** Elas limitam *onde* a senha pode ir, não *qual* equipamento dentro da rede. Um host malicioso dentro da rede de gerência ainda recebe a tentativa de login, mas a chave SSH registrada no primeiro acesso recusa um equipamento que trocou de chave. Cadastre redes estreitas. O painel pede confirmação para redes mais amplas que /16 (IPv4) ou /48 (IPv6): nelas costumam caber pools de VPN, e um técnico mal-intencionado poderia receber a senha num host dele dentro da faixa.
- **Selagem sem TPM2.** A chave do host fica no mesmo disco. Ela protege contra a cópia isolada de `/etc/netsnap` ou de um backup do banco, mas não contra o roubo do disco inteiro.
- **Um servidor, uma equipe.** Todo usuário logado vê todos os snapshots e pacotes. Para clientes que não podem ver os dados uns dos outros, use um servidor por cliente.
- **Telnet** trafega a senha em texto claro. Desative-o (`permitir_telnet = nao`) onde não houver OLT antiga.

### Recuperação de desastre

Com TPM2, a chave-mestra só abre **nesta máquina**. Sem a cópia, a perda do servidor leva o cofre e os usuários junto. Então:

1. `sudo netsnapctl chave exportar`: guarde o arquivo e a frase em lugares diferentes, fora do servidor.
2. `sudo netsnapctl backup criar /caminho`: backup cifrado com uma frase (AES-256-GCM em blocos, scrypt). Ele leva banco, snapshots, pacotes, configuração, PKI e a própria chave-mestra. É gerado em fluxo, sem nenhum arquivo em claro no disco. Troca, corte ou repetição de blocos é detectado na restauração, e os dados atuais só são substituídos depois que o arquivo inteiro foi autenticado. Para agendar, grave a frase num arquivo do root com permissão 600 e use o cron do root:
   ```
   install -m 600 /dev/null /root/.netsnap-frase && editor /root/.netsnap-frase
   # crontab -e (root): todo dia às 04:15
   15 4 * * * /usr/local/sbin/netsnapctl backup criar /srv/backup --frase-arquivo /root/.netsnap-frase
   ```
   Leve os `.nsbk` para fora do servidor e apague os antigos.
3. Para restaurar num servidor novo: instale, depois `sudo netsnapctl backup restaurar arquivo.nsbk`. Se o nome do servidor mudou, rode `netsnapctl certificado` e `netsnapctl web configurar`.

---

## 8. Configuração (`/etc/netsnap/servidor.conf`)

```ini
[servidor]
porta = 8765                 ; só sem o socket do systemd (testes); em produção o serviço usa /run/netsnap/netsnap.sock
nomes = netsnap.empresa.com.br, 10.0.0.5   ; nomes aceitos no Host
porta_publica = 443
dados = /var/lib/netsnap

[sessao]
ociosidade_minutos = 30
duracao_maxima_horas = 12
exigir_totp = sim
emissor_totp = netsnap netsnap.empresa.com.br   ; nome no aplicativo autenticador

[coleta]
max_execucoes_simultaneas = 3
permitir_dados_sensiveis = nao   ; sim = administrador pode incluir segredos no snapshot
permitir_telnet = sim
permitir_alvos_locais = nao  ; sim só em laboratório (equipamento simulado em 127.x)

[retencao]
snapshots_dias = 180         ; 0 = para sempre (o último de cada equipamento nunca sai)
analises_dias = 365
execucoes_dias = 365
```

Depois de editar: `sudo systemctl restart netsnap-servidor`. Nomes e porta pública mudam pelo instalador (*Refazer a configuração*), porque também mexem no certificado e no site.

---

## 9. Problemas comuns

| Sintoma | Causa provável e solução |
|---|---|
| Navegador diz "certificado não confiável" | CA interna não instalada no computador (seção 4), ou o nome digitado não está na lista de nomes |
| "Host não permitido" (421) | o endereço usado não está em `nomes`: inclua pelo instalador (*Refazer a configuração*) |
| Código do autenticador sempre inválido | relógio do celular ou do servidor fora de hora: `timedatectl` e NTP. São aceitos 30 s de diferença |
| Todos os hosts "sem resposta ICMP" | ping sem permissão para o serviço: o netsnap testa o ping no loopback e, se falhar, pula a varredura e tenta todos. Confira `sysctl net.ipv4.ping_group_range` (precisa incluir o grupo `netsnap`; o instalador oferece liberar só para esse grupo) |
| "a chave SSH do equipamento é diferente" | o equipamento foi trocado ou teve a chave refeita, ou há interceptação. Confirme e apague a linha dele em `/var/lib/netsnap/.netsnap_known_hosts` |
| Serviço não sobe: "a chave-mestra carregada não é a que criou este banco" | banco restaurado sem a chave dele: `netsnapctl chave importar` com a cópia correspondente |
| Let's Encrypt falha | nome não aponta para o servidor, ou a porta 80 está fechada para a internet. Use a CA interna em rede fechada |

---

## 10. Testado e não testado

**Testado:**
- Testes automatizados: cofre e banco; API completa contra equipamentos simulados, incluindo login em etapas, TOTP com recuperação, papéis, bloqueio, CSRF, Host, cofre, coleta, agendamentos, pacote e auditoria; cálculo das próximas execuções e retenção. Rodam no CI em Python 3.10 e 3.12 e foram conferidos também em 3.13.
- Dependências instaladas pelo arquivo com hash em Python 3.10, 3.11 e 3.12, com pip e uv.
- Instalador em Ubuntu 24.04, com Nginx 1.24 e Apache 2.4.58 reais e `systemd-creds` real, cobrindo:
  - instalação nova, retomada após falha, troca de Nginx para Apache com porta 8443 e restrição por rede, atualização, desinstalação mantendo dados e reinstalação;
  - backup e restauração (com frase errada recusada), importação da chave, importação de certificado (com par inválido recusado);
  - a restrição da CA interna: um certificado para outro domínio, assinado com a chave dela, é rejeitado.
- Ponta a ponta pelo proxy, com o serviço só no socket Unix: cookie seguro, HSTS, 80→443, limite de login no Nginx (429), IP forjado sobrescrito, usuário comum da máquina barrado no socket e uma coleta feita pelo serviço sem privilégios.
- Ataques apontados por uma revisão de segurança independente, cada um reproduzido e depois corrigido:
  - desvio da senha do cofre para outro host (IP, nome DNS, rede, Telnet, agendamento, netdiag);
  - técnico mudando redes de credencial;
  - `ativo: 0` no último administrador;
  - corte e limpeza da auditoria;
  - CA interna com nomes só IP ou só DNS emitindo para outros domínios;
  - backup adulterado.

  Uma segunda rodada da mesma revisão conferiu as correções. As regressões que ela apontou também foram corrigidas e testadas:
  - a restauração agora confere o arquivo e a frase antes de parar o serviço, e sempre o religa: arquivo inexistente, frase errada e adulteração no início ou no meio foram testados, com o serviço no ar e os dados intactos;
  - bloqueio distribuído não tranca quem entra de um navegador conhecido;
  - CA de modelo anterior é recriada;
  - log da auditoria sem quebra de linha forjada.
- Interface no navegador, passando pelo Nginx com TLS, até o agendamento disparar sozinho no horário e gerar o pacote.

**Rodar os testes.** Precisam do `cryptography` e do `netmiko` (um venv com `pip install --require-hashes -r requirements.lock` resolve). No repositório, monte antes com `./servidor/montar.sh`; no pacote extraído, rode da pasta dele:
```bash
python3 testes/test_cofre_banco.py
python3 testes/test_agenda_retencao.py
sudo python3 testes/test_servidor.py            # com o roteador simulado em 127.0.1.18
python3 testes/test_servidor.py app 10.0.0.1    # ou contra um equipamento de teste com SSH
```
O terceiro sobe um servidor temporário e coleta com usuário `netsnap` e senha `Lab#2026!`. Sem equipamento no IP informado, ele sobe o roteador Junos simulado de `testes/equipamento_simulado.py` (saídas sintéticas; porta 22, por isso o `sudo`). Sem root e sem equipamento, os testes de coleta são pulados e o motivo aparece no resultado.

**Não testado:**
- Uma máquina real com o systemd como PID 1. O contêiner de teste usou um `systemctl` simulado que reproduz usuário, ambiente e entrega da chave. Por isso o filtro de chamadas de sistema e as demais restrições da unidade não foram exercitados de verdade: na primeira instalação, confira `systemctl status netsnap-servidor` e faça uma coleta.
- Debian 12 e Ubuntu 22.04 especificamente (Python 3.11 e 3.10 testados à parte).
- Emissão real pelo Let's Encrypt (não havia nome público no teste).
- TPM2 físico.

---

## Licença

Distribuído sob a licença MIT (arquivo `LICENSE`).

Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
