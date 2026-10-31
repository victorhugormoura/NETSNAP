# Política de segurança

## Como relatar uma vulnerabilidade

Não abra issue pública para falhas de segurança. Use o relato privado do GitHub
(aba **Security → Report a vulnerability** deste repositório) ou escreva para
victorhugormoura@gmail.com.

Inclua, se possível: versão afetada (`python3 netsnap.py --version` e
`servidor/VERSAO`), passos para reproduzir e o impacto observado. Não envie
snapshots, logs ou configurações reais de equipamentos: eles contêm dados de
infraestrutura. Se precisar de exemplo, use dados fictícios.

## Escopo

- `netsnap.py` e ferramentas complementares (`netdiag`, `netcve`, `netsnap_ia`,
  `netcontrol`, `netalerta`, painel `netsnap_web`).
- Servidor (`servidor/`): autenticação, cofre de credenciais, API e instalação.
- Vazamento de segredo nos snapshots apesar da sanitização ativa também é
  vulnerabilidade: relate o formato da linha que escapou, com valores fictícios.

## Versões atendidas

Somente a versão mais recente do ramo `main` recebe correções.
