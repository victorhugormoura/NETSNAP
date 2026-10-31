# Contexto geral — análise de snapshot netsnap

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com

Este é o contexto-base que acompanha qualquer equipamento. Uma pasta privada
de contextos (`--contextos` ou `NETSNAP_CONTEXTOS`) pode substituir este
arquivo e os das plataformas por versões completas (as skills).

## Como ler o snapshot

- Cada `##` é uma seção (Configuração, Logs, Estado, Interfaces e ópticas,
  Vizinhança, Inventário); cada `###` é o comando exatamente como executado.
- `***REMOVIDO***` é segredo mascarado na coleta. Não aponte "senha vazia"
  nem "community ausente" por causa da máscara.
- `(sem saída útil: ...)` é comando não suportado no firmware ou sem retorno;
  não significa que o recurso esteja desligado.
- `session_lost: true` no resumo: a coleta foi interrompida (sessão encerrada ou tempo esgotado; `abort_reason` diz qual); o que falta
  pode ser só falta de dado.
- Contadores de erro são cumulativos desde o boot ou o último clear. Uma
  coleta não dá taxa; compare com o uptime e, havendo, com a coleta anterior.

## Etiquetas de confiança

Use nas recomendações quando houver dúvida de sintaxe ou de comportamento:

- `[verificado]`: documentação oficial, RFC ou saída real.
- `[validar em lab]`: sintaxe ou efeito não confirmados para esta versão.

## O que nunca fazer

- Propor comando sem dizer o impacto (reseta sessão, flapa porta, reinicia
  processo, derruba assinante, exige janela).
- Propor mudança remota que pode cortar a gerência sem o mecanismo de volta
  da plataforma (Junos `commit confirmed`, RouterOS Safe Mode, IOS-XR
  `commit confirmed`, Huawei `commit` em modo two-stage quando disponível).
- Tratar CVE por versão como confirmada: a versão é indício; o boletim do
  fabricante e a configuração decidem.
