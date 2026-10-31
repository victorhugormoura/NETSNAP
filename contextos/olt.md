# OLTs (Huawei SmartAX MA5600/MA5800, FiberHome AN551x/AN6000) — checklist

Infinity Consulting - Victor Hugo R. Moura - victorhugormoura@gmail.com
Contexto-base sem skill dedicada. OLT em produção atende assinantes: toda
proposta de mudança é de janela e leva `[validar em lab]` quando a sintaxe
não estiver confirmada para a placa e o release.

## Regras

- Não proponha comandos que reiniciem placa, porta PON ou ONT fora de
  janela. Diga o número estimado de assinantes afetados quando o snapshot
  permitir (ONTs por porta).
- Telnet é comum nessas OLTs: aponte como risco (credencial em texto claro)
  e recomende SSH quando o firmware suporta, com ACL de gerência.

## O que procurar

- Placas em falha ou não reconhecidas, alarmes ativos de energia, fan ou
  temperatura.
- Portas PON com muitas ONTs offline, ONTs com Rx fora da faixa (sinal
  fraco: tipicamente abaixo de -27 dBm; confirmar o limiar do modelo),
  ONTs desconhecidas/autofind acumuladas.
- Uplinks sem LACP/redundância, CPU alta persistente.
- Versão de firmware muito antiga para o modelo (conferir no boletim).
