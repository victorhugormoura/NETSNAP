/* netsnap · tema do painel
   Carregado no <head>, antes do primeiro desenho da página, para que o
   tema claro escolhido não apareça depois de um quadro escuro. O padrão é
   o escuro; a escolha fica neste navegador.

   Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
   Licenciado sob a licença MIT. */
(function () {
  var tema = "escuro";
  try {
    if (localStorage.getItem("netsnap.tema") === "claro") tema = "claro";
  } catch (e) { /* sem armazenamento: fica o padrão */ }
  document.documentElement.setAttribute("data-tema", tema);
})();
