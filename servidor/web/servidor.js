/* netsnap · servidor
   Login em etapas (senha, TOTP, troca de senha), cofre de credenciais,
   agendamentos persistentes, pacotes de análise, usuários e auditoria.
   Reaproveita as telas do painel local (app.js); todo dado vindo do servidor
   passa por esc() antes de ir para o HTML.

   Copyright (c) 2026 Victor Hugo R. Moura (VHRMO3) / Infinity Consulting
   Licenciado sob a licença MIT. */
"use strict";

const NIVEL = { leitura: 1, tecnico: 2, admin: 3 };
const NOME_PAPEL = { admin: "Administrador", tecnico: "Técnico", leitura: "Somente leitura" };
const DIAS = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"];

function pode(papel) {
  return !!(S.sessao && NIVEL[S.sessao.papel] >= NIVEL[papel]);
}

/* ------------------------------------------------------------ login */
// app.js chama semToken() quando a API responde 401.
function semToken() {
  mostrarLogin(S.sessao ? "Sua sessão expirou. Entre novamente." : "");
}

function cartao(html) {
  pararTimer();
  document.body.classList.add("sem-sessao");
  const m = tela(`<div class="entrada"><div class="entrada-cartao">
    <p class="marca"><span class="marca-fibras" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span>netsnap</span></p>
    ${html}</div></div>`);
  const primeiro = m.querySelector("input");
  if (primeiro) primeiro.focus();
  return m;
}

function mostrarLogin(msg) {
  S.sessao = null;
  S.csrf = "";
  cartao(`<h1>Entrar</h1>
    ${msg ? `<p class="alerta-campo">${esc(msg)}</p>` : ""}
    <form id="f-login" autocomplete="on">
      <div class="campo"><label for="l-usuario">Usuário</label>
        <input id="l-usuario" name="usuario" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required></div>
      <div class="campo"><label for="l-senha">Senha</label>
        <input id="l-senha" name="senha" type="password" autocomplete="current-password" required></div>
      <div class="acoes"><button class="principal" type="submit">Entrar</button></div>
    </form>
    <p class="suave pequeno espaco-acima">Acesso restrito à equipe técnica. Toda ação fica registrada na auditoria.
      ${S.caInterna ? `<br>Navegador avisando de certificado desconhecido? <a href="/ca.crt">Baixe a CA do servidor</a> e instale como autoridade confiável.` : ""}</p>`);
  $("#f-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    await enviarEtapa(e.target, "sessao", { usuario: fd.get("usuario").trim(), senha: fd.get("senha") });
  });
}

async function enviarEtapa(form, caminho, corpo) {
  const botao = form.querySelector("button[type=submit]");
  botao.disabled = true;
  try {
    proximaEtapa(await api("POST", caminho, corpo));
  } catch (err) {
    if (err.obsoleto) return;
    aviso(err.message, true);
    botao.disabled = false;
    // Desafio expirado ou tentativas esgotadas: volta ao começo.
    if (/expirada|esgotadas/.test(err.message)) mostrarLogin(err.message);
  }
}

function proximaEtapa(r) {
  if (r.aviso) aviso(r.aviso);
  if (r.codigos_recuperacao) {
    const codigos = r.codigos_recuperacao;
    delete r.codigos_recuperacao;
    return telaCodigos(codigos, () => proximaEtapa(r));
  }
  if (r.etapa === "ok") return entrou(r);
  if (r.etapa === "totp") return telaTotp(r);
  if (r.etapa === "cadastrar_totp") return telaCadastroTotp(r);
  if (r.etapa === "trocar_senha") return telaTrocarSenha(r);
  mostrarLogin("Resposta inesperada do servidor.");
}

function campoCodigo(rotulo, ajuda) {
  return `<div class="campo"><label for="l-codigo">${rotulo}</label>
    <input id="l-codigo" name="codigo" type="text" inputmode="numeric" autocomplete="one-time-code"
      maxlength="16" spellcheck="false" required class="codigo">
    ${ajuda ? `<small>${ajuda}</small>` : ""}</div>`;
}

function telaTotp(r) {
  cartao(`<h1>Verificação em duas etapas</h1>
    <form id="f-etapa" autocomplete="off">
      ${campoCodigo("Código do aplicativo autenticador", "Perdeu o celular? Digite um dos códigos de recuperação.")}
      <div class="acoes"><button class="principal" type="submit">Verificar</button>
        <button type="button" class="link" id="voltar">Voltar</button></div>
    </form>`);
  $("#voltar").addEventListener("click", () => mostrarLogin());
  $("#f-etapa").addEventListener("submit", (e) => {
    e.preventDefault();
    enviarEtapa(e.target, "sessao/etapa", { desafio: r.desafio, codigo: $("#l-codigo").value });
  });
}

function telaCadastroTotp(r) {
  const segredo = r.segredo.replace(/(.{4})/g, "$1 ").trim();
  const qr = r.qr_svg ? `<img class="qr" alt="QR code para o aplicativo autenticador"
      src="data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(r.qr_svg)))}">` : "";
  cartao(`<h1>Ative a verificação em duas etapas</h1>
    <p>Este servidor exige um segundo fator. No aplicativo autenticador (Google Authenticator, Microsoft
      Authenticator, Authy, FreeOTP ou o gerenciador de senhas), adicione uma conta lendo o código abaixo.</p>
    ${qr}
    <details ${qr ? "" : "open"}><summary>Não consegue ler? Digite a chave</summary>
      <p class="mono segredo">${esc(segredo)}</p>
      <p class="suave pequeno">Tipo: baseado em tempo, 6 dígitos, 30 segundos.</p></details>
    <form id="f-etapa" autocomplete="off">
      ${campoCodigo("Código mostrado pelo aplicativo", "")}
      <div class="acoes"><button class="principal" type="submit">Ativar</button></div>
    </form>`);
  $("#f-etapa").addEventListener("submit", (e) => {
    e.preventDefault();
    enviarEtapa(e.target, "sessao/etapa", { desafio: r.desafio, codigo: $("#l-codigo").value });
  });
}

function telaCodigos(codigos, continuar) {
  cartao(`<h1>Códigos de recuperação</h1>
    <p>Se perder o celular, cada código abaixo substitui o do aplicativo <strong>uma única vez</strong>.
      Guarde num lugar seguro, fora deste computador. Eles não serão mostrados de novo.</p>
    <ol class="codigos mono">${codigos.map((c) => `<li>${esc(c)}</li>`).join("")}</ol>
    <div class="acoes"><button type="button" id="copiar">Copiar</button>
      <button type="button" id="baixar-codigos">Baixar .txt</button></div>
    <label class="marcar espaco-acima"><input type="checkbox" id="guardei"> <span>Guardei os códigos</span></label>
    <div class="acoes"><button class="principal" type="button" id="continuar" disabled>Continuar</button></div>`);
  const texto = `netsnap — códigos de recuperação de ${S.usuarioLogin || ""}\n\n${codigos.join("\n")}\n`;
  $("#copiar").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(texto); aviso("Copiados"); } catch (e) { aviso("Copie manualmente", true); }
  });
  $("#baixar-codigos").addEventListener("click", () => baixarTexto("netsnap-codigos-recuperacao.txt", texto, "text/plain"));
  $("#guardei").addEventListener("change", (e) => { $("#continuar").disabled = !e.target.checked; });
  $("#continuar").addEventListener("click", continuar);
}

const AJUDA_SENHA = "Pelo menos 12 caracteres misturando três tipos (minúsculas, maiúsculas, números, símbolos), ou uma frase com 16 ou mais.";

function telaTrocarSenha(r) {
  cartao(`<h1>Defina sua senha</h1>
    <p>A senha atual é provisória. Escolha uma senha pessoal para continuar.</p>
    <form id="f-etapa" autocomplete="off">
      <div class="campo"><label for="n1">Nova senha</label>
        <input id="n1" type="password" autocomplete="new-password" required minlength="12" maxlength="256">
        <small>${AJUDA_SENHA}</small></div>
      <div class="campo"><label for="n2">Repita a nova senha</label>
        <input id="n2" type="password" autocomplete="new-password" required></div>
      <div class="acoes"><button class="principal" type="submit">Salvar e entrar</button></div>
    </form>`);
  $("#f-etapa").addEventListener("submit", (e) => {
    e.preventDefault();
    if ($("#n1").value !== $("#n2").value) return aviso("As senhas não conferem", true);
    enviarEtapa(e.target, "sessao/etapa", { desafio: r.desafio, nova_senha: $("#n1").value });
  });
}

function entrou(r) {
  S.csrf = r.csrf;
  iniciarServidor();
}

async function sair() {
  try { await api("DELETE", "sessao"); } catch (e) { /* sessão já encerrada */ }
  mostrarLogin("Você saiu.");
}

/* ------------------------------------------------------------ início */
async function iniciarServidor() {
  try {
    S.info = await api("GET", "info");
  } catch (e) {
    if (e.status === 401) return mostrarLogin();
    return tela(`<h1>Servidor inacessível</h1><p class="erro-campo">${esc(e.message)}</p>`);
  }
  S.sessao = S.info.usuario;
  S.csrf = S.sessao.csrf;
  S.caInterna = S.info.ca_interna;
  document.body.classList.remove("sem-sessao");
  $$("#menu li[data-papel]").forEach((li) => { li.hidden = !pode(li.dataset.papel); });
  $("#conta-link").textContent = `${S.sessao.usuario} · ${NOME_PAPEL[S.sessao.papel]}`;
  const c = S.info.capacidades;
  $("#rodape").innerHTML = `servidor ${esc(S.info.servidor)}${c.netsnap ? ` · netsnap ${esc(c.netsnap)}` : ""}<br>${c.coleta ? "coleta disponível" : "modo consulta"}<br><span class="credito">© 2026 Victor Hugo R. Moura · Infinity Consulting</span>`;
  if (!S.ouvindo) {
    window.addEventListener("hashchange", rotear);
    S.ouvindo = true;
  }
  rotear();
}

/* ------------------------------------------------------------ credenciais nos formulários */
async function carregarCredenciais() {
  S.credenciais = pode("tecnico") ? await api("GET", "cofre") : [];
}

// Substitui a versão do app.js: no servidor a credencial vem do cofre.
function camposCredencial(protocolo, porta) {
  const creds = S.credenciais || [];
  return `<div class="campo"><label for="credencial">Credencial</label>
      <select id="credencial" name="credencial">
        ${creds.map((c) => `<option value="${esc(c.id)}">${esc(c.nome)} — ${esc(c.usuario)} (${esc(c.redes.join(", "))})</option>`).join("")}
        <option value="">Digitar usuário e senha</option>
      </select>
      <small>Cifrada no servidor e usada só nas redes indicadas entre parênteses. <a href="#/cofre">Gerenciar o cofre</a></small></div>
    <div id="cred-manual" ${creds.length ? "hidden" : ""}>
      <div class="lado-a-lado">
        <div class="campo"><label for="usuario">Usuário</label>
          <input id="usuario" name="usuario" type="text" autocomplete="off" ${creds.length ? "" : "required"}></div>
        <div class="campo"><label for="senha">Senha</label>
          <input id="senha" name="senha" type="password" autocomplete="new-password" ${creds.length ? "" : "required"}></div>
      </div>
      <p class="suave pequeno">Usada só nesta execução. Para reutilizar e agendar, guarde no <a href="#/cofre">cofre</a>.</p>
    </div>
    <div class="campo"><label for="porta">Porta padrão</label>
      <input id="porta" name="porta" type="number" min="1" max="65535" value="${porta}">
      <small>Usada nas entradas sem <code>:porta</code>.</small></div>`;
}

document.addEventListener("change", (e) => {
  if (e.target.id !== "credencial") return;
  const manual = !e.target.value;
  const bloco = $("#cred-manual");
  if (!bloco) return;
  bloco.hidden = !manual;
  ["#usuario", "#senha"].forEach((s) => { const i = $(s); if (i) i.required = manual; });
});

function somenteTecnico(visao) {
  return async (...args) => {
    if (!pode("tecnico")) {
      return tela(`<h1>Ação não disponível</h1><p class="lead">Seu perfil é somente leitura.
        Peça a um administrador se precisar coletar ou diagnosticar.</p>`);
    }
    await carregarCredenciais();
    return visao(...args);
  };
}

/* ------------------------------------------------------------ cofre */
async function vCofre() {
  if (!pode("tecnico")) return tela(`<h1>Cofre de credenciais</h1><p class="lead">Disponível para técnicos e administradores.</p>`);
  const lista = await api("GET", "cofre");
  const editavel = (c) => pode("admin") || c.criado_por === S.sessao.usuario;
  const admin = pode("admin");
  tela(`<h1>Cofre de credenciais</h1>
    <p class="lead">Usuário e senha dos equipamentos, cifrados com AES-256-GCM e a chave-mestra do servidor. A senha não
      volta ao navegador, e cada credencial só é usada nas redes cadastradas: uma coleta ou agendamento com alvo fora
      delas é recusado. Assim ninguém aponta a credencial para um servidor próprio para capturar a senha.</p>
    ${lista.length ? `<div class="tabela-rolagem"><table><thead><tr><th>Nome</th><th>Usuário</th><th>Redes</th>
      <th>Criada por</th><th>Alterada</th><th>Último uso</th><th></th></tr></thead><tbody>
      ${lista.map((c) => `<tr><td><strong>${esc(c.nome)}</strong>${c.descricao ? `<br><span class="suave pequeno">${esc(c.descricao)}</span>` : ""}</td>
        <td class="mono">${esc(c.usuario)}</td>
        <td class="mono pequeno">${c.redes.map(esc).join("<br>")}${c.telnet ? `<br>${estado("telnet")}` : ""}</td>
        <td>${esc(c.criado_por)}</td><td class="data">${fmtData(c.atualizado)}</td>
        <td class="data">${fmtData(c.ultimo_uso)}</td>
        <td>${editavel(c) ? `<details class="acao-linha"><summary>Alterar</summary>
          <form class="f-cred" data-id="${esc(c.id)}" autocomplete="off">
            <div class="campo"><label>Novo usuário</label><input name="usuario" type="text" placeholder="manter ${esc(c.usuario)}"></div>
            <div class="campo"><label>Nova senha</label><input name="senha" type="password" autocomplete="new-password" placeholder="manter a atual"></div>
            <div class="campo"><label>Descrição</label><input name="descricao" type="text" maxlength="200" value="${esc(c.descricao)}"></div>
            ${admin ? `<div class="campo"><label>Redes (CIDR)</label><textarea name="redes" class="mini" spellcheck="false">${esc(c.redes.join("\n"))}</textarea></div>
            <label class="marcar"><input type="checkbox" name="telnet" ${c.telnet ? "checked" : ""}> <span>Permitir Telnet</span></label>` : ""}
            <div class="acoes"><button class="principal" type="submit">Salvar</button>
              <button class="perigo" type="button" data-remover="${esc(c.id)}" data-nome="${esc(c.nome)}">Remover</button></div>
          </form></details>` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhuma credencial guardada ainda.</p>`}
    <h2>Nova credencial</h2>
    <form class="grade" id="f-nova-cred" autocomplete="off">
      <div>
        <div class="campo"><label for="c-nome">Nome</label>
          <input id="c-nome" name="nome" type="text" required maxlength="64" placeholder="borda-sp, olts-zona-norte">
          <small>Como a credencial aparece nas coletas e agendamentos.</small></div>
        <div class="campo"><label for="c-desc">Descrição</label>
          <input id="c-desc" name="descricao" type="text" maxlength="200" placeholder="Usuário somente leitura dos MX"></div>
        <div class="campo"><label for="c-redes">Redes onde pode ser usada</label>
          <textarea id="c-redes" name="redes" class="mini" required spellcheck="false" placeholder="10.0.0.0/16&#10;172.16.10.0/24"></textarea>
          <small>CIDR, um por linha: as redes de gerência dos equipamentos desta credencial. Alvos fora delas são recusados.</small></div>
      </div>
      <div>
        <div class="campo"><label for="c-usuario">Usuário do equipamento</label>
          <input id="c-usuario" name="usuario" type="text" required autocomplete="off"></div>
        <div class="campo"><label for="c-senha">Senha do equipamento</label>
          <input id="c-senha" name="senha" type="password" required autocomplete="new-password">
          <small>Prefira um usuário com permissão só de leitura nos equipamentos.</small></div>
        ${admin ? `<label class="marcar"><input type="checkbox" name="telnet"> <span>Permitir uso por Telnet<small class="suave"> (senha em texto claro na rede)</small></span></label>` : ""}
        <div class="acoes"><button class="principal" type="submit">Guardar no cofre</button></div>
      </div>
    </form>`);
  const lerCred = (form) => {
    const fd = new FormData(form);
    const d = Object.fromEntries(fd.entries());
    if ("redes" in d) d.redes = d.redes.split(/[\s,;]+/).filter(Boolean);
    if (form.querySelector("[name=telnet]")) d.telnet = !!fd.get("telnet");
    return d;
  };
  // Rede ampla deixa a credencial chegar a mais hosts (inclusive pools de VPN
  // dos próprios técnicos dentro da faixa): confirma antes.
  const redesAmplas = (redes) => (redes || []).filter((r) => {
    const m = String(r).match(/\/(\d+)$/);
    return m && Number(m[1]) < (r.includes(":") ? 48 : 16);
  });
  const confirmaRedes = (d) => {
    const amplas = redesAmplas(d.redes);
    return !amplas.length || confirm(`Redes amplas: ${amplas.join(", ")}. A senha poderá ir para qualquer host ` +
      "dentro delas, inclusive pools de VPN. Prefira as redes de gerência dos equipamentos. Continuar?");
  };
  $("#f-nova-cred").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = lerCred(e.target);
    if (!confirmaRedes(d)) return;
    try {
      await api("POST", "cofre", d);
      aviso("Credencial guardada");
      vCofre();
    } catch (err) { aviso(err.message, true); }
  });
  $$(".f-cred").forEach((f) => f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = lerCred(f);
    if (!confirmaRedes(d)) return;
    try {
      await api("POST", `cofre/${f.dataset.id}`, d);
      aviso("Credencial alterada");
      vCofre();
    } catch (err) { aviso(err.message, true); }
  }));
  $$("[data-remover]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm(`Remover a credencial "${b.dataset.nome}"?`)) return;
    try {
      await api("DELETE", `cofre/${b.dataset.remover}`);
      aviso("Credencial removida");
      vCofre();
    } catch (err) { aviso(err.message, true); }
  }));
}

/* ------------------------------------------------------------ agendamentos */
function camposFrequencia(f) {
  f = f || { tipo: "diario", hora: "03:00" };
  const marcado = (d) => (f.dias_semana || [0, 1, 2, 3, 4]).includes(d) ? "checked" : "";
  return `<div class="campo"><label for="ag-tipo">Frequência</label>
      <select id="ag-tipo" name="tipo">
        <option value="diario" ${f.tipo === "diario" ? "selected" : ""}>Todo dia</option>
        <option value="semanal" ${f.tipo === "semanal" ? "selected" : ""}>Em dias da semana</option>
        <option value="dias" ${f.tipo === "dias" ? "selected" : ""}>A cada N dias (ex.: 7 = semanal)</option>
        <option value="horas" ${f.tipo === "horas" ? "selected" : ""}>A cada N horas</option>
      </select></div>
    <div class="lado-a-lado">
      <div class="campo" data-freq="diario semanal dias"><label for="ag-hora">Horário</label>
        <input id="ag-hora" name="hora" type="time" value="${esc(f.hora || "03:00")}"></div>
      <div class="campo" data-freq="dias horas"><label for="ag-n" id="ag-n-rotulo">A cada</label>
        <input id="ag-n" name="a_cada" type="number" min="1" max="720" value="${esc(f.a_cada || (f.tipo === "horas" ? 6 : 7))}"></div>
    </div>
    <div class="campo" data-freq="semanal"><span class="rotulo">Dias</span>
      <div class="dias">${DIAS.map((n, i) => `<label class="marcar"><input type="checkbox" name="dias_semana" value="${i}" ${marcado(i)}> ${n}</label>`).join("")}</div></div>
    <div class="campo" data-freq="dias"><label for="ag-inicio">A partir de</label>
      <input id="ag-inicio" name="inicio" type="date" value="${esc(f.inicio || new Date().toISOString().slice(0, 10))}"></div>`;
}

function atualizarFrequencia() {
  const tipo = $("#ag-tipo").value;
  $$("[data-freq]").forEach((el) => { el.hidden = !el.dataset.freq.split(" ").includes(tipo); });
  $("#ag-n-rotulo").textContent = tipo === "horas" ? "A cada quantas horas" : "A cada quantos dias";
}

function lerFrequencia(fd) {
  const tipo = fd.get("tipo");
  const f = { tipo };
  if (tipo !== "horas") f.hora = fd.get("hora");
  if (tipo === "horas" || tipo === "dias") f.a_cada = Number(fd.get("a_cada"));
  if (tipo === "semanal") f.dias_semana = fd.getAll("dias_semana").map(Number);
  if (tipo === "dias") f.inicio = fd.get("inicio");
  return f;
}

async function vAgendamentosServidor(editarId) {
  const [itens] = await Promise.all([api("GET", "agendamentos"), carregarCredenciais()]);
  const c = S.info.capacidades;
  const editando = editarId ? itens.find((a) => a.id === editarId) : null;
  const a = editando || { modo: "8", protocolo: "ssh", varredura: "fast", instancias: 5, analise: true, porta: 22 };
  const creds = S.credenciais;
  const podeEditar = pode("tecnico") && c.coleta;
  tela(`<h1>Agendamentos</h1>
    <p class="lead">Coletas recorrentes feitas pelo próprio servidor, sem ninguém conectado. A senha vem do cofre.
      Ao terminar, cada execução pode gerar um pacote de análise para o NETANALYTIC.</p>
    ${itens.length ? `<div class="tabela-rolagem"><table><thead><tr><th>Nome</th><th>Frequência</th><th>Próxima</th>
      <th>Última</th><th>Situação</th><th></th></tr></thead><tbody>
      ${itens.map((x) => `<tr><td><strong>${esc(x.nome)}</strong><br><span class="suave pequeno">
          ${esc(x.alvos.split("\n").filter((l) => l.trim()).length)} entrada(s) · ${esc(x.credencial_nome || "sem credencial")} · ${esc(x.protocolo)}${x.analise ? " · com análise" : ""}</span></td>
        <td>${esc(x.frequencia_texto)}</td><td class="data">${x.ativo ? fmtData(x.proxima) : "—"}</td>
        <td>${x.ultima ? `${fmtData(x.ultima)} ${x.ultimo_job ? `<a href="#/execucoes/${esc(x.ultimo_job)}">${esc(x.ultimo_estado || "")}</a>` : esc(x.ultimo_estado || "")}` : "—"}</td>
        <td>${estado(x.situacao)}</td>
        <td>${podeEditar ? `<div class="acoes">
          <button type="button" data-ag="executar" data-id="${esc(x.id)}">Executar agora</button>
          <button type="button" data-ag="${x.ativo ? "pausar" : "ativar"}" data-id="${esc(x.id)}">${x.ativo ? "Pausar" : "Retomar"}</button>
          <a class="botao" href="#/agendamentos/${esc(x.id)}">Editar</a>
          <button type="button" class="perigo" data-ag="remover" data-id="${esc(x.id)}" data-nome="${esc(x.nome)}">Remover</button></div>` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhum agendamento.</p>`}
    ${!podeEditar ? "" : !creds.length ? `<h2>Novo agendamento</h2>
      <p class="vazio">Agendamentos usam uma credencial do cofre. <a href="#/cofre">Guarde a primeira credencial</a>.</p>` : `
    <h2>${editando ? `Editar “${esc(editando.nome)}”` : "Novo agendamento"}</h2>
    <form class="grade" id="f-ag" autocomplete="off">
      <div>
        <div class="campo"><label for="ag-nome">Nome</label>
          <input id="ag-nome" name="nome" type="text" required maxlength="80" value="${esc(a.nome || "")}" placeholder="Backup diário da borda"></div>
        <div class="campo"><label for="ag-alvos">Alvos</label>
          <textarea id="ag-alvos" name="alvos" required spellcheck="false" class="curto"
            placeholder="10.0.0.1&#10;10.10.0.0/28&#10;olt-centro.isp.net">${esc(a.alvos || "")}</textarea></div>
        <div class="campo"><label for="ag-modo">O que extrair</label><select id="ag-modo" name="modo">
          ${c.modos.map((m) => `<option value="${esc(m.chave)}" ${m.chave === a.modo ? "selected" : ""}>${esc(m.nome)}</option>`).join("")}</select>
          <small>“Extração total” traz configuração, logs, estado, interfaces, vizinhança e inventário.</small></div>
      </div>
      <div>
        ${camposFrequencia(a.frequencia)}
        <div class="campo"><label for="ag-cred">Credencial</label>
          <select id="ag-cred" name="credencial">${creds.map((k) => `<option value="${esc(k.id)}" ${k.id === a.credencial ? "selected" : ""}>${esc(k.nome)} — ${esc(k.usuario)}</option>`).join("")}</select></div>
        <div class="lado-a-lado">
          <div class="campo"><span class="rotulo">Protocolo</span>
            <label class="marcar"><input type="radio" name="protocolo" value="ssh" ${a.protocolo !== "telnet" ? "checked" : ""}> SSH</label>
            ${S.info.permitir_telnet ? `<label class="marcar"><input type="radio" name="protocolo" value="telnet" ${a.protocolo === "telnet" ? "checked" : ""}> Telnet</label>` : ""}</div>
          <div class="campo"><label for="ag-porta">Porta padrão</label>
            <input id="ag-porta" name="porta" type="number" min="1" max="65535" value="${esc(a.porta || 22)}"></div>
        </div>
        <div class="lado-a-lado">
          <div class="campo"><label for="ag-var">Antes de conectar</label><select id="ag-var" name="varredura">
            <option value="fast" ${a.varredura !== "deep" ? "selected" : ""}>Pingar e pular quem não responde</option>
            <option value="deep" ${a.varredura === "deep" ? "selected" : ""}>Tentar todos</option></select></div>
          <div class="campo"><label for="ag-inst">Simultâneos</label>
            <input id="ag-inst" name="instancias" type="number" min="1" max="10" value="${esc(a.instancias || 5)}"></div>
        </div>
        <label class="marcar"><input type="checkbox" name="analise" ${a.analise ? "checked" : ""}>
          <span>Gerar pacote de análise ao terminar<small class="suave"> (resumo, mudanças desde a coleta anterior e instruções para a IA)</small></span></label>
        <div class="acoes"><button class="principal" type="submit">${editando ? "Salvar alterações" : "Criar agendamento"}</button>
          ${editando ? `<a class="botao" href="#/agendamentos">Cancelar</a>` : ""}</div>
      </div>
    </form>`}`);

  const tabela = $("table");
  if (tabela) tabela.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-ag]");
    if (!b) return;
    const id = b.dataset.id, acao = b.dataset.ag;
    try {
      if (acao === "remover") {
        if (!confirm(`Remover o agendamento "${b.dataset.nome}"?`)) return;
        await api("DELETE", `agendamentos/${id}`);
      } else if (acao === "executar") {
        const job = await api("POST", `agendamentos/${id}/executar`, {});
        location.hash = "#/execucoes/" + job.id;
        return;
      } else {
        await api("POST", `agendamentos/${id}/${acao}`, {});
      }
      vAgendamentosServidor();
    } catch (err) { aviso(err.message, true); }
  });

  const f = $("#f-ag");
  if (!f) return;
  $("#ag-tipo").addEventListener("change", atualizarFrequencia);
  atualizarFrequencia();
  f.addEventListener("change", (e) => {
    if (e.target.name === "protocolo") {
      const porta = $("#ag-porta");
      if (porta.value === "22" || porta.value === "23") porta.value = e.target.value === "telnet" ? "23" : "22";
    }
  });
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(f);
    const dados = {
      nome: fd.get("nome"), alvos: fd.get("alvos"), modo: fd.get("modo"), protocolo: fd.get("protocolo"),
      porta: Number(fd.get("porta")), varredura: fd.get("varredura"), instancias: Number(fd.get("instancias")),
      credencial: Number(fd.get("credencial")), analise: !!fd.get("analise"), frequencia: lerFrequencia(fd),
    };
    try {
      if (editando) await api("POST", `agendamentos/${editando.id}`, dados);
      else await api("POST", "agendamentos", dados);
      aviso(editando ? "Agendamento alterado" : "Agendamento criado");
      if (editando) location.hash = "#/agendamentos"; else vAgendamentosServidor();
    } catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ pacotes de análise */
async function vAnalises() {
  const lista = await api("GET", "analises");
  tela(`<h1>Pacotes de análise</h1>
    <p class="lead">Gerados ao fim das coletas agendadas. Cada pacote traz os snapshots da execução, um resumo por
      equipamento (versões, apontamentos de configuração, logs por gravidade, contadores de erro, mudanças desde a
      coleta anterior) e o <code>PROMPT.md</code> com as instruções para a IA do NETANALYTIC. Nenhuma correção é aplicada
      automaticamente.</p>
    ${lista.length ? `<div class="tabela-rolagem"><table><thead><tr><th>Gerado</th><th>Agendamento</th>
      <th class="num">Coletados</th><th class="num">Falhas</th><th class="num">Apontamentos</th>
      <th class="num">Com mudança</th><th></th></tr></thead><tbody>
      ${lista.map((p) => `<tr><td class="data">${fmtData(p.criado, true)}</td><td>${esc(p.resumo.agendamento || "")}
          <br><a class="pequeno" href="#/execucoes/${esc(p.job_id)}">execução ${esc(p.job_id)}</a></td>
        <td class="num">${esc(p.resumo.ok)} de ${esc(p.resumo.alvos)}</td><td class="num">${esc(p.resumo.falha + p.resumo.incompleto)}</td>
        <td class="num">${esc(p.resumo.apontamentos)}</td><td class="num">${esc(p.resumo.com_mudanca)}</td>
        <td><div class="acoes"><button type="button" data-pacote="${esc(p.id)}" data-arquivo="${esc(p.arquivo)}">Baixar .zip</button>
          ${pode("admin") ? `<button type="button" class="perigo" data-apagar="${esc(p.id)}">Remover</button>` : ""}</div></td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhum pacote ainda. Crie um <a href="#/agendamentos">agendamento</a>
        com “Gerar pacote de análise” marcado.</p>`}`);
  $$("[data-pacote]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const r = await fetch(`/api/analises/${encodeURIComponent(b.dataset.pacote)}/baixar`);
      if (!r.ok) throw new Error((await r.json()).erro);
      baixarBlob(b.dataset.arquivo, await r.blob());
    } catch (err) { aviso(err.message, true); }
  }));
  $$("[data-apagar]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Remover este pacote de análise?")) return;
    try { await api("DELETE", `analises/${b.dataset.apagar}`); vAnalises(); } catch (err) { aviso(err.message, true); }
  }));
}

/* ------------------------------------------------------------ usuários */
function senhaAleatoria() {
  const alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_.!";
  const v = new Uint32Array(20);
  crypto.getRandomValues(v);
  return Array.from(v, (n) => alfabeto[n % alfabeto.length]).join("");
}

function situacaoUsuario(u) {
  if (!u.ativo) return "desativado";
  if (u.bloqueado_ate && new Date(u.bloqueado_ate) > new Date()) return "bloqueado";
  if (u.trocar_senha) return "aguardando 1º acesso";
  return "ativo";
}

async function vUsuarios() {
  if (!pode("admin")) return tela(`<h1>Usuários</h1><p class="lead">Somente administradores.</p>`);
  const lista = await api("GET", "usuarios");
  const opcoesPapel = (atual) => Object.keys(NOME_PAPEL).map((p) =>
    `<option value="${p}" ${p === atual ? "selected" : ""}>${NOME_PAPEL[p]}</option>`).join("");
  tela(`<h1>Usuários</h1>
    <p class="lead">Administrador gerencia usuários e auditoria; técnico coleta, agenda e usa o cofre; somente leitura
      consulta snapshots, inventário e relatórios. Todo usuário entra com senha e código do aplicativo autenticador.</p>
    <div class="tabela-rolagem"><table><thead><tr><th>Usuário</th><th>Perfil</th><th>2 etapas</th><th>Situação</th>
      <th>Último acesso</th><th></th></tr></thead><tbody>
      ${lista.map((u) => `<tr><td><strong>${esc(u.nome)}</strong>${u.nome_completo ? `<br><span class="suave pequeno">${esc(u.nome_completo)}</span>` : ""}</td>
        <td>${esc(NOME_PAPEL[u.papel])}</td><td>${u.totp_ativo ? "ativa" : "pendente"}</td>
        <td>${estado(situacaoUsuario(u))}</td><td class="data">${fmtData(u.ultimo_login)}</td>
        <td>${u.nome === S.sessao.usuario ? `<a href="#/conta">Minha conta</a>` : `<details class="acao-linha"><summary>Gerenciar</summary>
          <div class="painel-acoes" data-uid="${esc(u.id)}" data-nome="${esc(u.nome)}">
            <div class="campo"><label>Perfil</label><select data-papel>${opcoesPapel(u.papel)}</select></div>
            <div class="acoes">
              <button type="button" data-acao="papel">Salvar perfil</button>
              <button type="button" data-acao="${u.ativo ? "desativar" : "ativar"}">${u.ativo ? "Desativar" : "Reativar"}</button>
              ${situacaoUsuario(u) === "bloqueado" ? `<button type="button" data-acao="desbloquear">Desbloquear</button>` : ""}
              <button type="button" data-acao="totp">Refazer 2 etapas</button>
            </div>
            <div class="campo espaco-acima"><label>Senha provisória</label>
              <div class="linha-campo"><input type="text" data-nova-senha autocomplete="off" spellcheck="false">
                <button type="button" data-acao="gerar">Gerar</button></div>
              <small>O usuário troca no próximo acesso. Passe por um canal seguro.</small></div>
            <div class="acoes"><button type="button" data-acao="senha">Redefinir senha</button>
              <button type="button" class="perigo" data-acao="remover">Remover usuário</button></div>
          </div></details>`}</td></tr>`).join("")}
      </tbody></table></div>
    <h2>Novo usuário</h2>
    <form class="grade" id="f-usuario" autocomplete="off">
      <div>
        <div class="campo"><label for="u-nome">Usuário</label>
          <input id="u-nome" name="usuario" type="text" required pattern="[a-z0-9][a-z0-9._\\-]{1,31}" autocapitalize="none" spellcheck="false">
          <small>Minúsculas, números, ponto, hífen ou sublinhado.</small></div>
        <div class="campo"><label for="u-completo">Nome completo</label><input id="u-completo" name="nome" type="text" maxlength="80"></div>
      </div>
      <div>
        <div class="campo"><label for="u-papel">Perfil</label><select id="u-papel" name="papel">${opcoesPapel("tecnico")}</select></div>
        <div class="campo"><label for="u-senha">Senha provisória</label>
          <div class="linha-campo"><input id="u-senha" name="senha" type="text" required autocomplete="off" spellcheck="false">
            <button type="button" id="u-gerar">Gerar</button></div>
          <small>No primeiro acesso o usuário ativa o autenticador e define a própria senha.</small></div>
        <div class="acoes"><button class="principal" type="submit">Criar usuário</button></div>
      </div>
    </form>`);
  $("#u-gerar").addEventListener("click", () => { $("#u-senha").value = senhaAleatoria(); });
  $("#f-usuario").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("POST", "usuarios", d);
      aviso(`Usuário ${d.usuario} criado`);
      vUsuarios();
    } catch (err) { aviso(err.message, true); }
  });
  $$(".painel-acoes").forEach((p) => p.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-acao]");
    if (!b) return;
    const uid = p.dataset.uid, nome = p.dataset.nome, acao = b.dataset.acao;
    try {
      if (acao === "gerar") { p.querySelector("[data-nova-senha]").value = senhaAleatoria(); return; }
      if (acao === "papel") await api("POST", `usuarios/${uid}/alterar`, { papel: p.querySelector("[data-papel]").value });
      else if (acao === "desativar" || acao === "ativar") await api("POST", `usuarios/${uid}/alterar`, { ativo: acao === "ativar" });
      else if (acao === "desbloquear") await api("POST", `usuarios/${uid}/desbloquear`, {});
      else if (acao === "totp") {
        if (!confirm(`${nome} terá de cadastrar o autenticador de novo no próximo acesso. Continuar?`)) return;
        await api("POST", `usuarios/${uid}/totp`, {});
      } else if (acao === "senha") {
        const senha = p.querySelector("[data-nova-senha]").value;
        if (!senha) return aviso("Informe ou gere a senha provisória", true);
        await api("POST", `usuarios/${uid}/senha`, { senha });
      } else if (acao === "remover") {
        if (!confirm(`Remover o usuário ${nome}? A auditoria dele é mantida.`)) return;
        await api("DELETE", `usuarios/${uid}`);
      }
      aviso("Feito");
      vUsuarios();
    } catch (err) { aviso(err.message, true); }
  }));
}

/* ------------------------------------------------------------ auditoria */
async function vAuditoria() {
  if (!pode("admin")) return tela(`<h1>Auditoria</h1><p class="lead">Somente administradores.</p>`);
  const filtro = S.filtroAuditoria || { usuario: "", acao: "" };
  const qs = new URLSearchParams({ limite: "1000", usuario: filtro.usuario, acao: filtro.acao });
  const lista = await api("GET", "auditoria?" + qs);
  tela(`<div class="cabecalho-linha"><div><h1>Auditoria</h1>
      <p class="lead">Logins, alterações de usuários e do cofre, coletas, agendamentos e downloads. Cada registro é encadeado
        ao anterior por HMAC: apagar ou editar uma linha direto no banco é detectado pela verificação.</p></div>
      <button type="button" id="verificar">Verificar integridade</button></div>
    <form class="filtros" id="f-filtro">
      <div class="campo"><label for="fa-usuario">Usuário</label><input id="fa-usuario" name="usuario" type="text" value="${esc(filtro.usuario)}"></div>
      <div class="campo"><label for="fa-acao">Ação começando por</label><input id="fa-acao" name="acao" type="text" value="${esc(filtro.acao)}" placeholder="login, credencial, agendamento"></div>
      <div class="acoes"><button type="submit">Filtrar</button></div>
    </form>
    ${lista.length ? `<div class="tabela-rolagem"><table><thead><tr><th>Quando</th><th>Usuário</th><th>IP</th><th>Ação</th>
      <th>Alvo</th><th>Detalhe</th></tr></thead><tbody>
      ${lista.map((r) => `<tr><td class="data">${fmtData(r.quando, true)}</td><td>${esc(r.usuario || "—")}</td>
        <td class="mono">${esc(r.ip || "")}</td><td>${esc(r.acao)}</td><td>${esc(r.alvo)}</td><td class="pequeno">${esc(r.detalhe)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nada encontrado.</p>`}`);
  $("#f-filtro").addEventListener("submit", (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    S.filtroAuditoria = { usuario: fd.get("usuario").trim(), acao: fd.get("acao").trim() };
    vAuditoria();
  });
  $("#verificar").addEventListener("click", async () => {
    try {
      const r = await api("GET", "auditoria?verificar=1");
      if (r.integra) aviso("Trilha íntegra: nenhum registro alterado ou removido");
      else aviso(r.primeiro_invalido ? `Trilha alterada a partir do registro ${r.primeiro_invalido}`
        : "Registros finais da trilha foram removidos", true);
    } catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ minha conta */
async function vConta() {
  const c = await api("GET", "conta");
  tela(`<h1>Minha conta</h1>
    <div class="faixa">
      <div><strong>${esc(c.usuario)}</strong><span>${esc(NOME_PAPEL[c.papel])}</span></div>
      <div><strong>${esc(c.codigos_restantes)}</strong><span>códigos de recuperação restantes</span></div>
      <div><strong>${esc(c.sessoes)}</strong><span>sessão(ões) aberta(s)</span></div>
    </div>
    <p class="suave pequeno">Último acesso: ${fmtData(c.ultimo_login, true)} · Senha alterada: ${fmtData(c.senha_alterada, true)}</p>
    <div class="colunas">
      <section><h2>Trocar senha</h2>
        <form id="f-senha" autocomplete="off">
          <div class="campo"><label for="s-atual">Senha atual</label><input id="s-atual" type="password" autocomplete="current-password" required></div>
          <div class="campo"><label for="s-n1">Nova senha</label><input id="s-n1" type="password" autocomplete="new-password" required minlength="12">
            <small>${AJUDA_SENHA}</small></div>
          <div class="campo"><label for="s-n2">Repita a nova senha</label><input id="s-n2" type="password" autocomplete="new-password" required></div>
          <div class="acoes"><button class="principal" type="submit">Trocar senha</button></div>
          <p class="suave pequeno">As outras sessões abertas com a sua conta são encerradas.</p>
        </form></section>
      <section><h2>Códigos de recuperação</h2>
        <p class="pequeno">Gerar novos invalida os anteriores.</p>
        <form id="f-codigos" autocomplete="off">
          <div class="campo"><label for="r-senha">Senha</label><input id="r-senha" type="password" autocomplete="current-password" required></div>
          <div class="campo"><label for="r-codigo">Código do aplicativo</label><input id="r-codigo" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required class="codigo"></div>
          <div class="acoes"><button type="submit">Gerar novos códigos</button></div>
        </form>
        <h2>Sessões</h2>
        <div class="acoes"><button type="button" id="sair-todas">Encerrar as outras sessões</button></div>
      </section>
    </div>`);
  $("#f-senha").addEventListener("submit", async (e) => {
    e.preventDefault();
    if ($("#s-n1").value !== $("#s-n2").value) return aviso("As senhas não conferem", true);
    try {
      await api("POST", "conta/senha", { atual: $("#s-atual").value, nova: $("#s-n1").value });
      aviso("Senha trocada");
      vConta();
    } catch (err) { aviso(err.message, true); }
  });
  $("#f-codigos").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await api("POST", "conta/codigos", { senha: $("#r-senha").value, codigo: $("#r-codigo").value });
      S.usuarioLogin = S.sessao.usuario;
      telaCodigos(r.codigos_recuperacao, () => { document.body.classList.remove("sem-sessao"); vConta(); });
    } catch (err) { aviso(err.message, true); }
  });
  $("#sair-todas").addEventListener("click", async () => {
    try { await api("POST", "conta/sair-de-todas", {}); aviso("Outras sessões encerradas"); vConta(); }
    catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ rotas e partida */
ROTAS.agendamentos = vAgendamentosServidor;
ROTAS.coletar = somenteTecnico(vColetar);
ROTAS.diagnostico = somenteTecnico(vDiagnostico);
ROTAS.cofre = vCofre;
ROTAS.analises = vAnalises;
ROTAS.usuarios = vUsuarios;
ROTAS.auditoria = vAuditoria;
ROTAS.conta = vConta;

$("#sair").addEventListener("click", sair);
document.addEventListener("submit", (e) => {
  // Guarda o nome digitado para a tela de códigos de recuperação.
  if (e.target.id === "f-login") S.usuarioLogin = e.target.usuario.value.trim();
}, true);

(async () => {
  try {
    const s = await api("GET", "sessao");
    S.caInterna = !!s.ca_interna;
    if (!s.autenticado) return mostrarLogin();
    S.csrf = s.csrf;
    iniciarServidor();
  } catch (e) {
    tela(`<h1>Servidor inacessível</h1><p class="erro-campo">${esc(e.message)}</p>`);
  }
})();
