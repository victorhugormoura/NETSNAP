/* netsnap · painel local
   Sem dependências externas: funciona em rede de gerência isolada.
   Todo dado vindo do servidor passa por esc() antes de ir para o HTML. */
"use strict";

const S = {
  token: "",
  geracao: 0,
  info: null,
  timer: null,
  snapshots: null,
  prefill: null,
  inventarioOrdem: { campo: "host", asc: true },
};

/* ------------------------------------------------------------ utilidades */
const $ = (sel, raiz = document) => raiz.querySelector(sel);
const $$ = (sel, raiz = document) => Array.from(raiz.querySelectorAll(sel));

function esc(v) {
  return String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmtData(iso, comAno) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return esc(iso);
  const p = (n) => String(n).padStart(2, "0");
  const data = `${p(d.getDate())}/${p(d.getMonth() + 1)}` + (comAno ? `/${d.getFullYear()}` : "");
  return `${data} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtTamanho(b) {
  if (b > 1048576) return (b / 1048576).toFixed(1) + " MB";
  if (b > 1024) return Math.round(b / 1024) + " KB";
  return b + " B";
}

function fibra(chave, nome) {
  return `<span class="fibra" data-p="${esc(chave || "")}">${esc(nome || chave || "—")}</span>`;
}

function estado(texto) {
  const cls = String(texto || "").toLowerCase().normalize("NFD")
    .replace(/[̀-ͯ]/g, "").replace(/\s+/g, "-");
  return `<span class="estado ${esc(cls)}">${esc(texto)}</span>`;
}

function aviso(msg, erro) {
  if (msg === "obsoleto") return;
  const a = $("#aviso");
  a.textContent = msg;
  a.className = "visivel" + (erro ? " erro" : "");
  clearTimeout(aviso.t);
  aviso.t = setTimeout(() => { a.className = ""; }, erro ? 6000 : 3200);
}

// localStorage: o token vale para todas as abas do painel nesta execução
// (cada execução usa uma porta e um token próprios). Sem armazenamento
// disponível, o painel funciona na aba aberta pelo endereço do terminal.
function guardar(chave, valor) {
  try { localStorage.setItem("netsnap." + chave, valor); } catch (e) { /* sem armazenamento */ }
}
function ler(chave) {
  try { return localStorage.getItem("netsnap." + chave) || ""; } catch (e) { return ""; }
}

async function api(metodo, caminho, corpo) {
  // Resposta que chega depois de uma troca de tela é descartada: senão a
  // tela anterior, mais lenta, sobrescreveria a atual.
  const geracao = S.geracao;
  const opcoes = { method: metodo, headers: { "X-Netsnap-Token": S.token } };
  if (corpo !== undefined) {
    opcoes.headers["Content-Type"] = "application/json";
    opcoes.body = JSON.stringify(corpo);
  }
  const r = await fetch("/api/" + caminho, opcoes);
  const tipo = r.headers.get("Content-Type") || "";
  const dados = tipo.includes("json") ? await r.json() : await r.text();
  if (geracao !== S.geracao) {
    const obsoleto = new Error("obsoleto");
    obsoleto.obsoleto = true;
    throw obsoleto;
  }
  if (!r.ok) {
    const msg = (dados && dados.erro) || `Erro ${r.status}`;
    const e = new Error(msg);
    e.status = r.status;
    throw e;
  }
  return dados;
}

async function baixar(tipo, nome) {
  try {
    const r = await fetch(`/api/arquivo/${tipo}/${encodeURIComponent(nome)}?baixar=1`,
      { headers: { "X-Netsnap-Token": S.token } });
    if (!r.ok) throw new Error((await r.json()).erro);
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url; a.download = nome; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (e) { aviso(e.message, true); }
}

function baixarTexto(nome, texto, tipo) {
  const url = URL.createObjectURL(new Blob([texto], { type: tipo }));
  const a = document.createElement("a");
  a.href = url; a.download = nome; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}

function tela(html) {
  const m = $("#conteudo");
  m.innerHTML = html;
  return m;
}

function pararTimer() {
  if (S.timer) { clearTimeout(S.timer); S.timer = null; }
}

/* ------------------------------------------------------------ markdown (relatórios do netsnap) */
function inline(t) {
  return esc(t)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|\s)_(\(?[^_]+?\)?)_(?=\s|$|[.,;:])/g, "$1<em>$2</em>")
    .replace(/&lt;(https?:\/\/[^&\s]+)&gt;/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
}

function markdown(texto) {
  const linhas = texto.replace(/\r/g, "").split("\n");
  let i = 0;
  if (linhas[0] === "---") {
    i = 1;
    while (i < linhas.length && linhas[i] !== "---") i++;
    i++;
  }
  const out = [];
  let par = [];
  const fecharPar = () => { if (par.length) { out.push(`<p>${inline(par.join(" "))}</p>`); par = []; } };
  for (; i < linhas.length; i++) {
    const l = linhas[i];
    if (l.startsWith("```")) {
      fecharPar();
      const buf = [];
      for (i++; i < linhas.length && linhas[i] !== "```"; i++) buf.push(linhas[i]);
      out.push(`<pre><code>${esc(buf.join("\n"))}</code></pre>`);
      continue;
    }
    const h = l.match(/^(#{1,4})\s+(.*)$/);
    if (h) { fecharPar(); const n = h[1].length; out.push(`<h${n}>${inline(h[2])}</h${n}>`); continue; }
    if (/^\s*\|/.test(l)) {
      fecharPar();
      const rows = [];
      for (; i < linhas.length && /^\s*\|/.test(linhas[i]); i++) rows.push(linhas[i]);
      i--;
      const cel = (r) => r.trim().replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
      const corpo = rows.filter((r) => !/^\s*\|[\s|:-]+\|\s*$/.test(r));
      if (!corpo.length) continue;
      const [cab, ...resto] = corpo;
      out.push('<div class="tabela-rolagem"><table><thead><tr>' +
        cel(cab).map((c) => `<th>${inline(c)}</th>`).join("") + "</tr></thead><tbody>" +
        resto.map((r) => "<tr>" + cel(r).map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>").join("") +
        "</tbody></table></div>");
      continue;
    }
    if (l.startsWith(">")) {
      fecharPar();
      const buf = [];
      for (; i < linhas.length && linhas[i].startsWith(">"); i++) buf.push(linhas[i].replace(/^>\s?/, ""));
      i--;
      out.push(`<blockquote>${markdown(buf.join("\n"))}</blockquote>`);
      continue;
    }
    if (/^\s*[-*]\s+/.test(l)) {
      fecharPar();
      const buf = [];
      for (; i < linhas.length && /^\s*[-*]\s+/.test(linhas[i]); i++) buf.push(linhas[i].replace(/^\s*[-*]\s+/, ""));
      i--;
      out.push("<ul>" + buf.map((b) => `<li>${inline(b)}</li>`).join("") + "</ul>");
      continue;
    }
    if (/^---+\s*$/.test(l)) { fecharPar(); out.push("<hr>"); continue; }
    if (!l.trim()) { fecharPar(); continue; }
    par.push(l);
  }
  fecharPar();
  return out.join("\n");
}

/* ------------------------------------------------------------ roteamento */
const ROTAS = {
  painel: vPainel,
  coletar: vColetar,
  execucoes: vExecucoes,
  snapshots: vSnapshots,
  inventario: vInventario,
  comparar: vComparar,
  topologia: vTopologia,
  vulnerabilidades: vVulnerabilidades,
  diagnostico: vDiagnostico,
  agendamentos: vAgendamentos,
  relatorio: vRelatorio,
};

async function rotear() {
  pararTimer();
  S.geracao++;
  let partes;
  try {
    partes = (location.hash.replace(/^#\/?/, "") || "painel").split("/").map(decodeURIComponent);
  } catch (e) {
    partes = ["painel"];
  }
  const nome = ROTAS[partes[0]] ? partes[0] : "painel";
  $$("#menu a").forEach((a) => a.classList.toggle("ativo", a.dataset.rota === nome ||
    (nome === "relatorio" && a.dataset.rota === partes[1])));
  try {
    await ROTAS[nome](...partes.slice(1));
  } catch (e) {
    if (e.obsoleto) return;
    if (e.status === 401) { guardar("token", ""); return semToken(); }
    tela(`<h1>Não foi possível carregar</h1><p class="erro-campo">${esc(e.message)}</p>`);
  }
  $("#conteudo").focus({ preventScroll: true });
}

function semToken() {
  tela(`<h1>Abra o painel pelo endereço do terminal</h1>
    <p class="lead">Cada execução do painel gera um endereço com um token de acesso.
    Copie o endereço completo mostrado no terminal onde o <code>netsnap_web.py</code> está rodando
    e cole no navegador. O token impede que outras páginas abertas neste PC acionem coletas.</p>`);
}

/* ------------------------------------------------------------ visão geral */
async function vPainel() {
  const d = await api("GET", "painel");
  const execucoes = d.jobs.length ? `<div class="tabela-rolagem"><table>
      <thead><tr><th>Execução</th><th>Início</th><th>Hosts</th><th>Estado</th></tr></thead><tbody>
      ${d.jobs.map((j) => `<tr class="clicavel" data-ir="#/execucoes/${esc(j.id)}">
        <td>${esc(j.titulo)}</td><td class="data">${fmtData(j.criado)}</td><td class="num">${j.hosts || "—"}</td>
        <td>${estado(j.estado)}</td></tr>`).join("")}
      </tbody></table></div>`
    : `<p class="vazio">Nenhuma execução desde que o painel foi aberto.</p>`;

  const ultimas = d.ultimas.length ? `<div class="tabela-rolagem"><table>
      <thead><tr><th>Equipamento</th><th>Plataforma</th><th>Coletado</th></tr></thead><tbody>
      ${d.ultimas.map((s) => `<tr class="clicavel" data-ir="#/snapshots/${encodeURIComponent(s.arquivo)}">
        <td><strong>${esc(s.host)}</strong> <span class="suave">${esc(s.ip)}</span></td>
        <td>${fibra(s.plataforma, s.plataforma_nome)}</td><td class="data">${fmtData(s.coletado_em)}</td></tr>`).join("")}
      </tbody></table></div>`
    : `<p class="vazio">Nenhum snapshot ainda. <a href="#/coletar">Faça a primeira coleta</a>.</p>`;

  const agenda = d.agendamentos.length ? `<ul class="pequeno">${d.agendamentos.map((a) =>
      `<li><strong>${esc(a.nome)}</strong> — ${estado(a.situacao)} próxima ${fmtData(a.proxima)}</li>`).join("")}</ul>`
    : `<p class="suave pequeno">Nenhum agendamento. <a href="#/agendamentos">Criar</a></p>`;

  const falhas = d.falhas.length ? `<div class="tabela-rolagem"><table>
      <thead><tr><th>IP</th><th>Motivo</th><th>Quando</th></tr></thead><tbody>
      ${d.falhas.slice().reverse().map((f) => `<tr><td class="mono">${esc(f.ip)}</td>
        <td>${esc(f.motivo)}</td><td class="data">${fmtData(f.quando)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="suave pequeno">Nenhuma falha nas últimas coletas.</p>`;

  tela(`<div class="cabecalho-linha"><div><h1>Visão geral</h1>
      <p class="lead">Coletas somente leitura do parque. Os arquivos ficam em <code>${esc(d.pastas.snapshots)}</code>.</p></div>
      <a class="botao principal" href="#/coletar">Nova coleta</a></div>
    <div class="faixa">
      <div><strong>${d.hosts}</strong><span>equipamentos com snapshot</span></div>
      <div><strong>${d.snapshots}</strong><span>snapshots na pasta</span></div>
      <div><strong>${d.executando}</strong><span>execuções em andamento</span></div>
    </div>
    <div class="colunas">
      <section><h2>Execuções desta sessão</h2>${execucoes}</section>
      <section><h2>Últimas coletas</h2>${ultimas}</section>
    </div>
    <div class="colunas">
      <section><h2>Agendamentos</h2>${agenda}</section>
      <section><h2>Falhas recentes</h2>${falhas}</section>
    </div>
    <h2>Código de cores das plataformas</h2>
    <p class="suave pequeno">Cada plataforma usa a cor de capa de uma fibra (TIA-598).</p>
    <div class="legenda-fibras">${(S.info.capacidades.plataformas.length ? S.info.capacidades.plataformas : PLATAFORMAS_PADRAO)
      .map((p) => fibra(p.chave, p.nome)).join("")}</div>`);
}

const PLATAFORMAS_PADRAO = [
  ["juniper_junos", "Juniper Junos"], ["huawei", "Huawei VRP V5"], ["huawei_ce", "Huawei VRP V8"],
  ["huawei_smartax", "Huawei SmartAX"], ["fiberhome", "FiberHome OLT"], ["cisco_nxos", "Cisco NX-OS"],
  ["cisco_ios", "Cisco IOS/IOS-XE"], ["cisco_xr", "Cisco IOS-XR"], ["mikrotik_routeros", "MikroTik RouterOS"],
  ["linux", "Servidor Linux"],
].map(([chave, nome]) => ({ chave, nome }));

/* ------------------------------------------------------------ nova coleta */
function semColeta() {
  return `<h1>Coleta indisponível nesta máquina</h1>
    <p class="erro-campo">${esc(S.info.capacidades.motivo)}</p>
    <p class="lead">Snapshots, inventário, comparação, topologia e vulnerabilidades continuam disponíveis.</p>`;
}

function camposCredencial(protocolo, porta) {
  return `<div class="lado-a-lado">
      <div class="campo"><label for="usuario">Usuário</label>
        <input id="usuario" name="usuario" type="text" autocomplete="username" required value="${esc(ler("usuario"))}"></div>
      <div class="campo"><label for="senha">Senha</label>
        <input id="senha" name="senha" type="password" autocomplete="new-password" required></div>
    </div>
    <div class="campo"><label for="porta">Porta padrão</label>
      <input id="porta" name="porta" type="number" min="1" max="65535" value="${porta}">
      <small>Usada nas entradas sem <code>:porta</code>.</small></div>`;
}

async function vColetar() {
  if (!S.info.capacidades.coleta) return tela(semColeta());
  const modos = S.info.capacidades.modos;
  const descricao = {
    "1": "Configuração completa na sintaxe do equipamento",
    "2": "Últimas entradas de log",
    "3": "CPU, memória, alarmes, BGP/OSPF",
    "4": "Portas, ópticas (Rx/Tx), velocidade e erros",
    "5": "LLDP e CDP",
    "6": "Versão, hardware, licenças e pacotes",
    "7": "Configuração, ópticas, vizinhança e inventário, sem logs",
    "8": "Todas as seções",
  };
  const alvos = S.prefill || "";
  S.prefill = null;
  tela(`<h1>Nova coleta</h1>
    <p class="lead">Somente leitura: nenhum comando altera os equipamentos. A senha vai direto para o processo de coleta e não é gravada.</p>
    <form class="grade" id="f-coleta" autocomplete="off">
      <div>
        <div class="campo"><label for="alvos">Alvos</label>
          <textarea id="alvos" name="alvos" required spellcheck="false"
            placeholder="10.0.0.1&#10;10.0.0.2:2222&#10;10.10.0.0/28&#10;10.20.0.1-30&#10;olt-centro.isp.net   # comentário">${esc(alvos)}</textarea>
          <small>Um por linha: IP, IP:porta, nome DNS, CIDR, intervalo ou IPv6 (<code>[2001:db8::1]:22</code>).</small></div>
        <div class="campo"><span class="rotulo" id="r-modo">O que extrair</span>
          <div class="opcoes" role="radiogroup" aria-labelledby="r-modo">
          ${modos.map((m) => `<label class="opcao"><input type="radio" name="modo" value="${esc(m.chave)}" ${m.chave === "8" ? "checked" : ""}>
            <span>${esc(m.nome)}<small>${esc(descricao[m.chave] || "")}</small></span></label>`).join("")}
          </div></div>
      </div>
      <div>
        <div class="campo"><span class="rotulo">Protocolo</span>
          <label class="marcar"><input type="radio" name="protocolo" value="ssh" checked> SSH</label>
          <label class="marcar"><input type="radio" name="protocolo" value="telnet"> Telnet, para equipamentos sem SSH</label>
          <p class="alerta-campo pequeno" id="aviso-telnet" hidden>O Telnet transmite usuário, senha e toda a sessão em texto claro. Use só em rede de gerência confiável.</p>
        </div>
        ${camposCredencial("ssh", 22)}
        <div class="lado-a-lado">
          <div class="campo"><label for="varredura">Antes de conectar</label>
            <select id="varredura" name="varredura">
              <option value="fast">Pingar e pular quem não responde</option>
              <option value="deep">Tentar todos, sem ping</option>
            </select></div>
          <div class="campo"><label for="instancias">Simultâneos</label>
            <input id="instancias" name="instancias" type="number" min="1" max="10" value="5">
            <small>1 a 10 equipamentos ao mesmo tempo.</small></div>
        </div>
        <label class="marcar"><input type="checkbox" name="sensivel"> <span>Incluir senhas, chaves e communities no snapshot</span></label>
        <label class="marcar"><input type="checkbox" name="debug"> <span>Gerar log de depuração (sempre sem segredos)</span></label>
        <div class="acoes"><button class="principal" type="submit">Iniciar coleta</button>
          <span class="suave pequeno" id="contagem-alvos"></span></div>
      </div>
    </form>`);
  const f = $("#f-coleta");
  f.addEventListener("change", (e) => {
    if (e.target.name === "protocolo") {
      const telnet = e.target.value === "telnet";
      $("#aviso-telnet").hidden = !telnet;
      const porta = $("#porta");
      if (porta.value === "22" || porta.value === "23") porta.value = telnet ? "23" : "22";
    }
  });
  const contar = () => {
    const n = $("#alvos").value.split("\n").filter((l) => l.split("#")[0].trim()).length;
    $("#contagem-alvos").textContent = n ? `${n} entrada(s)` : "";
  };
  $("#alvos").addEventListener("input", contar);
  contar();
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(f);
    const cfg = {
      alvos: fd.get("alvos"), modo: fd.get("modo"), protocolo: fd.get("protocolo"),
      usuario: fd.get("usuario").trim(), senha: fd.get("senha"), porta: Number(fd.get("porta")),
      varredura: fd.get("varredura"), instancias: Number(fd.get("instancias")),
      sensivel: !!fd.get("sensivel"), debug: !!fd.get("debug"),
    };
    const botao = f.querySelector("button[type=submit]");
    botao.disabled = true;
    try {
      guardar("usuario", cfg.usuario);
      const job = await api("POST", "coletas", cfg);
      $("#senha").value = "";
      location.hash = "#/execucoes/" + job.id;
    } catch (err) {
      aviso(err.message, true);
      botao.disabled = false;
    }
  });
}

/* ------------------------------------------------------------ execuções */
async function vExecucoes(id) {
  if (id) return vExecucao(id);
  const jobs = await api("GET", "jobs");
  tela(`<h1>Execuções</h1>
    <p class="lead">Coletas, diagnósticos e triagens disparados desde que o painel foi aberto.</p>
    ${jobs.length ? `<div class="tabela-rolagem"><table>
      <thead><tr><th>Execução</th><th>Tipo</th><th>Início</th><th>Fim</th><th>Resultado</th><th>Estado</th></tr></thead><tbody>
      ${jobs.map((j) => `<tr class="clicavel" data-ir="#/execucoes/${esc(j.id)}">
        <td>${esc(j.titulo)}</td><td>${esc(j.tipo)}</td><td class="data">${fmtData(j.criado)}</td><td class="data">${fmtData(j.terminado)}</td>
        <td class="pequeno">${Object.entries(j.contagem).map(([k, v]) => `${v} ${esc(k)}`).join(", ") || "—"}</td>
        <td>${estado(j.estado)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nada executado ainda. <a href="#/coletar">Iniciar uma coleta</a>.</p>`}`);
}

function classeLinha(l) {
  if (/\[OK\]/.test(l)) return "l-ok";
  if (/\[FALHA\]|\[ERRO|Traceback|Error/.test(l)) return "l-falha";
  if (/\[!\]|\[PENDENTE\]|\[ABORTADO\]/.test(l)) return "l-aviso";
  return "";
}

async function vExecucao(id) {
  // Uma resposta que chegue depois da troca de tela não pode escrever na
  // tela nova nem reagendar a consulta.
  const geracao = S.geracao;
  let linhas = 0;
  const m = tela(`<p class="carregando">Carregando execução…</p>`);
  let montado = false;

  const atualizar = async () => {
    let d;
    try { d = await api("GET", `jobs/${id}?desde=${linhas}`); } catch (e) {
      if (geracao !== S.geracao) return;
      if (!montado) tela(`<h1>Execução não encontrada</h1><p class="lead">Execuções ficam em memória e somem quando o painel é reiniciado. <a href="#/execucoes">Ver execuções</a></p>`);
      return;
    }
    if (geracao !== S.geracao) return;
    if (!montado) { montar(d); montado = true; }
    $("#ex-estado").innerHTML = estado(d.estado);
    $("#ex-fim").textContent = d.terminado ? fmtData(d.terminado) : "em andamento";
    $("#ex-cancelar").hidden = d.estado !== "executando";
    if (d.linhas.length) {
      const c = $("#ex-console");
      const noFim = c.scrollTop + c.clientHeight >= c.scrollHeight - 30;
      c.insertAdjacentHTML("beforeend", d.linhas.map((l) => {
        const k = classeLinha(l);
        return k ? `<span class="${k}">${esc(l)}</span>\n` : esc(l) + "\n";
      }).join(""));
      linhas = d.total_linhas;
      if (noFim) c.scrollTop = c.scrollHeight;
    }
    renderHosts(d);
    if (d.estado !== "executando") renderResultado(d);
    else S.timer = setTimeout(atualizar, 1200);
  };

  const montar = (d) => {
    m.innerHTML = `<p class="pequeno"><a href="#/execucoes">Execuções</a></p>
      <div class="cabecalho-linha"><div><h1>${esc(d.titulo)}</h1>
        <p class="lead">Início ${fmtData(d.criado)} · término <span id="ex-fim"></span> · <span id="ex-estado"></span></p></div>
        <button class="perigo" id="ex-cancelar" type="button">Cancelar execução</button></div>
      <div id="ex-erro"></div>
      <div id="ex-hosts"></div>
      <div id="ex-resultado"></div>
      <h2>Saída</h2><pre class="console" id="ex-console" tabindex="0" aria-label="Saída da execução"></pre>`;
    $("#ex-cancelar").addEventListener("click", async () => {
      if (!confirm("Cancelar esta execução? As sessões abertas serão encerradas.")) return;
      try { await api("POST", `jobs/${id}/cancelar`); aviso("Execução cancelada"); } catch (e) { aviso(e.message, true); }
    });
  };

  const renderHosts = (d) => {
    if (!d.lista_hosts.length) { $("#ex-hosts").innerHTML = ""; return; }
    $("#ex-hosts").innerHTML = `<h2>Equipamentos</h2><div class="tabela-rolagem"><table>
      <thead><tr><th>IP</th><th>Estado</th><th>Plataforma</th><th>Detalhe</th></tr></thead><tbody>
      ${d.lista_hosts.map((h) => `<tr><td class="mono">${esc(h.ip)}</td><td>${estado(h.estado)}</td>
        <td>${esc(h.plataforma || "—")}</td>
        <td class="pequeno">${h.arquivo ? `<a href="#/snapshots/${encodeURIComponent(h.arquivo)}">${esc(h.arquivo)}</a>${h.motivo ? `<br><span class="suave">${esc(h.motivo)}</span>` : ""}`
          : esc(h.motivo || h.ultimo || "")}</td></tr>`).join("")}
      </tbody></table></div>`;
  };

  const renderResultado = (d) => {
    if (d.erro) $("#ex-erro").innerHTML = `<p class="erro-campo">${esc(d.erro)}</p>`;
    const r = d.resultado || {};
    const partes = [];
    if (r.indice) partes.push(`<a href="#/relatorio/indice/${encodeURIComponent(r.indice)}">Índice da coleta</a>`);
    if (r.debug) partes.push(`<button class="link" data-baixar="debug" data-nome="${esc(r.debug)}">Baixar log de depuração</button>`);
    if (r.relatorio && d.tipo === "netcve") partes.push(`<a href="#/relatorio/triagem/${encodeURIComponent(r.relatorio)}">Abrir relatório de vulnerabilidades</a>`);
    if (r.csv) partes.push(`<button class="link" data-baixar="triagem_csv" data-nome="${esc(r.csv)}">Baixar CSV</button>`);
    if (r.relatorio && d.tipo === "netdiag") partes.push(`<a href="#/relatorio/diagnostico/${encodeURIComponent(r.relatorio)}">Abrir diagnóstico</a>`);
    let html = partes.length ? `<div class="acoes">${partes.join("")}</div>` : "";
    if (r.pendentes && r.pendentes.length) {
      const plataformas = S.info.capacidades.plataformas;
      html += `<h2>Não identificados automaticamente</h2>
        <p class="suave">Responderam, mas a plataforma não foi reconhecida. Escolha o tipo para coletar com o perfil certo.</p>
        <form id="f-pendentes" class="bloco" autocomplete="off">
        ${r.pendentes.map((p, n) => `<div class="lado-a-lado campo"><label class="mono" for="pend-${n}">${esc(p)}</label>
          <select id="pend-${n}" data-alvo="${esc(p)}"><option value="">Pular</option>
          ${plataformas.map((x) => `<option value="${esc(x.chave)}">${esc(x.nome)}</option>`).join("")}</select></div>`).join("")}
        <div class="lado-a-lado"><div class="campo"><label for="pend-senha">Senha de ${esc(d.config.usuario || "")}</label>
          <input id="pend-senha" type="password" autocomplete="new-password" required></div></div>
        <button class="principal" type="submit">Coletar selecionados</button></form>`;
    }
    $("#ex-resultado").innerHTML = html;
    const fp = $("#f-pendentes");
    if (fp) fp.addEventListener("submit", async (e) => {
      e.preventDefault();
      const senha = $("#pend-senha").value;
      const porTipo = {};
      $$("select[data-alvo]", fp).forEach((s) => { if (s.value) (porTipo[s.value] = porTipo[s.value] || []).push(s.dataset.alvo); });
      const tipos = Object.keys(porTipo);
      if (!tipos.length) return aviso("Escolha a plataforma de ao menos um equipamento", true);
      try {
        let ultimo;
        for (const tipo of tipos) {
          ultimo = await api("POST", "coletas", Object.assign({}, d.config, {
            alvos: porTipo[tipo].join("\n"), tipo, senha, titulo: undefined }));
        }
        location.hash = "#/execucoes/" + ultimo.id;
      } catch (err) { aviso(err.message, true); }
    });
  };

  await atualizar();
}

/* ------------------------------------------------------------ snapshots */
async function vSnapshots(arquivo) {
  if (arquivo) return vSnapshot(arquivo);
  const lista = await api("GET", "snapshots");
  S.snapshots = lista;
  tela(`<div class="cabecalho-linha"><div><h1>Snapshots</h1>
      <p class="lead">${lista.length} arquivo(s). Clique para ler por seção e comando.</p></div>
      <div class="campo campo-filtro"><label for="filtro">Filtrar</label>
      <input id="filtro" type="search" placeholder="nome, IP ou plataforma"></div></div>
    ${lista.length ? `<div class="tabela-rolagem"><table id="t-snaps">
      <thead><tr><th>Equipamento</th><th>IP</th><th>Plataforma</th><th>Coletado</th><th>Modo</th><th>Observações</th><th>Tamanho</th></tr></thead><tbody>
      ${lista.map((s) => `<tr class="clicavel" data-ir="#/snapshots/${encodeURIComponent(s.arquivo)}"
          data-busca="${esc((s.host + " " + s.ip + " " + s.plataforma_nome + " " + s.aplicacoes.join(" ")).toLowerCase())}">
        <td><strong>${esc(s.host)}</strong>${s.aplicacoes.length ? `<br><span class="suave pequeno">${esc(s.aplicacoes.join(", "))}</span>` : ""}</td>
        <td class="mono">${esc(s.ip)}</td><td>${fibra(s.plataforma, s.plataforma_nome)}</td>
        <td class="data">${fmtData(s.coletado_em, true)}</td><td class="pequeno">${esc(s.modo)}</td>
        <td>${s.sessao_perdida ? estado("incompleta") + " " : ""}${s.transporte === "telnet" ? estado("telnet") + " " : ""}${s.sensivel === "included" ? estado("com segredos") : ""}</td>
        <td class="num pequeno">${fmtTamanho(s.tamanho)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhum snapshot na pasta. <a href="#/coletar">Fazer uma coleta</a>.</p>`}`);
  const filtro = $("#filtro");
  if (filtro) filtro.addEventListener("input", () => {
    const q = filtro.value.trim().toLowerCase();
    $$("#t-snaps tbody tr").forEach((tr) => { tr.hidden = q && !tr.dataset.busca.includes(q); });
  });
}

async function vSnapshot(arquivo) {
  const s = await api("GET", "snapshots/" + encodeURIComponent(arquivo));
  const m = s.meta;
  let n = 0;
  const indice = [], corpo = [];
  s.secoes.forEach((sec) => {
    indice.push(`<h4>${esc(sec.titulo)}</h4>`);
    corpo.push(`<h2 class="secao-titulo">${esc(sec.titulo)}</h2>`);
    sec.comandos.forEach((c) => {
      n++;
      indice.push(`<a href="#c-${n}" data-ancora="c-${n}" class="${c.saida == null ? "vazio-cmd" : ""}" title="${esc(c.comando)}">${esc(c.comando)}</a>`);
      corpo.push(`<article class="comando" id="c-${n}" data-busca="${esc((c.comando + "\n" + (c.saida || "")).toLowerCase())}">
        <h3><span>${esc(c.comando)}</span></h3>
        ${c.saida == null ? `<p class="sem-saida">Sem saída útil${c.retorno ? ` — retorno: ${esc(c.retorno)}` : ""}. Não significa recurso desabilitado.</p>`
          : `<pre>${esc(c.saida)}</pre>`}</article>`);
    });
  });
  tela(`<p class="pequeno"><a href="#/snapshots">Snapshots</a></p>
    <div class="cabecalho-linha"><div><h1>${esc(m.host)} <span class="suave">${esc(m.ip)}</span></h1>
      <p class="lead">${fibra(m.platform_key, m.platform_name)} · coletado ${fmtData(m.collected_at, true)} · netsnap ${esc(m.netsnap_version)}</p></div>
      <div class="acoes"><a class="botao" href="#/comparar/${encodeURIComponent(arquivo)}">Comparar com outra coleta</a>
      <button type="button" data-baixar="snapshot" data-nome="${esc(arquivo)}">Baixar .md</button></div></div>
    <dl class="metadados">
      <div><dt>Modo</dt><dd>${esc(m.extraction_mode)}</dd></div>
      <div><dt>Transporte</dt><dd>${esc(m.transport || "ssh")}</dd></div>
      <div><dt>Dados sensíveis</dt><dd>${m.sensitive_data === "included" ? "incluídos" : "removidos"}</dd></div>
      <div><dt>Aplicações</dt><dd>${esc((m.applications || []).join(", ") || "—")}</dd></div>
    </dl>
    ${s.avisos.map((a) => `<p class="aviso-snapshot">${inline(a)}</p>`).join("")}
    <div class="campo campo-busca"><label for="busca">Buscar nas saídas</label>
      <input id="busca" type="search" placeholder="ex.: bgp, xe-0/0/1, Rx Power"></div>
    <div class="leitor"><nav class="leitor-indice" aria-label="Comandos do snapshot">${indice.join("")}</nav>
      <div id="leitor-corpo">${corpo.join("")}</div></div>`);
  $(".leitor-indice").addEventListener("click", (e) => {
    const a = e.target.closest("a[data-ancora]");
    if (!a) return;
    e.preventDefault();
    document.getElementById(a.dataset.ancora).scrollIntoView({ block: "start" });
  });
  const busca = $("#busca");
  // Espera a digitação parar: em snapshot de vários MB cada busca custa
  // segundos, e buscar a cada tecla travaria a página.
  let espera = null;
  busca.addEventListener("input", () => {
    clearTimeout(espera);
    espera = setTimeout(filtrar, 300);
  });
  const filtrar = () => {
    const q = busca.value.trim().toLowerCase();
    $$("#leitor-corpo .comando").forEach((art) => {
      const pre = art.querySelector("pre");
      if (pre && !pre.dataset.original) pre.dataset.original = pre.textContent;
      const casa = !q || art.dataset.busca.includes(q);
      art.hidden = !casa;
      if (pre) {
        const original = pre.dataset.original;
        if (q && casa) {
          // Divide o texto original (não o escapado) e escapa cada pedaço:
          // os trechos ímpares são as ocorrências.
          const re = new RegExp("(" + q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "gi");
          pre.innerHTML = original.split(re).map((p, i) => i % 2 ? `<mark>${esc(p)}</mark>` : esc(p)).join("");
        } else pre.textContent = original;
      }
    });
    $$("#leitor-corpo .secao-titulo").forEach((h) => {
      let el = h.nextElementSibling, algum = false;
      while (el && !el.classList.contains("secao-titulo")) { if (!el.hidden) algum = true; el = el.nextElementSibling; }
      h.hidden = !algum;
    });
  };
}

/* ------------------------------------------------------------ inventário */
async function vInventario() {
  const d = await api("GET", "inventario");
  const campos = [
    ["host", "Equipamento"], ["ip", "IP"], ["plataforma_nome", "Plataforma"], ["modelo", "Modelo"],
    ["versoes", "Versões"], ["cves", "CVEs"], ["coletas", "Coletas"], ["coletado_em", "Última coleta"],
  ];
  const desenhar = () => {
    const { campo, asc } = S.inventarioOrdem;
    const val = (h) => Array.isArray(h[campo]) ? h[campo].join(" ") : (h[campo] == null ? -1 : h[campo]);
    const linhas = d.hosts.slice().sort((a, b) => {
      const x = val(a), y = val(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "pt-BR", { numeric: true });
      return asc ? r : -r;
    });
    $("#t-inv").innerHTML = `<thead><tr>${campos.map(([c, t]) =>
      `<th aria-sort="${c === campo ? (asc ? "ascending" : "descending") : "none"}"><button data-ordem="${c}">${t}${c === campo ? (asc ? " ↑" : " ↓") : ""}</button></th>`).join("")}</tr></thead>
      <tbody>${linhas.map((h) => `<tr class="clicavel" data-ir="#/snapshots/${encodeURIComponent(h.arquivo)}">
        <td class="nome"><strong>${esc(h.host)}</strong>${h.sessao_perdida ? " " + estado("incompleta") : ""}</td>
        <td class="mono">${esc(h.ip)}</td><td>${fibra(h.plataforma, h.plataforma_nome)}</td>
        <td>${esc(h.modelo || "—")}</td><td class="pequeno">${esc(h.versoes.join(" · ") || "—")}</td>
        <td class="num">${h.cves == null ? '<span class="suave">—</span>' : h.cves}</td>
        <td class="num">${h.coletas}</td><td class="data">${fmtData(h.coletado_em)}</td></tr>`).join("")}</tbody>`;
  };
  tela(`<div class="cabecalho-linha"><div><h1>Inventário</h1>
      <p class="lead">Snapshot mais recente de cada equipamento. ${d.triagem
        ? `CVEs da triagem <a href="#/relatorio/triagem/${encodeURIComponent(d.triagem)}">${esc(d.triagem)}</a>; — quando a versão não foi consultada.`
        : `Rode a <a href="#/vulnerabilidades">triagem de vulnerabilidades</a> para preencher a coluna de CVEs.`}</p></div>
      <button type="button" id="inv-csv">Exportar CSV</button></div>
    ${d.hosts.length ? `<div class="tabela-rolagem"><table id="t-inv"></table></div>`
      : `<p class="vazio">Sem snapshots ainda. <a href="#/coletar">Fazer uma coleta</a>.</p>`}
    ${d.falhas.length ? `<h2>Sem snapshot, com falha nas últimas coletas</h2>
      <div class="tabela-rolagem"><table><thead><tr><th>IP</th><th>Motivo</th><th>Quando</th></tr></thead><tbody>
      ${d.falhas.map((f) => `<tr><td class="mono">${esc(f.ip)}</td><td>${esc(f.motivo)}</td><td class="data">${fmtData(f.quando)}</td></tr>`).join("")}
      </tbody></table></div>` : ""}`);
  if (!d.hosts.length) return;
  desenhar();
  $("#t-inv").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-ordem]");
    if (!b) return;
    e.stopPropagation();
    const o = S.inventarioOrdem;
    o.asc = o.campo === b.dataset.ordem ? !o.asc : true;
    o.campo = b.dataset.ordem;
    desenhar();
  });
  $("#inv-csv").addEventListener("click", () => {
    const q = (v) => `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
    const linhas = [["host", "ip", "plataforma", "modelo", "versoes", "cves", "coletas", "ultima_coleta", "arquivo"].join(";")]
      .concat(d.hosts.map((h) => [h.host, h.ip, h.plataforma_nome, h.modelo, h.versoes.join(" | "),
        h.cves == null ? "" : h.cves, h.coletas, h.coletado_em, h.arquivo].map(q).join(";")));
    baixarTexto("inventario_netsnap.csv", "﻿" + linhas.join("\r\n"), "text/csv");
  });
}

/* ------------------------------------------------------------ comparar */
async function vComparar(arquivoInicial) {
  const lista = await api("GET", "snapshots");
  const grupos = {};
  lista.forEach((s) => { const k = `${s.host} (${s.ip})`; (grupos[k] = grupos[k] || []).push(s); });
  const chaves = Object.keys(grupos).sort((a, b) => (grupos[b].length > 1) - (grupos[a].length > 1) || a.localeCompare(b));
  let grupoInicial = chaves[0];
  if (arquivoInicial) grupoInicial = chaves.find((k) => grupos[k].some((s) => s.arquivo === arquivoInicial)) || grupoInicial;

  tela(`<h1>Comparar coletas</h1>
    <p class="lead">Mostra o que mudou entre duas coletas do mesmo equipamento, comando a comando.</p>
    ${lista.length < 2 ? `<p class="vazio">É preciso ao menos dois snapshots.</p>` : `
    <form class="bloco" id="f-comp">
      <div class="campo"><label for="c-host">Equipamento</label>
        <select id="c-host">${chaves.map((k) => `<option ${k === grupoInicial ? "selected" : ""}>${esc(k)}</option>`).join("")}</select></div>
      <div class="lado-a-lado">
        <div class="campo"><label for="c-a">Coleta anterior</label><select id="c-a"></select></div>
        <div class="campo"><label for="c-b">Coleta posterior</label><select id="c-b"></select></div>
      </div>
      <label class="marcar"><input type="checkbox" id="c-estaveis" checked> <span>Só configuração e inventário. Estado, ópticas e logs mudam a cada coleta.</span></label>
      <label class="marcar"><input type="checkbox" id="c-iguais"> <span>Mostrar comandos sem diferença</span></label>
      <div class="acoes"><button class="principal" type="submit">Comparar</button></div>
    </form>
    <div id="c-resultado"></div>`}`);
  if (lista.length < 2) return;
  const preencher = () => {
    const snaps = grupos[$("#c-host").value].slice().sort((a, b) => a.coletado_em.localeCompare(b.coletado_em));
    const opt = (s) => `<option value="${esc(s.arquivo)}">${fmtData(s.coletado_em, true)} · ${esc(s.modo)}</option>`;
    $("#c-a").innerHTML = snaps.map(opt).join("");
    $("#c-b").innerHTML = snaps.map(opt).join("");
    if (snaps.length > 1) { $("#c-a").selectedIndex = snaps.length - 2; $("#c-b").selectedIndex = snaps.length - 1; }
    if (snaps.length < 2) $("#c-resultado").innerHTML = `<p class="vazio">Este equipamento tem uma coleta só. Escolha outro ou faça uma nova coleta para comparar.</p>`;
    else $("#c-resultado").innerHTML = "";
  };
  $("#c-host").addEventListener("change", preencher);
  preencher();
  $("#f-comp").addEventListener("submit", async (e) => {
    e.preventDefault();
    const a = $("#c-a").value, b = $("#c-b").value;
    if (a === b) return aviso("Escolha duas coletas diferentes", true);
    let r;
    try {
      r = await api("GET", `comparar?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}&estaveis=${$("#c-estaveis").checked ? 1 : 0}`);
    } catch (err) { return aviso(err.message, true); }
    const mostrarIguais = $("#c-iguais").checked;
    const cont = {};
    r.itens.forEach((i) => { cont[i.estado] = (cont[i.estado] || 0) + 1; });
    const itens = r.itens.filter((i) => mostrarIguais || i.estado !== "igual");
    $("#c-resultado").innerHTML = `<h2>Resultado</h2>
      <p>${Object.entries(cont).map(([k, v]) => `${estado(k)} ${v}`).join(" &nbsp; ")}</p>
      ${itens.length ? itens.map((i) => `<details class="item" ${i.estado === "alterado" && i.diff.length < 80 ? "open" : ""}>
        <summary>${estado(i.estado)} <code>${esc(i.comando)}</code>
          <span class="contagem-diff">${i.estado === "alterado" ? `<span class="m">+${i.mais}</span> <span class="n">−${i.menos}</span>` : ""}</span>
          <span class="suave pequeno">${esc(i.secao)}</span></summary>
        ${i.diff.length ? `<div class="diff">${i.diff.map((l) => `<div class="${l.startsWith("+") ? "mais" : l.startsWith("-") ? "menos" : l.startsWith("@@") ? "contexto-arroba" : ""}">${esc(l) || " "}</div>`).join("")}</div>` : ""}
        </details>`).join("") : `<p class="vazio">Nenhuma diferença nas seções comparadas.</p>`}`;
  });
}

/* ------------------------------------------------------------ topologia */
async function vTopologia() {
  const g = await api("GET", "topologia");
  const nos = {};
  g.nos.forEach((n) => { nos[n.id] = n; });
  const nome = (id) => {
    const n = nos[id];
    if (!n) return esc(id);
    return n.coletado && n.arquivo ? `<a href="#/snapshots/${encodeURIComponent(n.arquivo)}">${esc(n.rotulo)}</a>` : esc(n.rotulo);
  };
  const naoColetados = g.nos.filter((n) => !n.coletado);
  const comIp = naoColetados.filter((n) => n.ips_gerencia.some((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)));
  tela(`<div class="cabecalho-linha"><div><h1>Topologia</h1>
      <p class="lead">Enlaces lidos do LLDP/CDP do snapshot mais recente de cada equipamento. É a base do desenho automático da rede, que virá num módulo próprio.</p></div>
      <div class="acoes"><button type="button" id="topo-salvar">Salvar JSON</button></div></div>
    <div class="faixa">
      <div><strong>${g.nos.filter((n) => n.coletado).length}</strong><span>coletados</span></div>
      <div><strong>${naoColetados.length}</strong><span>vizinhos ainda não coletados</span></div>
      <div><strong>${g.enlaces.length}</strong><span>enlaces</span></div>
      <div><strong>${g.enlaces.filter((e) => e.confirmado).length}</strong><span>confirmados pelos dois lados</span></div>
    </div>
    <p class="suave pequeno">Enlace sem LLDP/CDP habilitado não aparece. Ausência aqui não significa ausência de cabo.</p>
    <h2>Enlaces</h2>
    ${g.enlaces.length ? `<div class="tabela-rolagem"><table><thead><tr><th>Equipamento</th><th>Porta</th><th>Vizinho</th><th>Porta do vizinho</th><th>Confirmação</th></tr></thead><tbody>
      ${g.enlaces.map((e) => `<tr><td class="nome">${nome(e.a)}</td><td class="mono">${esc(e.porta_a)}</td><td>${nome(e.b)}</td>
        <td class="mono">${esc(e.portas_b.join(", ") || e.porta_b || "—")}</td>
        <td title="${esc(e.origem.join("\n"))}">${e.confirmado ? estado("dois lados") : '<span class="suave pequeno">um lado</span>'}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhum enlace encontrado. Colete a seção Vizinhança L2 (modo 5, 7 ou 8) com LLDP/CDP habilitado nos equipamentos.</p>`}
    ${naoColetados.length ? `<h2>Vizinhos ainda não coletados</h2>
      <p class="suave">Aparecem na vizinhança de equipamentos coletados. ${comIp.length ? "Os que anunciam endereço de gerência podem ser coletados direto daqui." : ""}</p>
      <div class="tabela-rolagem"><table><thead><tr><th>Nome anunciado</th><th>Endereço de gerência</th></tr></thead><tbody>
      ${naoColetados.map((n) => `<tr><td>${esc(n.rotulo)}</td><td class="mono">${esc(n.ips_gerencia.join(", ") || "—")}</td></tr>`).join("")}
      </tbody></table></div>
      ${comIp.length && S.info.capacidades.coleta ? `<div class="acoes"><button class="principal" type="button" id="topo-coletar">Coletar os ${comIp.length} com endereço</button></div>` : ""}` : ""}
    ${g.sem_vizinhanca.length ? `<h2>Sem vizinhança</h2><ul>${g.sem_vizinhanca.map((s) =>
      `<li><strong>${esc(s.host)}</strong> — <span class="suave">${esc(s.motivo)}</span></li>`).join("")}</ul>` : ""}`);
  $("#topo-salvar").addEventListener("click", async () => {
    try { const r = await api("POST", "topologia/salvar"); aviso("Salvo em " + r.arquivo); baixar("topologia", r.arquivo); }
    catch (e) { aviso(e.message, true); }
  });
  const bc = $("#topo-coletar");
  if (bc) bc.addEventListener("click", () => {
    S.prefill = comIp.map((n) => `${n.ips_gerencia.find((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip))}   # ${n.rotulo}`).join("\n");
    location.hash = "#/coletar";
  });
}

/* ------------------------------------------------------------ relatórios */
async function listaRelatorios(tipo, rotuloVazio) {
  const r = await api("GET", "relatorios");
  const itens = r[tipo] || [];
  if (!itens.length) return `<p class="vazio">${rotuloVazio}</p>`;
  return `<div class="tabela-rolagem"><table><thead><tr><th>Arquivo</th><th>Tamanho</th></tr></thead><tbody>
    ${itens.slice(0, 20).map((i) => `<tr class="clicavel" data-ir="#/relatorio/${tipo}/${encodeURIComponent(i.arquivo)}">
      <td class="mono">${esc(i.arquivo)}</td><td class="num pequeno">${fmtTamanho(i.tamanho)}</td></tr>`).join("")}
    </tbody></table></div>`;
}

async function vRelatorio(tipo, nome) {
  const texto = await api("GET", `arquivo/${tipo}/${encodeURIComponent(nome)}`);
  const volta = { indice: ["execucoes", "Execuções"], triagem: ["vulnerabilidades", "Vulnerabilidades"],
    diagnostico: ["diagnostico", "Diagnóstico"] }[tipo] || ["painel", "Visão geral"];
  tela(`<div class="cabecalho-linha"><p class="pequeno"><a href="#/${volta[0]}">${volta[1]}</a></p>
      <button type="button" data-baixar="${esc(tipo)}" data-nome="${esc(nome)}">Baixar</button></div>
    <article class="relatorio">${markdown(texto)}</article>`);
}

/* ------------------------------------------------------------ vulnerabilidades */
async function vVulnerabilidades() {
  const lista = await listaRelatorios("triagem", "Nenhuma triagem ainda.");
  tela(`<h1>Vulnerabilidades</h1>
    <p class="lead">Lê os snapshots, identifica versões e configuração insegura, e cruza com a NVD e o catálogo CISA KEV.
      Resultado é triagem para priorizar investigação, não laudo: o boletim do fabricante é a fonte final.</p>
    <form class="bloco" id="f-cve" autocomplete="off">
      <label class="marcar"><input type="checkbox" name="sem_rede"> <span>Sem internet: só as verificações de configuração</span></label>
      <label class="marcar"><input type="checkbox" name="todos"> <span>Incluir coletas antigas do mesmo equipamento</span></label>
      <div class="lado-a-lado espaco-acima">
        <div class="campo"><label for="api_key">Chave da API NVD (opcional)</label>
          <input id="api_key" name="api_key" type="password" autocomplete="off">
          <small>Sem chave: cerca de 6,5 s por consulta. Gratuita em nvd.nist.gov.</small></div>
        <div class="campo"><label for="limite_cve">CVEs listadas por versão</label>
          <input id="limite_cve" name="limite_cve" type="number" min="1" max="200" value="15"></div>
      </div>
      <label class="marcar"><input type="checkbox" name="inseguro"> <span>Ignorar validação TLS (só se a estação tiver certificados vencidos)</span></label>
      <div class="acoes"><button class="principal" type="submit">Rodar triagem</button></div>
    </form>
    <h2>Triagens anteriores</h2>${lista}`);
  $("#f-cve").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const job = await api("POST", "netcve", {
        sem_rede: !!fd.get("sem_rede"), todos: !!fd.get("todos"), inseguro: !!fd.get("inseguro"),
        api_key: fd.get("api_key"), limite_cve: Number(fd.get("limite_cve")) });
      location.hash = "#/execucoes/" + job.id;
    } catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ diagnóstico */
async function vDiagnostico() {
  const lista = await listaRelatorios("diagnostico", "Nenhum diagnóstico ainda.");
  if (!S.info.capacidades.coleta) return tela(semColeta() + `<h2>Diagnósticos anteriores</h2>${lista}`);
  const c = S.info.capacidades;
  tela(`<h1>Diagnóstico</h1>
    <p class="lead">Executa cada comando do perfil separadamente e mostra qual funciona, qual a plataforma recusa,
      qual volta vazio e qual é lento. Serve para ajustar perfis. Só SSH, até 20 equipamentos.</p>
    <form class="grade" id="f-diag" autocomplete="off">
      <div>
        <div class="campo"><label for="d-alvos">Alvos</label>
          <textarea id="d-alvos" name="alvos" required spellcheck="false" class="curto" placeholder="10.0.0.1&#10;10.0.0.2:2222"></textarea></div>
        <div class="campo"><span class="rotulo">Seções</span>
          ${c.secoes.map((s) => `<label class="marcar"><input type="checkbox" name="secoes" value="${esc(s.chave)}" checked> ${esc(s.nome)}</label>`).join("")}</div>
      </div>
      <div>
        ${camposCredencial("ssh", 22)}
        <div class="campo"><label for="d-plat">Plataforma</label>
          <select id="d-plat" name="plataforma"><option value="">Detectar automaticamente</option>
          ${c.plataformas.map((p) => `<option value="${esc(p.chave)}">${esc(p.nome)}</option>`).join("")}</select></div>
        <div class="campo"><label for="d-timeout">Tempo máximo por comando (s)</label>
          <input id="d-timeout" name="timeout" type="number" min="10" max="600" value="120"></div>
        <label class="marcar"><input type="checkbox" name="anonimizar"> <span>Anonimizar IPs, MACs, nomes e números de série, para compartilhar</span></label>
        <label class="marcar"><input type="checkbox" name="sensivel"> <span>Não mascarar senhas nas amostras (só para uso local)</span></label>
        <div class="acoes"><button class="principal" type="submit">Iniciar diagnóstico</button></div>
      </div>
    </form>
    <h2>Diagnósticos anteriores</h2>${lista}`);
  $("#f-diag").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      guardar("usuario", fd.get("usuario").trim());
      const job = await api("POST", "netdiag", {
        alvos: fd.get("alvos"), usuario: fd.get("usuario").trim(), senha: fd.get("senha"),
        porta: Number(fd.get("porta")), secoes: fd.getAll("secoes"), plataforma: fd.get("plataforma"),
        timeout: Number(fd.get("timeout")), anonimizar: !!fd.get("anonimizar"), sensivel: !!fd.get("sensivel") });
      location.hash = "#/execucoes/" + job.id;
    } catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ agendamentos */
async function vAgendamentos() {
  const itens = await api("GET", "agendamentos");
  const c = S.info.capacidades;
  const intervalo = (a) => a.intervalo_tipo === "horas" ? `a cada ${esc(a.intervalo_valor)} h` : `todo dia às ${esc(a.intervalo_valor)}`;
  tela(`<h1>Agendamentos</h1>
    <p class="lead">Coletas recorrentes enquanto o painel estiver aberto. O agendamento fica salvo sem a senha;
      ela vive só na memória e precisa ser informada de novo sempre que o painel reinicia.</p>
    ${itens.length ? `<div class="tabela-rolagem" id="ag-lista"><table><thead><tr><th>Nome</th><th>Frequência</th><th>Próxima</th><th>Última</th><th>Situação</th><th></th></tr></thead><tbody>
      ${itens.map((a) => `<tr><td><strong>${esc(a.nome)}</strong><br><span class="suave pequeno">${esc(a.alvos.split("\n").filter((l) => l.trim()).length)} entrada(s) · ${esc(a.usuario)} · ${esc(a.protocolo)}</span></td>
        <td>${intervalo(a)}</td><td>${a.ativo ? fmtData(a.proxima) : "—"}</td>
        <td>${a.ultima ? `${fmtData(a.ultima)} ${a.ultimo_job ? `<a href="#/execucoes/${esc(a.ultimo_job)}">${esc(a.ultimo_estado || "")}</a>` : ""}` : "—"}</td>
        <td>${estado(a.situacao)}</td>
        <td><div class="acoes">
          ${a.tem_senha ? `<button type="button" data-ag="executar" data-id="${esc(a.id)}">Executar agora</button>`
            : `<button type="button" class="principal" data-ag="senha" data-id="${esc(a.id)}">Informar senha</button>`}
          <button type="button" data-ag="${a.ativo ? "pausar" : "ativar"}" data-id="${esc(a.id)}">${a.ativo ? "Pausar" : "Retomar"}</button>
          <button type="button" class="perigo" data-ag="remover" data-id="${esc(a.id)}">Remover</button></div></td></tr>`).join("")}
      </tbody></table></div>` : `<p class="vazio">Nenhum agendamento.</p>`}
    ${c.coleta ? `<h2>Novo agendamento</h2>
    <form class="grade" id="f-ag" autocomplete="off">
      <div>
        <div class="campo"><label for="ag-nome">Nome</label><input id="ag-nome" name="nome" type="text" required placeholder="Backup diário da borda"></div>
        <div class="campo"><label for="ag-alvos">Alvos</label><textarea id="ag-alvos" name="alvos" required spellcheck="false" class="curto"></textarea></div>
        <div class="campo"><label for="ag-modo">O que extrair</label><select id="ag-modo" name="modo">
          ${c.modos.map((m) => `<option value="${esc(m.chave)}" ${m.chave === "1" ? "selected" : ""}>${esc(m.nome)}</option>`).join("")}</select></div>
      </div>
      <div>
        <div class="lado-a-lado">
          <div class="campo"><label for="ag-tipo">Frequência</label><select id="ag-tipo" name="intervalo_tipo">
            <option value="diario">Todo dia no horário</option><option value="horas">A cada N horas</option></select></div>
          <div class="campo"><label for="ag-valor" id="ag-valor-rotulo">Horário</label>
            <input id="ag-valor" name="intervalo_valor" type="time" value="03:00" required></div>
        </div>
        <div class="campo"><span class="rotulo">Protocolo</span>
          <label class="marcar"><input type="radio" name="protocolo" value="ssh" checked> SSH</label>
          <label class="marcar"><input type="radio" name="protocolo" value="telnet"> Telnet</label></div>
        ${camposCredencial("ssh", 22)}
        <div class="lado-a-lado">
          <div class="campo"><label for="ag-var">Antes de conectar</label><select id="ag-var" name="varredura">
            <option value="fast">Pingar e pular quem não responde</option><option value="deep">Tentar todos</option></select></div>
          <div class="campo"><label for="ag-inst">Simultâneos</label><input id="ag-inst" name="instancias" type="number" min="1" max="10" value="5"></div>
        </div>
        <div class="acoes"><button class="principal" type="submit">Criar agendamento</button></div>
      </div>
    </form>` : ""}`);

  const listaAg = $("#ag-lista");
  if (listaAg) listaAg.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-ag]");
    if (!b) return;
    const id = b.dataset.id, acao = b.dataset.ag;
    try {
      if (acao === "remover") {
        if (!confirm("Remover este agendamento?")) return;
        await api("DELETE", `agendamentos/${id}`);
      } else if (acao === "senha") {
        const senha = prompt("Senha do equipamento para este agendamento (fica só na memória):");
        if (!senha) return;
        await api("POST", `agendamentos/${id}/senha`, { senha });
        aviso("Senha registrada; o agendamento está ativo");
      } else if (acao === "executar") {
        const job = await api("POST", `agendamentos/${id}/executar`, {});
        location.hash = "#/execucoes/" + job.id;
        return;
      } else {
        await api("POST", `agendamentos/${id}/${acao}`, {});
      }
      vAgendamentos();
    } catch (err) { aviso(err.message, true); }
  });

  const f = $("#f-ag");
  if (!f) return;
  $("#ag-tipo").addEventListener("change", (e) => {
    const horas = e.target.value === "horas";
    const v = $("#ag-valor");
    v.type = horas ? "number" : "time";
    v.value = horas ? "6" : "03:00";
    if (horas) { v.min = "1"; v.max = "720"; } else { v.removeAttribute("min"); v.removeAttribute("max"); }
    $("#ag-valor-rotulo").textContent = horas ? "Intervalo em horas" : "Horário";
  });
  f.addEventListener("change", (e) => {
    if (e.target.name === "protocolo") {
      const porta = $("#porta");
      if (porta.value === "22" || porta.value === "23") porta.value = e.target.value === "telnet" ? "23" : "22";
    }
  });
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(f);
    const dados = Object.fromEntries(fd.entries());
    dados.instancias = Number(dados.instancias);
    dados.porta = Number(dados.porta);
    dados.sensivel = false;
    try {
      await api("POST", "agendamentos", dados);
      aviso("Agendamento criado");
      vAgendamentos();
    } catch (err) { aviso(err.message, true); }
  });
}

/* ------------------------------------------------------------ eventos globais */
document.addEventListener("click", (e) => {
  const baixa = e.target.closest("[data-baixar]");
  if (baixa) { e.preventDefault(); baixar(baixa.dataset.baixar, baixa.dataset.nome); return; }
  if (e.target.closest("a, button, input, select, textarea, summary")) return;
  const tr = e.target.closest("[data-ir]");
  if (tr) location.hash = tr.dataset.ir;
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const tr = e.target.closest && e.target.closest("[data-ir]");
  if (tr) location.hash = tr.dataset.ir;
});

async function iniciar() {
  const m = location.hash.match(/[#&]t=([\w-]+)/);
  if (m) {
    S.token = m[1];
    guardar("token", S.token);
    history.replaceState(null, "", location.pathname + "#/painel");
  } else {
    S.token = ler("token");
  }
  if (!S.token) return semToken();
  try {
    S.info = await api("GET", "info");
  } catch (e) {
    if (e.status === 401) guardar("token", "");
    return e.status === 401 ? semToken() : tela(`<h1>Painel inacessível</h1><p class="erro-campo">${esc(e.message)}</p>`);
  }
  const c = S.info.capacidades;
  $("#rodape").innerHTML = `painel ${esc(S.info.versao)}${c.netsnap ? ` · netsnap ${esc(c.netsnap)}` : ""}<br>${c.coleta ? "coleta disponível" : "modo consulta"}`;
  window.addEventListener("hashchange", rotear);
  rotear();
}

iniciar();
