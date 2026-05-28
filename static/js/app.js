/**
 * PIT Chile Looking Glass - Frontend JS v2.2
 * Ejemplos dinamicos por comando. Config desde /api/config.
 */

"use strict";

const state = { config: null, lastOutput: null, currentTool: "bgp", rawVisible: false };

// ---------------------------------------------------------------------------
// Ejemplos por comando - separados por tipo de input
// Prefijos: para bgp_route, bgp_route_v6, prefix_info, rpki, whois
// ASNs:     para bgp_aspath, whois
// Hosts:    para dns, ping, traceroute
// ---------------------------------------------------------------------------

const EXAMPLES = {
  // BGP Route (prefijos globalmente visibles)
  bgp_route: [
    { val: "1.1.1.0/24",       tip: "Cloudflare DNS (AS13335)" },
    { val: "8.8.8.0/24",       tip: "Google DNS (AS15169)" },
    { val: "208.67.222.0/24",  tip: "OpenDNS (AS36692)" },
    { val: "190.10.24.0/24",   tip: "Telefonica Chile (AS22927)" },
    { val: "200.1.193.0/24",   tip: "Entel Chile (AS7418)" },
    { val: "181.41.0.0/18",    tip: "GTD Chile (AS14259)" },
    { val: "190.160.0.0/14",   tip: "Movistar Chile (AS22927)" },
    { val: "200.75.0.0/16",    tip: "Telecom Argentina (AS7303)" },
    { val: "187.174.0.0/15",   tip: "TELMEX Mexico (AS8151)" },
    { val: "200.48.0.0/13",    tip: "Telefonica Peru (AS6147)" },
  ],
  // BGP Route IPv6
  bgp_route_v6: [
    { val: "2606:4700::/32",   tip: "Cloudflare (AS13335)" },
    { val: "2001:4860::/32",   tip: "Google (AS15169)" },
    { val: "2800:3f0::/32",    tip: "Google LATAM (AS15169)" },
    { val: "2801:14:9000::/48",tip: "PIT Chile SCL IPv6 (AS61522)" },
    { val: "2803:3440::/32",   tip: "PIT Mexico IPv6 (AS61525)" },
  ],
  // BGP AS Path (solo ASNs)
  bgp_aspath: [
    { val: "61522",  tip: "RS PIT Chile Santiago" },
    { val: "61525",  tip: "RS PIT Mexico Queretaro" },
    { val: "61523",  tip: "RS PIT Argentina BUE" },
    { val: "64115",  tip: "RS PIT Peru Lima" },
    { val: "22927",  tip: "Telefonica Chile / Movistar" },
    { val: "7418",   tip: "Entel Chile" },
    { val: "14259",  tip: "GTD Chile" },
    { val: "7303",   tip: "Telecom Argentina" },
    { val: "6147",   tip: "Telefonica Peru / Movistar" },
    { val: "8151",   tip: "TELMEX Mexico" },
    { val: "13335",  tip: "Cloudflare" },
    { val: "15169",  tip: "Google" },
  ],
  // BGP Summary - sin input
  bgp_summary:    [],
  bgp_summary_v6: [],
  // Ping/Traceroute
  ping: [
    { val: "8.8.8.8",         tip: "Google DNS" },
    { val: "1.1.1.1",         tip: "Cloudflare DNS" },
    { val: "45.68.16.1",      tip: "PIT Chile SCL RS1" },
    { val: "200.23.206.1",    tip: "PIT Mexico RS1" },
    { val: "pitchile.cl",     tip: "Sitio web PIT Chile" },
  ],
  traceroute: [
    { val: "8.8.8.8",         tip: "Google DNS" },
    { val: "1.1.1.1",         tip: "Cloudflare DNS" },
    { val: "45.68.16.1",      tip: "PIT Chile SCL RS1" },
    { val: "200.23.206.1",    tip: "PIT Mexico RS1" },
    { val: "pitchile.cl",     tip: "Sitio web PIT Chile" },
  ],
};

// Ejemplos para otras herramientas (no BGP)
const TOOL_EXAMPLES = {
  whois: [
    { val: "AS61522",         tip: "RS PIT Chile Santiago" },
    { val: "AS61525",         tip: "RS PIT Mexico" },
    { val: "AS64115",         tip: "RS PIT Peru Lima" },
    { val: "AS61523",         tip: "RS PIT Argentina" },
    { val: "45.68.16.0/22",   tip: "PIT Chile SCL LAN peering" },
    { val: "45.68.44.0/24",   tip: "PIT Argentina BUE LAN" },
    { val: "45.183.47.0/24",  tip: "PIT Peru LIM LAN" },
    { val: "200.23.206.0/24", tip: "PIT Mexico QRO LAN" },
    { val: "AS22927",         tip: "Telefonica Chile" },
    { val: "AS7418",          tip: "Entel Chile" },
    { val: "AS7303",          tip: "Telecom Argentina" },
    { val: "AS6147",          tip: "Telefonica Peru" },
  ],
  rpki: [
    { val: "1.1.1.0/24",      asn: "13335",  tip: "Cloudflare - VALID" },
    { val: "8.8.8.0/24",      asn: "15169",  tip: "Google DNS - VALID" },
    { val: "208.67.222.0/24", asn: "36692",  tip: "OpenDNS - VALID" },
    { val: "190.10.24.0/24",  asn: "22927",  tip: "Telefonica Chile" },
    { val: "200.1.193.0/24",  asn: "7418",   tip: "Entel Chile" },
    { val: "181.41.0.0/18",   asn: "14259",  tip: "GTD Chile" },
    { val: "200.75.0.0/16",   asn: "7303",   tip: "Telecom Argentina" },
    { val: "187.174.0.0/15",  asn: "8151",   tip: "TELMEX Mexico" },
  ],
  dns: [
    { val: "pitchile.cl",              tip: "Sitio web PIT Chile" },
    { val: "speedtest.pitchile.cl",    tip: "Speedtest PIT Chile" },
    { val: "pit.scl.routeviews.org",   tip: "RouteViews PIT Santiago" },
    { val: "pitmx.qro.routeviews.org", tip: "RouteViews PIT Mexico" },
    { val: "45.68.16.1",               tip: "PIT SCL RS1 - PTR" },
    { val: "200.23.206.1",             tip: "PIT MX RS1 - PTR" },
    { val: "8.8.8.8",                  tip: "Google DNS - PTR" },
  ],
  prefix_info: [
    { val: "45.68.16.0/22",      tip: "PIT Chile SCL LAN peering" },
    { val: "45.68.44.0/24",      tip: "PIT Argentina BUE LAN" },
    { val: "45.183.47.0/24",     tip: "PIT Peru LIM LAN" },
    { val: "200.23.206.0/24",    tip: "PIT Mexico QRO LAN" },
    { val: "2801:14:9000::/48",  tip: "PIT Chile SCL IPv6" },
    { val: "2803:3440:9025::/48",tip: "PIT Mexico IPv6" },
    { val: "2803:cd60:6411::/48",tip: "PIT Peru IPv6" },
    { val: "10.0.0.0/8",         tip: "RFC1918 privado" },
  ],
};

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  await loadConfig();
  setupListeners();
});

async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    if (!res.ok) throw new Error("HTTP " + res.status);
    state.config = await res.json();
    applyConfig();
  } catch (e) {
    setStatus("Error cargando config: " + e.message, "error", "status-bgp");
  }
}

function applyConfig() {
  const cfg = state.config;
  if (!cfg) return;
  document.title = cfg.title;
  const d = document.getElementById("page-desc");
  if (d) d.textContent = cfg.description;
  const fc = document.getElementById("footer-contact");
  if (fc) fc.href = "mailto:" + cfg.contact;

  const servers   = cfg.route_servers;
  const countries = [...new Set(servers.map(s => s.group))].filter(g => g !== "Global");
  setEl("stat-servers",   servers.length);
  setEl("stat-countries", countries.length);

  populateServerSelect(servers);
  populateCommandSelect(cfg.commands);
  populateServersTable(servers);
  populateToolExamples();
}

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

function populateServerSelect(servers) {
  const sel = document.getElementById("sel-server");
  sel.innerHTML = "";
  const groups = {};
  servers.forEach(s => { if (!groups[s.group]) groups[s.group] = []; groups[s.group].push(s); });
  Object.entries(groups).forEach(([group, list]) => {
    const og = document.createElement("optgroup");
    og.label = group;
    list.forEach(s => {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = s.name;
      og.appendChild(opt);
    });
    sel.appendChild(og);
  });
  sel.addEventListener("change", onServerChange);
  onServerChange();
}

function populateCommandSelect(commands) {
  const sel = document.getElementById("sel-command");
  sel.innerHTML = "";
  Object.entries(commands).forEach(([key, cmd]) => {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = cmd.label;
    sel.appendChild(opt);
  });
  sel.addEventListener("change", onCommandChange);
  onCommandChange();
}

function populateServersTable(servers) {
  const tbody = document.getElementById("servers-tbody");
  tbody.innerHTML = "";
  servers.forEach(s => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(s.name)}</td>
      <td>${esc(s.group)}</td>
      <td class="td-host">${esc(s.host)}</td>
      <td><span class="td-type">${esc(s.type)}</span></td>
      <td class="td-note">${esc(s.note || "")}</td>`;
    tbody.appendChild(tr);
  });
}

// Poblar ejemplos de herramientas (whois, rpki, dns, prefix_info)
function populateToolExamples() {
  Object.entries(TOOL_EXAMPLES).forEach(([tool, items]) => {
    const container = document.getElementById("ex-" + tool);
    if (!container || !items.length) return;
    container.innerHTML = '<span class="qe-label">Ejemplos:</span>';
    items.forEach(item => {
      const btn = document.createElement("button");
      btn.className = "qe-btn";
      btn.textContent = item.val;
      btn.title = item.tip || item.val;
      btn.addEventListener("click", () => {
        if (tool === "rpki") {
          const p = document.getElementById("inp-rpki-prefix");
          const a = document.getElementById("inp-rpki-asn");
          if (p) p.value = item.val;
          if (a) a.value = item.asn || "";
        } else {
          const inputMap = { whois:"inp-whois", dns:"inp-dns", prefix_info:"inp-prefix" };
          const inp = document.getElementById(inputMap[tool]);
          if (inp) inp.value = item.val;
        }
      });
      container.appendChild(btn);
    });
  });
}

// Actualizar ejemplos BGP segun comando seleccionado
function updateBGPExamples(cmdKey) {
  const container = document.getElementById("quick-examples");
  if (!container) return;

  const items = EXAMPLES[cmdKey] || [];
  container.innerHTML = "";

  if (!items.length) {
    container.style.display = "none";
    return;
  }

  container.style.display = "flex";
  const label = document.createElement("span");
  label.className = "qe-label";
  label.textContent = "Ejemplos:";
  container.appendChild(label);

  items.forEach(item => {
    const btn = document.createElement("button");
    btn.className = "qe-btn";
    btn.textContent = item.val;
    btn.title = item.tip || item.val;
    btn.addEventListener("click", () => {
      const inp = document.getElementById("inp-bgp");
      if (inp) { inp.value = item.val; inp.focus(); }
    });
    container.appendChild(btn);
  });
}

// ---------------------------------------------------------------------------
// Tool tabs
// ---------------------------------------------------------------------------

function switchTool(name) {
  state.currentTool = name;
  clearOutput();
  document.querySelectorAll(".tool-panel").forEach(p => p.style.display = "none");
  const panel = document.getElementById("panel-" + name);
  if (panel) panel.style.display = "block";
  document.querySelectorAll(".tool-tab").forEach(btn =>
    btn.classList.toggle("active", btn.dataset.tool === name));
  if (name === "latam") loadLatamIXPs();
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

function setupListeners() {
  const enterMap = {
    "inp-bgp":         () => runBGP(),
    "inp-whois":       () => runTool("whois",       "inp-whois",  "status-whois"),
    "inp-dns":         () => runTool("dns",          "inp-dns",    "status-dns"),
    "inp-prefix":      () => runTool("prefix_info",  "inp-prefix", "status-prefix"),
    "inp-rpki-prefix": () => runRPKI(),
    "inp-rpki-asn":    () => runRPKI(),
  };
  Object.entries(enterMap).forEach(([id, fn]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("keydown", e => { if (e.key === "Enter") fn(); });
  });
}

function onServerChange() {
  const id = document.getElementById("sel-server").value;
  const rs = state.config?.route_servers?.find(s => s.id === id);
  setEl("server-hint", rs ? (rs.note || rs.host) : "");
}

function onCommandChange() {
  const key = document.getElementById("sel-command").value;
  const cmd = state.config?.commands?.[key];
  if (!cmd) return;

  setEl("cmd-hint", cmd.description || "");
  setEl("bgp-query-label", cmd.input_label || "Target");

  const inp = document.getElementById("inp-bgp");
  if (inp) inp.placeholder = cmd.input_placeholder || "";

  const grp = document.getElementById("bgp-query-group");
  if (grp) grp.style.visibility = cmd.no_input ? "hidden" : "visible";

  // Actualizar ejemplos segun comando
  updateBGPExamples(key);
}

// ---------------------------------------------------------------------------
// BGP
// ---------------------------------------------------------------------------

async function runBGP() {
  const rsId   = document.getElementById("sel-server").value;
  const cmd    = document.getElementById("sel-command").value;
  const query  = document.getElementById("inp-bgp").value.trim();
  const cmdCfg = state.config?.commands?.[cmd];
  const sid    = "status-bgp";

  if (!rsId)                       { setStatus("Selecciona un route server", "error", sid); return; }
  if (!cmd)                        { setStatus("Selecciona un comando",       "error", sid); return; }
  if (!cmdCfg?.no_input && !query) { setStatus("Ingresa el target",           "error", sid); return; }

  setBusy("btn-bgp", true);
  setStatus("Conectando...", "loading", sid);
  clearOutputOnly();

  try {
    const res  = await fetch("/api/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ route_server_id: rsId, command: cmd, query }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", sid); return; }
    showOutput(data, "BGP", data.route_server || rsId);
    setStatus("OK - " + data.elapsed_s + "s", "ok", sid);
  } catch (e) {
    setStatus("Error de red: " + e.message, "error", sid);
  } finally {
    setBusy("btn-bgp", false);
  }
}

// ---------------------------------------------------------------------------
// Tool generico
// ---------------------------------------------------------------------------

async function runTool(tool, inputId, statusId) {
  const query = document.getElementById(inputId)?.value.trim();
  if (!query) { setStatus("Ingresa un valor", "error", statusId); return; }

  setStatus("Ejecutando...", "loading", statusId);
  clearOutputOnly();

  try {
    const res  = await fetch("/api/tool", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool, query }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", statusId); return; }
    const labels = { whois:"WHOIS", dns:"DNS", prefix_info:"PREFIX INFO" };
    showOutput(data, labels[tool] || tool.toUpperCase(), query);
    setStatus("OK - " + data.elapsed_s + "s", "ok", statusId);
  } catch (e) {
    setStatus("Error de red: " + e.message, "error", statusId);
  }
}

// ---------------------------------------------------------------------------
// RPKI
// ---------------------------------------------------------------------------

async function runRPKI() {
  const prefix = document.getElementById("inp-rpki-prefix")?.value.trim();
  const asn    = document.getElementById("inp-rpki-asn")?.value.trim().replace(/^AS/i, "");
  const sid    = "status-rpki";

  if (!prefix) { setStatus("Ingresa un prefijo", "error", sid); return; }
  if (!prefix.includes("/")) { setStatus("Incluye la mascara. Ej: 1.1.1.0/24", "error", sid); return; }

  setStatus("Consultando RPKI...", "loading", sid);
  clearOutputOnly();

  try {
    const res  = await fetch("/api/tool", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool: "rpki", query: prefix, asn }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", sid); return; }

    showOutput(data, "RPKI", prefix);

    const badge = document.getElementById("rpki-badge");
    const sv = (data.state || "unknown").toLowerCase();
    badge.style.display = "block";
    badge.textContent   = sv.toUpperCase().replace("_", " ");
    badge.className     = "rpki-badge " + (
      sv === "valid"   ? "valid"    :
      sv === "invalid" ? "invalid"  : "notfound");

    setStatus("OK - " + data.elapsed_s + "s", "ok", sid);
  } catch (e) {
    setStatus("Error de red: " + e.message, "error", sid);
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function showOutput(data, toolLabel, title) {
  state.lastOutput = data;
  state.rawVisible = false;

  const panel  = document.getElementById("output-panel");
  const pre    = document.getElementById("output-pre");
  const rawBox = document.getElementById("raw-box");
  const btnRaw = document.getElementById("btn-raw");

  panel.style.display = "block";
  setEl("output-tool-tag", toolLabel);
  setEl("output-title", title);

  if (toolLabel !== "RPKI") {
    const badge = document.getElementById("rpki-badge");
    if (badge) badge.style.display = "none";
  }

  const ts = new Date(data.timestamp).toLocaleString("es-CL", { timeZone: "America/Santiago" });
  const n  = (data.output || "").split("\n").length;
  setEl("output-meta", ts + "  |  " + data.elapsed_s + "s  |  " + n + " lineas");

  pre.innerHTML        = highlight(data.output || "(sin output)", toolLabel);
  rawBox.style.display = "none";
  rawBox.textContent   = data.output || "";
  if (btnRaw) btnRaw.textContent = "Ver texto";

  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function toggleRaw() {
  state.rawVisible = !state.rawVisible;
  const rawBox = document.getElementById("raw-box");
  const btnRaw = document.getElementById("btn-raw");
  rawBox.style.display = state.rawVisible ? "block" : "none";
  if (btnRaw) btnRaw.textContent = state.rawVisible ? "Ocultar texto" : "Ver texto";
}

// ---------------------------------------------------------------------------
// Highlight
// ---------------------------------------------------------------------------

function highlight(text, tool) {
  let out = esc(text);
  out = out.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g,
    '<span style="color:#89b4fa">$1</span>');
  out = out.replace(/\b(AS\d+)\b/g, '<span style="color:#cba6f7">$1</span>');

  if (tool === "BGP") {
    out = out.replace(/^(\s*\*&gt;\s)/gm, '<span style="color:#a6e3a1">$1</span>');
    out = out.replace(/^(\s*\*\s)/gm,     '<span style="color:#fab387">$1</span>');
    out = out.replace(/\b(Network|Next Hop|Metric|LocPrf|Weight|Path|Origin|via|from|Established|Active|Idle)\b/g,
      '<span style="color:#f9e2af">$1</span>');
  }
  if (tool === "RPKI") {
    out = out.replace(/\bVALID\b/g,     '<span style="color:#a6e3a1;font-weight:700">VALID</span>');
    out = out.replace(/\bINVALID\b/g,   '<span style="color:#f38ba8;font-weight:700">INVALID</span>');
    out = out.replace(/\bNOT.FOUND\b/g, '<span style="color:#f9e2af;font-weight:700">NOT FOUND</span>');
    out = out.replace(/\bUNKNOWN\b/g,   '<span style="color:#a6adc8;font-weight:700">UNKNOWN</span>');
  }
  if (tool === "DNS") {
    out = out.replace(/(A\s{3,}|AAAA\s*|PTR\s*)(:)/g,
      '<span style="color:#89dceb;font-weight:600">$1</span>$2');
  }
  if (tool === "PREFIX INFO") {
    out = out.replace(/^([A-Za-z /]+?)\s*(:)/gm, '<span style="color:#cba6f7">$1</span>$2');
    out = out.replace(/\b(True)\b/g,  '<span style="color:#a6e3a1">True</span>');
    out = out.replace(/\b(False)\b/g, '<span style="color:#f38ba8">False</span>');
  }
  if (tool === "WHOIS") {
    out = out.replace(/^(%.*)/gm, '<span style="color:#6c7086">$1</span>');
    out = out.replace(/^([a-zA-Z\-]+)(\s*:)/gm, '<span style="color:#89dceb">$1</span>$2');
  }
  return out;
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------

function copyOutput() {
  navigator.clipboard.writeText(document.getElementById("output-pre").textContent || "")
    .then(() => setStatus("Copiado", "ok", "status-bgp"))
    .catch(() => setStatus("Error al copiar", "error", "status-bgp"));
}

function downloadOutput() {
  const d = state.lastOutput;
  if (!d) return;
  const ts   = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob = new Blob([
    "# PIT Chile Looking Glass\n",
    "# Query     : " + (d.query || d.command || "") + "\n",
    "# Timestamp : " + d.timestamp + "\n",
    "# Elapsed   : " + d.elapsed_s + "s\n#\n",
    d.output || "",
  ], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "pit-lg_" + ts + ".txt";
  a.click();
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

function clearOutputOnly() {
  state.lastOutput = null;
  state.rawVisible = false;
  const pre    = document.getElementById("output-pre");
  const raw    = document.getElementById("raw-box");
  const btnRaw = document.getElementById("btn-raw");
  const badge  = document.getElementById("rpki-badge");
  if (pre)    pre.innerHTML = "";
  if (raw)    { raw.style.display = "none"; raw.textContent = ""; }
  if (btnRaw) btnRaw.textContent = "Ver texto";
  if (badge)  badge.style.display = "none";
  document.getElementById("output-panel").style.display = "none";
}

function clearOutput() {
  clearOutputOnly();
  document.querySelectorAll(".query-status").forEach(el => {
    el.textContent = ""; el.className = "query-status";
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setStatus(msg, cls, id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className   = "query-status" + (cls ? " " + cls : "");
}

function setBusy(btnId, busy) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled    = busy;
  btn.textContent = busy ? "Ejecutando..." : "Ejecutar Query";
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function esc(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ---------------------------------------------------------------------------
// LATAM IXP Ranking
// ---------------------------------------------------------------------------

let latamLoaded = false;

async function loadLatamIXPs() {
  if (latamLoaded) return;
  const tbody  = document.getElementById("latam-tbody");
  const status = document.getElementById("latam-status");

  try {
    if (status) status.textContent = "Consultando PeeringDB API...";
    const res  = await fetch("/api/latam-ixps");
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.detail || "Error API");

    const ixps = data.ixps;
    const maxM = Math.max(...ixps.map(d => d.members || 0)) || 1;

    tbody.innerHTML = "";
    ixps.forEach((ixp, i) => {
      const tr   = document.createElement("tr");
      const isPit = ixp.pit;
      if (isPit) tr.className = "pit-ixp-row";

      const barW   = Math.round(((ixp.members || 0) / maxM) * 100);
      const barClr = isPit ? "#F37021" : "#378ADD";
      const badge  = isPit ? '<span class="ixp-badge">PIT</span>' : "";
      const noData = !ixp.members ? '<span style="font-size:11px;color:#bbb;">sin datos</span>' : "";

      tr.innerHTML = `
        <td class="rank-num">${i + 1}</td>
        <td>
          <div class="ixp-name">
            <a href="${esc(ixp.pdb_url)}" target="_blank"
               style="color:inherit;text-decoration:none;">${esc(ixp.name)}</a>${badge}
          </div>
        </td>
        <td style="font-size:12px;">${esc(ixp.country_name || ixp.country)}</td>
        <td style="font-size:12px;color:#666;">${esc(ixp.city || "")}</td>
        <td style="text-align:right;font-variant-numeric:tabular-nums;font-size:13px;">
          ${ixp.members ? ixp.members.toLocaleString("es-CL") : noData}
        </td>
        <td>
          <div class="bar-cell">
            <div class="bar-track">
              <div class="bar-fill" style="width:${barW}%;background:${barClr};"></div>
            </div>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });

    if (status) status.textContent =
      `${ixps.length} IXPs · Fuente: PeeringDB API · ${new Date().toLocaleString("es-CL", {timeZone:"America/Santiago"})}`;

    latamLoaded = true;

  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="loading-cell" style="color:#c62828;">Error cargando datos: ${esc(e.message)}</td></tr>`;
    if (status) status.textContent = "Error consultando PeeringDB";
  }
}
