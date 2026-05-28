/**
 * PIT Chile Looking Glass - Frontend JS v2
 * Herramientas: BGP, Whois, RPKI, DNS, Prefix Info
 * Toda la config desde /api/config - nada embebido.
 */

"use strict";

const state = { config: null, lastOutput: null, currentTool: "bgp" };

const FLAGS = { Chile:"", Mexico:"", Argentina:"", Peru:"", Global:"" };

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
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.config = await res.json();
    applyConfig();
  } catch (e) {
    setStatus("Error cargando config: " + e.message, "error", "query-status");
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

  const servers  = cfg.route_servers;
  const countries = [...new Set(servers.map(s => s.group))].filter(g => g !== "Global");
  setEl("stat-servers",   servers.length);
  setEl("stat-countries", countries.length);

  populateServerSelect(servers);
  populateCommandSelect(cfg.commands);
  populateServersTable(servers);
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
      <td>${escHtml(s.name)}</td>
      <td><span class="badge-group">${escHtml(s.group)}</span></td>
      <td class="td-host">${escHtml(s.host)}</td>
      <td><span class="td-type">${escHtml(s.type)}</span></td>
      <td class="td-note">${escHtml(s.note || "")}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------------------------------------------------------------------------
// Tool tabs
// ---------------------------------------------------------------------------

function switchTool(name) {
  state.currentTool = name;
  document.querySelectorAll(".tool-panel").forEach(p => p.style.display = "none");
  const panel = document.getElementById("panel-" + name);
  if (panel) panel.style.display = "block";
  document.querySelectorAll(".tool-tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tool === name);
  });
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

function setupListeners() {
  // BGP examples -> inp-bgp
  document.querySelectorAll("#panel-bgp .qe-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.getElementById("inp-bgp").value = btn.dataset.val;
    });
  });

  // Tool examples -> corresponding input
  document.querySelectorAll(".qe-btn.tool-ex").forEach(btn => {
    btn.addEventListener("click", () => {
      const tool = btn.dataset.tool;
      const val  = btn.dataset.val;
      const asn  = btn.dataset.asn || "";
      const inputMap = {
        whois:       "inp-whois",
        dns:         "inp-dns",
        prefix_info: "inp-prefix",
        rpki:        "inp-rpki-prefix",
      };
      const inp = document.getElementById(inputMap[tool]);
      if (inp) inp.value = val;
      if (tool === "rpki" && asn) {
        const asnInp = document.getElementById("inp-rpki-asn");
        if (asnInp) asnInp.value = asn;
      }
    });
  });

  // Enter en cualquier input
  ["inp-bgp","inp-whois","inp-dns","inp-prefix","inp-rpki-prefix","inp-rpki-asn"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("keydown", e => { if (e.key === "Enter") dispatchEnter(); });
  });
}

function dispatchEnter() {
  const t = state.currentTool;
  if (t === "bgp")         runBGP();
  else if (t === "whois")  runTool("whois", "inp-whois");
  else if (t === "dns")    runTool("dns", "inp-dns");
  else if (t === "rpki")   runRPKI();
  else if (t === "prefix_info") runTool("prefix_info", "inp-prefix");
}

function onServerChange() {
  const id  = document.getElementById("sel-server").value;
  const rs  = state.config?.route_servers?.find(s => s.id === id);
  setEl("server-hint", rs ? (rs.note || rs.host) : "");
}

function onCommandChange() {
  const key = document.getElementById("sel-command").value;
  const cmd = state.config?.commands?.[key];
  if (!cmd) return;
  setEl("cmd-hint", cmd.description || "");
  setEl("bgp-query-label", cmd.input_label || "Target");
  const inp = document.getElementById("inp-bgp");
  inp.placeholder = cmd.input_placeholder || "";
  const grp = document.getElementById("bgp-query-group");
  const qe  = document.getElementById("quick-examples");
  grp.style.visibility = cmd.no_input ? "hidden" : "visible";
  if (qe) qe.style.display = ["bgp_route","bgp_aspath","bgp_route_v6"].includes(key) ? "flex" : "none";
}

// ---------------------------------------------------------------------------
// BGP query
// ---------------------------------------------------------------------------

async function runBGP() {
  const rsId  = document.getElementById("sel-server").value;
  const cmd   = document.getElementById("sel-command").value;
  const query = document.getElementById("inp-bgp").value.trim();
  const cmdCfg = state.config?.commands?.[cmd];

  if (!rsId)                         { setStatus("Selecciona un route server", "error", "query-status"); return; }
  if (!cmd)                          { setStatus("Selecciona un comando",       "error", "query-status"); return; }
  if (!cmdCfg?.no_input && !query)   { setStatus("Ingresa el target",           "error", "query-status"); return; }

  setBtnLoading("btn-bgp", true, "Ejecutando...");
  setStatus("Conectando al route server...", "loading", "query-status");

  try {
    const res = await fetch("/api/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ route_server_id: rsId, command: cmd, query }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", "query-status"); return; }
    showOutput(data, "BGP", data.route_server);
    setStatus("Completado en " + data.elapsed_s + "s", "ok", "query-status");
  } catch (e) {
    setStatus("Error de red: " + e.message, "error", "query-status");
  } finally {
    setBtnLoading("btn-bgp", false, "Ejecutar Query");
  }
}

// ---------------------------------------------------------------------------
// Generic tool
// ---------------------------------------------------------------------------

async function runTool(tool, inputId) {
  const query = document.getElementById(inputId)?.value.trim();
  const statusId = { whois:"query-status-whois", dns:"query-status-dns",
                     prefix_info:"query-status-prefix" }[tool] || "query-status";
  if (!query) { setStatus("Ingresa un valor", "error", statusId); return; }

  setStatus("Ejecutando " + tool + "...", "loading", statusId);

  try {
    const res = await fetch("/api/tool", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool, query }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", statusId); return; }

    const labels = { whois:"WHOIS", dns:"DNS", prefix_info:"PREFIX INFO" };
    showOutput(data, labels[tool] || tool.toUpperCase(), query);
    setStatus("Completado en " + data.elapsed_s + "s", "ok", statusId);
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
  const statusId = "query-status-rpki";

  if (!prefix) { setStatus("Ingresa un prefijo", "error", statusId); return; }
  if (!prefix.includes("/")) { setStatus("Prefijo debe incluir mascara Ej: 45.68.16.0/22", "error", statusId); return; }

  setStatus("Consultando RPKI...", "loading", statusId);

  try {
    const res = await fetch("/api/tool", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool: "rpki", query: prefix, asn }),
    });
    const data = await res.json();
    if (!res.ok) { setStatus("Error: " + (data.detail || res.statusText), "error", statusId); return; }

    showOutput(data, "RPKI", prefix);

    // Badge de estado
    const badge = document.getElementById("rpki-badge");
    const state_val = (data.state || "unknown").toLowerCase();
    badge.style.display = "block";
    badge.textContent = state_val.toUpperCase();
    badge.className = "rpki-badge " + (
      state_val.includes("valid") && !state_val.includes("invalid") ? "valid" :
      state_val.includes("invalid") ? "invalid" : "notfound"
    );

    setStatus("Completado en " + data.elapsed_s + "s", "ok", statusId);
  } catch (e) {
    setStatus("Error de red: " + e.message, "error", statusId);
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function showOutput(data, toolLabel, title) {
  state.lastOutput = data;
  const panel  = document.getElementById("output-panel");
  const pre    = document.getElementById("output-pre");
  const ttl    = document.getElementById("output-title");
  const meta   = document.getElementById("output-meta");
  const tag    = document.getElementById("output-tool-tag");
  const badge  = document.getElementById("rpki-badge");

  panel.style.display = "block";
  tag.textContent     = toolLabel;
  ttl.textContent     = title;
  if (badge && toolLabel !== "RPKI") badge.style.display = "none";

  const ts = new Date(data.timestamp).toLocaleString("es-CL", { timeZone: "America/Santiago" });
  const n  = (data.output || "").split("\n").length;
  meta.textContent = `${ts}  |  ${data.elapsed_s}s  |  ${n} lineas`;

  pre.innerHTML = highlightOutput(data.output || "(sin output)", toolLabel);
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------------------------------------------------------------------------
// Highlight
// ---------------------------------------------------------------------------

function highlightOutput(text, tool) {
  let out = escHtml(text);

  if (["BGP","WHOIS","RPKI"].includes(tool)) {
    // IPs y prefijos
    out = out.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g,
      '<span style="color:#89b4fa">$1</span>');
    // ASNs
    out = out.replace(/\b(AS\d+|\bASN?\s*\d+)\b/g,
      '<span style="color:#cba6f7">$1</span>');
    // BGP best route marker
    out = out.replace(/^(\s*\*&gt;\s)/gm,
      '<span style="color:#a6e3a1">$1</span>');
    out = out.replace(/^(\s*\*\s)/gm,
      '<span style="color:#fab387">$1</span>');
    // Keywords
    out = out.replace(/\b(Network|Next Hop|Metric|LocPrf|Weight|Path|Origin|via|from|Established|Active|Idle)\b/g,
      '<span style="color:#f9e2af">$1</span>');
  }

  if (tool === "RPKI") {
    out = out.replace(/\bVALID\b/g,     '<span style="color:#a6e3a1;font-weight:700">VALID</span>');
    out = out.replace(/\bINVALID\b/g,   '<span style="color:#f38ba8;font-weight:700">INVALID</span>');
    out = out.replace(/\bNOT.FOUND\b/g, '<span style="color:#f9e2af;font-weight:700">NOT FOUND</span>');
  }

  if (tool === "DNS") {
    out = out.replace(/\b(A\s{3}|AAAA|PTR)\s*:/g,
      '<span style="color:#89dceb;font-weight:600">$1</span>:');
  }

  if (tool === "PREFIX INFO") {
    out = out.replace(/^([A-Za-z ]+)\s*:/gm,
      '<span style="color:#cba6f7">$1</span>:');
    out = out.replace(/\b(True|False)\b/g,
      m => m === "True" ? '<span style="color:#a6e3a1">True</span>'
                        : '<span style="color:#f38ba8">False</span>');
  }

  return out;
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------

function copyOutput() {
  navigator.clipboard.writeText(document.getElementById("output-pre").textContent || "")
    .then(() => setStatus("Copiado", "ok", "query-status"))
    .catch(() => setStatus("Error al copiar", "error", "query-status"));
}

function downloadOutput() {
  const d = state.lastOutput;
  if (!d) return;
  const ts    = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob  = new Blob([
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

function clearOutput() {
  const panel = document.getElementById("output-panel");
  panel.style.display = "none";
  document.getElementById("output-pre").innerHTML = "";
  state.lastOutput = null;
  document.querySelectorAll(".query-status").forEach(el => {
    el.textContent = ""; el.className = "query-status";
  });
  const badge = document.getElementById("rpki-badge");
  if (badge) badge.style.display = "none";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setStatus(msg, cls, id) {
  const el = document.getElementById(id || "query-status");
  if (!el) return;
  el.textContent = msg;
  el.className = "query-status" + (cls ? " " + cls : "");
}

function setBtnLoading(btnId, loading, label) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = label;
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
