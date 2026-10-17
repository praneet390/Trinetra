// Dashboard frontend: polls the stdlib JSON API in web_server.py and
// renders stat tiles, charts, and tables. Deliberately uses textContent
// (never innerHTML) for anything derived from a detection message, process
// name, or file hash - those can legitimately contain attacker-controlled
// strings (e.g. a malicious CommandLine), so treat them as data, not markup.

const POLL_MS = 2000;
const COLORS = { critical: "#b5432f", warning: "#a97a1f", info: "#5c6570", accent: "#4a7fb5" };
const CATEGORY_PALETTE = ["#4a7fb5", "#b5432f", "#a97a1f", "#5c6570", "#6f6ba0", "#3f7d5c", "#8a6a3f"];
const AXIS_COLOR = "#838b96";
const LEGEND_COLOR = "#d8dade";

let lastAlerts = [];
let lastActivity = [];
let charts = {};

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function el(tag, opts = {}) {
  const node = document.createElement(tag);
  if (opts.text !== undefined) node.textContent = opts.text;
  if (opts.className) node.className = opts.className;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function emptyRow(colSpan, label) {
  const tr = el("tr", { className: "empty-row" });
  const td = el("td", { text: label });
  td.colSpan = colSpan;
  tr.appendChild(td);
  return tr;
}

// ---- masthead --------------------------------------------------------
function formatTimestamp(epochSeconds) {
  if (!epochSeconds) return "—";
  return new Date(epochSeconds * 1000).toLocaleString();
}

function renderMasthead(summary) {
  document.getElementById("metaHost").textContent = summary.hostname || "—";
  document.getElementById("metaSessionStart").textContent = formatTimestamp(summary.session_start);
  document.getElementById("metaReportTime").textContent = new Date().toLocaleString();
}

// ---- gauges ----------------------------------------------------------
// Circumference of the gauge ring (r=30, see index.html): 2 * PI * 30.
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 30;

function setGauge(cardEl, arcEl, textEl, fraction, text, zone) {
  const clamped = Math.max(0, Math.min(1, fraction));
  // Round line-cap on a true zero-length arc still paints a visible dot at
  // the start position - drop the stroke entirely at zero instead.
  arcEl.setAttribute("stroke-dasharray", clamped > 0 ? String(GAUGE_CIRCUMFERENCE) : "0");
  arcEl.setAttribute("stroke-dashoffset", String(GAUGE_CIRCUMFERENCE * (1 - clamped)));
  textEl.textContent = text;
  cardEl.classList.remove("zone-warning", "zone-critical");
  if (zone) cardEl.classList.add(zone);
}

function renderSensorHealthGauge(summary) {
  // Real, computed value: how many of the two independent kernel sensors
  // (see process_correlator.py) are currently live - not a fabricated score.
  const states = [summary.sysmon_state, summary.etw_state];
  const liveCount = states.filter((s) => s === "live").length;
  const anyUnavailable = states.some((s) => s === "unavailable");
  const fraction = liveCount / 2;
  const zone = liveCount === 2 ? null : anyUnavailable ? "zone-critical" : "zone-warning";
  setGauge(
    document.getElementById("gaugeSensorHealth"),
    document.getElementById("sensorHealthArc"),
    document.getElementById("sensorHealthText"),
    fraction, `${liveCount}/2`, zone
  );
  let sub = `Sysmon: ${summary.sysmon_state || "?"} · ETW: ${summary.etw_state || "?"}`;
  // "lossy" = alive but dropping events; say how many, so the size of the
  // hole in visibility is visible rather than just its existence.
  const dropped = (summary.sysmon_dropped_events || 0) + (summary.etw_dropped_events || 0);
  if (dropped > 0) sub += ` · ${dropped} events dropped`;
  document.getElementById("sensorHealthSub").textContent = sub;
}

function renderPeakThreatGauge(summary, processes) {
  // Real, computed value: the highest current per-process score
  // (HeuristicEngine.process_scores), same number the Endpoint Processes
  // table and Top Endpoint Scores chart already show - not a fabricated
  // "threat radar" figure.
  const thresholds = summary.thresholds || { warning: 50, critical: 80 };
  const peak = processes.length ? processes[0].score : 0;
  const zone = peak >= thresholds.critical ? "zone-critical" : peak >= thresholds.warning ? "zone-warning" : null;
  setGauge(
    document.getElementById("gaugePeakThreat"),
    document.getElementById("peakThreatArc"),
    document.getElementById("peakThreatText"),
    peak / 100, String(Math.round(peak)), zone
  );
  document.getElementById("peakThreatSub").textContent = processes.length
    ? `${processes[0].name} (PID ${processes[0].pid})`
    : "No scored process yet";
}

// ---- stat tiles ----------------------------------------------------------
function renderSummary(summary) {
  renderMasthead(summary);
  renderSensorHealthGauge(summary);
  document.getElementById("statTotalAlerts").textContent = summary.total_alerts;
  document.getElementById("statCritical").textContent = summary.critical_count;
  document.getElementById("statWarning").textContent = summary.warning_count;
  document.getElementById("statProcesses").textContent = summary.processes_monitored;
  document.getElementById("statSamples").textContent = summary.samples_scanned;

  document.getElementById("statTelemetry").textContent = summary.telemetry_events_seen;
  const lastEventEl = document.getElementById("statLastEvent");
  const dot = document.getElementById("liveDot");
  const age = summary.seconds_since_last_event;
  if (age === null || age === undefined) {
    lastEventEl.textContent = "no events yet";
    dot.className = "live-dot";
  } else if (age < 10) {
    lastEventEl.textContent = "live";
    dot.className = "live-dot live";
  } else {
    lastEventEl.textContent = `last ${Math.round(age)}s ago`;
    dot.className = "live-dot stale";
  }

  const badge = document.getElementById("sensorStatus");
  badge.textContent = summary.sensor_status;
  let badgeClass = "badge-ok";
  if (summary.sensor_status.includes("unavailable")) {
    badgeClass = "badge-off";
  } else if (summary.sysmon_stale || summary.etw_stale || summary.sensor_status.includes("lossy")) {
    badgeClass = "badge-warn";
  }
  badge.className = "badge " + badgeClass;

  // Aggregate visibility state (see sensor_health.compute_blind_state) -
  // distinct from the per-sensor badge above: two sensors can each be
  // individually "down" for different reasons (one never started, one went
  // stale mid-run) while this collapses that into one telemetry-integrity
  // signal that detection confidence should key off of.
  const BLIND_STATE_CLASS = {
    HEALTHY: "badge-ok",
    DEGRADED: "badge-warn",
    PARTIALLY_BLIND: "badge-off",
    CRITICALLY_BLIND: "badge-off",
  };
  const blindBadge = document.getElementById("blindState");
  blindBadge.textContent = `Visibility: ${summary.blind_state || "?"}`;
  blindBadge.className = "badge " + (BLIND_STATE_CLASS[summary.blind_state] || "badge-neutral");

  // Negative-evidence protection (see sensor_health.negative_evidence_caveat):
  // the stat tiles above (Total Alerts/Critical/Warnings) are, in the end,
  // just counts of what was observed - they say nothing about what wasn't.
  // Surface that distinction right here rather than let a viewer read
  // "0 critical" as "confirmed clean" when visibility is actually degraded.
  const caveatEl = document.getElementById("visibilityCaveat");
  const caveatTextEl = document.getElementById("visibilityCaveatText");
  if (summary.visibility_caveat) {
    caveatTextEl.textContent = summary.visibility_caveat;
    caveatEl.style.display = "flex";
  } else {
    caveatEl.style.display = "none";
  }
}

// ---- charts ---------------------------------------------------------------
function initCharts() {
  charts.timeseries = new Chart(document.getElementById("timeseriesChart"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        { label: "Critical", data: [], backgroundColor: COLORS.critical },
        { label: "Warning", data: [], backgroundColor: COLORS.warning },
        { label: "Info", data: [], backgroundColor: COLORS.info },
      ],
    },
    options: {
      responsive: true,
      scales: { x: { stacked: true, ticks: { color: AXIS_COLOR } }, y: { stacked: true, beginAtZero: true, ticks: { color: AXIS_COLOR } } },
      plugins: { legend: { labels: { color: LEGEND_COLOR } } },
    },
  });

  charts.category = new Chart(document.getElementById("categoryChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: CATEGORY_PALETTE }] },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: LEGEND_COLOR, boxWidth: 10, font: { size: 10 } } } } },
  });

  charts.process = new Chart(document.getElementById("processChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Threat score", data: [], backgroundColor: COLORS.accent }] },
    options: {
      indexAxis: "y",
      responsive: true,
      scales: { x: { beginAtZero: true, max: 100, ticks: { color: AXIS_COLOR } }, y: { ticks: { color: AXIS_COLOR } } },
      plugins: { legend: { display: false } },
    },
  });
}

function renderTimeseries(ts) {
  const c = charts.timeseries;
  c.data.labels = ts.labels;
  c.data.datasets[0].data = ts.critical;
  c.data.datasets[1].data = ts.warning;
  c.data.datasets[2].data = ts.info;
  c.update("none");
}

function renderCategories(cats) {
  const c = charts.category;
  c.data.labels = Object.keys(cats);
  c.data.datasets[0].data = Object.values(cats);
  c.update("none");
}

function renderProcessChart(rows) {
  const top = rows.slice(0, 5);
  const c = charts.process;
  c.data.labels = top.map((r) => `${r.name} (${r.pid})`);
  c.data.datasets[0].data = top.map((r) => r.score);
  c.update("none");
}

// ---- detections table -------------------------------------------------
function renderAlerts() {
  const body = document.getElementById("alertsBody");
  const textFilter = document.getElementById("alertFilter").value.toLowerCase();
  const sevFilter = document.getElementById("severityFilter").value;

  const rows = lastAlerts.filter((a) => {
    if (sevFilter && a.severity !== sevFilter) return false;
    if (textFilter && !a.message.toLowerCase().includes(textFilter)) return false;
    return true;
  });

  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(4, "No detections match this filter."));
    return;
  }
  for (const a of rows.slice(0, 200)) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: a.time }));
    tr.appendChild(el("td", { text: a.severity, className: `sev-${a.severity}` }));
    tr.appendChild(el("td", { text: a.category }));
    tr.appendChild(el("td", { text: a.message }));
    body.appendChild(tr);
  }
}

// ---- endpoint processes table ------------------------------------------
function renderProcesses(rows) {
  const body = document.getElementById("processBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(5, "No scored processes yet."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.pid }));
    tr.appendChild(el("td", { text: r.name }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.verdict, className: `sev-${r.verdict === "CRITICAL" ? "CRITICAL" : r.verdict === "SUSPICIOUS" ? "WARNING" : "INFO"}` }));
    const actionTd = el("td");
    // Detection-forensics actions: why is this score what it is (Breakdown),
    // is the process still alive right now (Live), and how did it get here
    // (Chain). All three fetch on click - they are point-in-time answers,
    // not polled state, which matches how an analyst actually consumes
    // them (ask once per alert, re-ask when in doubt).
    const breakdownBtn = el("button", { text: "Breakdown", className: "btn btn-small" });
    breakdownBtn.addEventListener("click", () => openBreakdown(r.pid));
    actionTd.appendChild(breakdownBtn);
    const liveBtn = el("button", { text: "Live", className: "btn btn-small" });
    liveBtn.addEventListener("click", () => openLive(r.pid));
    actionTd.appendChild(liveBtn);
    const chainBtn = el("button", { text: "Chain", className: "btn btn-small" });
    chainBtn.addEventListener("click", () => openChain(r.pid));
    actionTd.appendChild(chainBtn);
    const btn = el("button", { text: "Terminate", className: "btn btn-danger-outline btn-small" });
    btn.addEventListener("click", () => terminateProcess(r.pid, r.name));
    actionTd.appendChild(btn);
    tr.appendChild(actionTd);
    body.appendChild(tr);
  }
}

async function terminateProcess(pid, name) {
  if (!confirm(`Suspend and terminate ${name} (PID ${pid})?`)) return;
  await fetch(`/api/processes/${pid}/terminate`, { method: "POST" });
  poll();
}

// ---- static analysis table ----------------------------------------------
function renderStatic(rows) {
  const body = document.getElementById("staticBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(4, "No static findings yet."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.file }));
    tr.appendChild(el("td", { text: r.hash }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.verdict, className: `sev-${r.verdict === "MALICIOUS" ? "CRITICAL" : r.verdict === "SUSPICIOUS" ? "WARNING" : "INFO"}` }));
    body.appendChild(tr);
  }
}

// ---- process explorer (every launch, flagged or not) --------------------
function renderExplorer() {
  const body = document.getElementById("explorerBody");
  const filter = document.getElementById("explorerFilter").value.toLowerCase();

  const rows = lastActivity.filter((e) => {
    if (!filter) return true;
    return [e.image, e.parent_image, e.command_line, e.lineage].some((f) => (f || "").toLowerCase().includes(filter));
  });

  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(6, lastActivity.length === 0 ? "No process activity observed yet - needs an elevated, Sysmon-connected run." : "No activity matches this filter."));
    return;
  }
  for (const e of rows.slice(0, 300)) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: e.time }));
    tr.appendChild(el("td", { text: e.pid }));
    tr.appendChild(el("td", { text: e.image || "" }));
    const source = e.source || "sysmon";
    tr.appendChild(el("td", { text: source, className: `src-${source}` }));
    tr.appendChild(el("td", { text: e.lineage || "" }));
    tr.appendChild(el("td", { text: e.command_line || "" }));
    body.appendChild(tr);
  }
}

// ---- rules tab (additive YAML rule pack) ---------------------------------
function renderRules(rows) {
  const body = document.getElementById("rulesBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(6, "No custom rules loaded - add a YAML file under rules/custom/."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.name }));
    tr.appendChild(el("td", { text: r.technique || "" }));
    tr.appendChild(el("td", { text: r.applies_to }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.enabled ? "Enabled" : "Disabled", className: r.enabled ? "sev-INFO" : "sev-WARNING" }));
    tr.appendChild(el("td", { text: r.hit_count }));
    body.appendChild(tr);
  }
}

// ---- tabs -----------------------------------------------------------------
function initTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });
}

// ---- polling loop -----------------------------------------------------
async function poll() {
  try {
    const [summary, alerts, timeseries, categories, processes, staticRows, activity, rules] = await Promise.all([
      getJSON("/api/summary"),
      getJSON("/api/alerts?limit=200"),
      getJSON("/api/alerts/timeseries"),
      getJSON("/api/alerts/categories"),
      getJSON("/api/processes"),
      getJSON("/api/static"),
      getJSON("/api/process-activity?limit=300"),
      getJSON("/api/rules"),
    ]);
    renderSummary(summary);
    renderPeakThreatGauge(summary, processes);
    lastAlerts = alerts;
    renderAlerts();
    renderTimeseries(timeseries);
    renderCategories(categories);
    renderProcessChart(processes);
    renderProcesses(processes);
    renderStatic(staticRows);
    lastActivity = activity;
    renderExplorer();
    renderRules(rules);
  } catch (e) {
    console.error("poll failed", e);
  }
}

async function isolateHost() {
  if (!confirm("Isolate this host from the network? (simulated - no real firewall changes are made)")) return;
  await fetch("/api/host/isolate", { method: "POST" });
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initTabs();
  document.getElementById("alertFilter").addEventListener("input", renderAlerts);
  document.getElementById("severityFilter").addEventListener("change", renderAlerts);
  document.getElementById("explorerFilter").addEventListener("input", renderExplorer);
  document.getElementById("isolateBtn").addEventListener("click", isolateHost);
  // Detection-forensics modal wiring: backdrop click and the ✕ button both
  // close. The script tag sits at the end of <body> (see index.html), so
  // these elements already exist when this runs.
  document.getElementById("modalClose").addEventListener("click", closeModal);
  document.getElementById("modalBackdrop").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeModal(); // only clicks on the dark backdrop itself
  });
  poll();
  setInterval(poll, POLL_MS);
});

// ---- detection-forensics modal panels -------------------------------------
// One modal shell (see index.html) serves three panels: Score Breakdown,
// Live Process Status, and the Memory Ancestry chain. Every dynamic value
// is rendered via textContent - never innerHTML - because these payloads
// embed process names, command lines and rule contexts that can be
// attacker-controlled. Same XSS discipline as the tables above.

function openModal(title) {
  document.getElementById("modalTitle").textContent = title;
  const body = document.getElementById("modalBody");
  clear(body);
  document.getElementById("modalBackdrop").style.display = "flex";
  return body;
}

function closeModal() {
  document.getElementById("modalBackdrop").style.display = "none";
}

function modalNote(text) {
  return el("p", { text, className: "modal-note" });
}

function kvRow(label, value) {
  const div = el("div", { className: "kv-row" });
  div.appendChild(el("span", { text: label, className: "kv-label" }));
  const display = value === null || value === undefined || value === "" ? "—" : String(value);
  div.appendChild(el("span", { text: display, className: "kv-value" }));
  return div;
}

function modalHeading(text) {
  return el("h4", { text, className: "modal-h4" });
}

async function fetchModalJSON(url, body, missingText) {
  try {
    return await getJSON(url);
  } catch (e) {
    clear(body);
    body.appendChild(modalNote(missingText));
    return null;
  }
}

async function openBreakdown(pid) {
  const body = openModal(`Score Breakdown — PID ${pid}`);
  body.appendChild(modalNote("Loading breakdown..."));
  const data = await fetchModalJSON(
    `/api/processes/${pid}/breakdown`, body,
    `No breakdown available for PID ${pid} (the engine has not scored it, or it was never observed).`
  );
  if (!data) return;
  clear(body);

  const head = el("div", { className: "breakdown-head" });
  head.appendChild(kvRow("Live score (after decay)", data.total));
  head.appendChild(kvRow("Raw contributions (never decay)", data.raw_sum));
  head.appendChild(kvRow("Thresholds", `warning ${data.thresholds?.warning ?? "?"} / critical ${data.thresholds?.critical ?? "?"}`));
  head.appendChild(kvRow("Suspicious activity span", data.activity_span_human));
  body.appendChild(head);

  // The two numbers measure different things and the panel says so:
  // 'total' is what the engine acts on (it decays), while the component
  // points below are history (they never decay). Showing both, labeled,
  // is the whole point - no unexplained numbers anywhere.
  body.appendChild(modalNote("Component points are raw contributions (history); the live score decays ~20 pts/min. Shares are of raw contributions."));

  if (!data.components || data.components.length === 0) {
    body.appendChild(modalNote("Score exists but no attributed components remain (decayed or rescored)."));
    return;
  }
  for (const c of data.components) {
    const row = el("div", { className: "comp-row" });
    const label = el("div", { className: "comp-label" });
    label.appendChild(el("span", { text: c.check_id, className: "comp-id" }));
    label.appendChild(el("span", {
      text: `+${c.points} pts × ${c.hits} hit${c.hits === 1 ? "" : "s"} · ${c.share}%`,
      className: "comp-points",
    }));
    row.appendChild(label);
    const barOuter = el("div", { className: "comp-bar" });
    const barInner = el("div", { className: "comp-bar-fill" });
    barInner.style.width = `${Math.max(2, Math.min(100, c.share))}%`;
    barOuter.appendChild(barInner);
    row.appendChild(barOuter);
    row.appendChild(el("div", { text: c.context, className: "comp-context" }));
    body.appendChild(row);
  }
}

async function openLive(pid) {
  const body = openModal(`Live Process Status — PID ${pid}`);
  body.appendChild(modalNote("Querying the live agent (same process as this dashboard)..."));
  const data = await fetchModalJSON(
    `/api/processes/${pid}/live`, body,
    `PID ${pid} could not be queried (already exited, or never existed).`
  );
  if (!data) return;
  clear(body);

  const head = el("div", { className: "live-head" });
  head.appendChild(el("span", {
    text: data.alive ? "ALIVE" : "DEAD",
    className: `badge ${data.alive ? "badge-ok" : "badge-off"}`,
  }));
  head.appendChild(kvRow("Name", data.name));
  head.appendChild(kvRow("Status", data.status));
  head.appendChild(kvRow("Threads", data.num_threads));
  head.appendChild(kvRow("Memory RSS/VM", data.rss != null ? `${(data.rss / 1048576).toFixed(1)} / ${(data.vms / 1048576).toFixed(1)} MB` : "—"));
  body.appendChild(head);

  if (data.denied && data.denied.length) {
    body.appendChild(modalNote(`Fields denied by the OS for this process: ${data.denied.join(", ")} (elevated/protected process - that itself is an answer).`));
  }

  body.appendChild(modalHeading("Open files"));
  if (data.open_files == null) {
    body.appendChild(modalNote("unavailable (denied)"));
  } else if (data.open_files.length === 0) {
    body.appendChild(modalNote("none open at this instant"));
  } else {
    const list = el("ul", { className: "live-list" });
    for (const f of data.open_files) list.appendChild(el("li", { text: f.path }));
    body.appendChild(list);
  }

  body.appendChild(modalHeading("Network connections"));
  if (data.net_connections == null) {
    body.appendChild(modalNote("unavailable (denied)"));
  } else if (data.net_connections.length === 0) {
    body.appendChild(modalNote("none open at this instant"));
  } else {
    const list = el("ul", { className: "live-list mono" });
    for (const c of data.net_connections) {
      list.appendChild(el("li", { text: `${c.laddr || "*"} → ${c.raddr || "*"} (${c.status})` }));
    }
    body.appendChild(list);
  }

  body.appendChild(modalHeading("Memory maps"));
  body.appendChild(modalNote(data.memory_maps_count == null ? "unavailable (denied)" : `${data.memory_maps_count} mapped regions`));

  const refresh = el("button", { text: "Refresh", className: "btn btn-small" });
  refresh.addEventListener("click", () => openLive(pid));
  body.appendChild(refresh);
}

async function openChain(pid) {
  const body = openModal(`Memory Ancestry Graph — PID ${pid}`);
  body.appendChild(modalNote("Reconstructing the attack chain..."));
  const data = await fetchModalJSON(
    `/api/processes/${pid}/ancestry`, body,
    `No ancestry or forensic snapshot recorded for PID ${pid}.`
  );
  if (!data) return;
  clear(body);

  const snap = data.forensic_snapshot;
  if (snap) {
    const snapBox = el("div", { className: "snap-box" });
    snapBox.appendChild(kvRow("Captured at", new Date(snap.taken_at * 1000).toLocaleString()));
    snapBox.appendChild(kvRow("Trigger", snap.trigger));
    snapBox.appendChild(kvRow("Score at capture", snap.score_at_capture));
    snapBox.appendChild(kvRow("Activity span", snap.activity_span_human));
    if (snap.trigger_edge) {
      snapBox.appendChild(kvRow("Connection edge", `${snap.trigger_edge.label} → ${snap.trigger_edge.target_image || `pid ${snap.trigger_edge.to}`}`));
    }
    if (snap.chain_summary) snapBox.appendChild(kvRow("Chain summary", snap.chain_summary));
    if (snap.ancestry_note) snapBox.appendChild(modalNote(`Ancestry: ${snap.ancestry_note}`));
    body.appendChild(snapBox);
  }

  const ancestry = data.ancestry;
  if (!ancestry || !ancestry.nodes || ancestry.nodes.length === 0) {
    body.appendChild(modalNote(
      snap
        ? "The forensic snapshot above is the surviving evidence - the live lineage tracker no longer has this chain (evicted, or the agent restarted)."
        : "No ancestry nodes recorded - the tracker never observed this PID or its ancestors."
    ));
    return;
  }

  if (ancestry.incomplete) {
    body.appendChild(modalNote("Chain is PARTIAL - the walk stopped at an untracked ancestor, a cycle, or the depth cap. Edges below are what was observed."));
  }

  // Render the chain oldest-first: each node indented under its parent,
  // with the connecting edge label on the connector line (EXEC for a
  // process-create link; the forensic snapshot's access edge, if any, is
  // shown in the snapshot box above since it is not a parentage relation).
  const tree = el("div", { className: "chain-tree" });
  ancestry.nodes.forEach((node, i) => {
    const nodeBox = el("div", { className: "chain-node" });
    nodeBox.style.marginLeft = `${Math.min(i, 6) * 18}px`;

    const edgeToHere = ancestry.edges.find((e) => e.to === node.pid);
    const edgeLabel = edgeToHere ? `—[${edgeToHere.label}]→ ` : "";
    const title = el("div", { className: "chain-title" });
    title.appendChild(el("span", { text: `${edgeLabel}${node.image || `pid:${node.pid}`}`, className: "chain-image" }));
    title.appendChild(el("span", { text: `PID ${node.pid}${node.alive ? "" : " (exited)"}`, className: "chain-pid" }));
    nodeBox.appendChild(title);

    const details = el("div", { className: "chain-details" });
    if (node.command_line) details.appendChild(kvRow("Command line", node.command_line));
    if (node.user) details.appendChild(kvRow("User", node.user));
    if (node.spawn_time) details.appendChild(kvRow("Spawn time", node.spawn_time));
    if (node.first_seen) details.appendChild(kvRow("First seen by agent", new Date(node.first_seen * 1000).toLocaleString()));
    if (node.env_vars) {
      const envCount = Object.keys(node.env_vars).length;
      details.appendChild(kvRow("Environment variables", `${envCount} captured`));
      const envList = el("ul", { className: "live-list mono env-list" });
      Object.entries(node.env_vars).slice(0, 15).forEach(([k, v]) => {
        envList.appendChild(el("li", { text: `${k}=${v}` }));
      });
      details.appendChild(envList);
      if (envCount > 15) details.appendChild(modalNote(`…and ${envCount - 15} more variables`));
    } else if (node.env_note) {
      details.appendChild(kvRow("Environment", node.env_note));
    }
    if (details.childNodes.length) nodeBox.appendChild(details);
    tree.appendChild(nodeBox);
  });
  body.appendChild(tree);
}
