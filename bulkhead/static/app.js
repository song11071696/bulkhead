/* Bulkhead dashboard: vanilla JS, no build step.
 * Live mode polls the FastAPI server. Static mode (GitHub Pages) plays a recorded export of the same events. */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const pct = (x) => (x === null || x === undefined ? "n/a" : `${Math.round(x * 100)}%`);

const STAGES = { task: "Task", inbound: "Inbound screen", command: "Command check", outbound: "Outbound check", final: "Final-report check", note: "Hook" };
const ACTION_LABEL = { allow: "allow", ask: "ask human", deny: "deny", quarantine: "quarantine", redact: "redact", caution: "caution", withhold: "withhold" };
const ENDPOINTS = {
  injection: ["Guard", "/injection"], script: ["Inspect", "/script"], pii: ["Protect", "/pii"],
  decide: ["Decide", "/decide"], grounding: ["Verify", "/grounding"], pipeline: ["Pipeline", "/pipeline"],
};

let STATIC = null;        // recorded export when served without the API
let state = { sid: null, lastId: 0, events: [], status: null, playing: false };

async function api(path, opts) {
  if (STATIC) return staticApi(path, opts);
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

/* ---------------- static (recorded) mode ---------------- */
const staticPlayed = {};   // sid -> number of events revealed
function staticApi(path, opts) {
  if (path.startsWith("/api/status")) {
    const t = { events: 0, blocked: 0, asked: 0, sanitized: 0, credits: 0 };
    for (const s of STATIC.sessions) {
      for (const e of s.events.slice(0, staticPlayed[s.session.id] ?? s.events.length)) {
        t.events++; t.credits += e.credits || 0;
        if (["deny", "withhold"].includes(e.action)) t.blocked++;
        if (e.action === "ask") t.asked++;
        if (["quarantine", "redact"].includes(e.action)) t.sanitized++;
      }
    }
    return { ...STATIC.status, mode: "recorded", totals: t };
  }
  if (path.startsWith("/api/scenarios")) {
    if (opts && opts.method === "POST") {
      const name = path.split("/")[3];
      const s = STATIC.sessions.find((x) => x.scenario === name);
      staticPlayed[s.session.id] = 0;
      const tick = () => {
        staticPlayed[s.session.id]++;
        if (staticPlayed[s.session.id] < s.events.length) setTimeout(tick, 1600);
      };
      setTimeout(tick, 300);
      return { session_id: s.session.id };
    }
    return STATIC.scenarios;
  }
  if (path.startsWith("/api/sessions/")) {
    const sid = decodeURIComponent(path.split("/")[3].split("?")[0]);
    const after = Number((path.split("after=")[1] || "0"));
    const s = STATIC.sessions.find((x) => x.session.id === sid);
    const shown = s.events.slice(0, staticPlayed[sid] ?? s.events.length);
    return { session: s.session, events: shown.filter((e) => e.id > after) };
  }
  if (path.startsWith("/api/sessions")) {
    return STATIC.sessions.map((s) => {
      const shown = s.events.slice(0, staticPlayed[s.session.id] ?? s.events.length);
      return { ...s.session, events: shown.length, credits: shown.reduce((a, e) => a + (e.credits || 0), 0),
        blocked: shown.filter((e) => ["deny", "withhold"].includes(e.action)).length,
        asked: shown.filter((e) => e.action === "ask").length, last: s.session.created };
    });
  }
  return {};
}

/* ---------------- rendering helpers ---------------- */
function segHtml(segs) {
  if (!segs) return "";
  return segs.map((s) => (s.kind ? `<span class="seg ${s.kind}" title="${esc(s.label || s.kind)}">${esc(s.text)}</span>` : esc(s.text))).join("");
}

function meter(label, value, opts = {}) {
  if (value === null || value === undefined) return "";
  const v = Math.max(0, Math.min(1, value / (opts.max || 1)));
  const lo = opts.lo ?? 0.4, hi = opts.hi ?? 0.8;
  const cls = v >= hi ? "hi" : v >= lo ? "mid" : "lo";
  const band = opts.band === false ? "" : `<div class="band" style="left:${lo * 100}%;width:${(hi - lo) * 100}%"></div>`;
  const shown = opts.max ? `${value.toFixed(2)} / ${opts.max}` : pct(value);
  return `<div class="meter"><div class="lbl"><span>${esc(label)}</span><b>${shown}</b></div>
    <div class="bar">${band}<div class="fill ${cls}" style="width:${v * 100}%"></div></div></div>`;
}

function signalsHtml(e) {
  const d = e.data || {};
  const s = (state.status && state.status.settings) || {};
  let out = [];
  if (d.guard) {
    out.push(meter("Guard · prompt injection", d.guard.injection, { lo: s.guard_caution ?? 0.4, hi: s.guard_block ?? 0.8 }));
    if (d.guard.residual !== undefined && d.guard.residual !== null)
      out.push(meter("Guard · risk left after cutting evidence", d.guard.residual, { lo: s.guard_caution ?? 0.4, hi: s.guard_block ?? 0.8 }));
  }
  if (d.inspect) {
    out.push(meter("Inspect · malicious (command alone)", d.inspect.malicious, { lo: 0.5, hi: s.inspect_deny ?? 0.8 }));
  }
  if (d.decide && d.decide.answers) {
    const a = d.decide.answers;
    if (a.follows_untrusted) out.push(meter("Decide · follows injected instruction", a.follows_untrusted.noul, { lo: s.follow_ask ?? 0.4, hi: s.follow_deny ?? 0.8 }));
    if (a.exfiltration) out.push(meter("Decide · sends data off-machine", a.exfiltration.noul, { lo: 0.5, hi: s.exfil_ask ?? 0.8 }));
    if (a.scope) out.push(meter(`Decide · out of scope (choice: ${a.scope.choice})`, (a.scope.probabilities || {}).out_of_scope ?? 0, { lo: 0.5, hi: 0.8 }));
    if (a.blast_radius) out.push(meter("Decide · blast radius", a.blast_radius.score, { max: 2, lo: 0.5, hi: 0.75, band: false }));
  }
  let html = out.length ? `<div class="sig">${out.join("")}</div>` : "";
  const chips = [];
  if (d.guard && d.guard.category) chips.push(`<span class="chip ${d.guard.injection >= 0.4 ? "bad" : "ok"}">Guard: ${esc(d.guard.category)} · severity ${esc(d.guard.severity)}</span>`);
  if (d.inspect && d.inspect.category) chips.push(`<span class="chip ${d.inspect.verdict !== "benign" ? "bad" : "ok"}">Inspect: ${esc(d.inspect.verdict)} · ${esc(d.inspect.category)}</span>`);
  if (d.protect) {
    const counts = {};
    for (const en of d.protect.entities || []) counts[en.type] = (counts[en.type] || 0) + 1;
    const ks = Object.keys(counts);
    chips.push(ks.length ? ks.map((k) => `<span class="chip ${["api_secret", "credit_card", "ssn", "bank_account"].includes(k) ? "bad" : "mid"}">Protect: ${esc(k)} ×${counts[k]}</span>`).join("")
      : `<span class="chip ok">Protect: nothing sensitive</span>`);
  }
  if (e.data && e.data.tainted) chips.push(`<span class="chip mid">session tainted (${esc(e.data.taint_severity || "")})</span>`);
  if (chips.length) html += `<div class="chips">${chips.join("")}</div>`;
  if (d.verify && d.verify.claims) {
    html += `<div class="claims">` + d.verify.claims.map((c) => {
      const cls = c.verdict === "supported" ? "ok" : c.verdict === "contradicted" ? "bad" : "mid";
      const p = c.verdict === "contradicted" ? c.contradicted : c.verdict === "supported" ? c.supported : c.not_stated;
      return `<div class="claim"><span class="chip ${cls}">${esc(c.verdict)} ${pct(p)}</span><span>${esc(c.claim)}</span></div>`;
    }).join("") + `</div>`;
  }
  return html;
}

function callsHtml(calls) {
  if (!calls || !calls.length) return `<div class="calls"><span class="c">no Clocked call (decided locally)</span></div>`;
  return `<div class="calls">` + calls.map((c) => {
    const [nm] = ENDPOINTS[c.endpoint] || [c.endpoint];
    if (c.error) return `<span class="c retry">${esc(nm)} failed: ${esc(c.error.kind)} ${esc(c.error.status ?? "")} after ${c.error.attempts} attempt(s)</span>`;
    let steps = "";
    if (c.steps) steps = " [" + c.steps.map((st) => {
      const n = (ENDPOINTS[st.endpoint] || [st.endpoint])[0];
      return st.skipped ? `<span class="skip">${esc(n)}</span>` : `${esc(n)}✓`;
    }).join(" · ") + "]";
    const retr = (c.retries || []).map((r) => `<span class="retry">attempt ${r.attempt}: ${r.status ?? "network"} (key ${esc(r.key || "")}…)</span>`).join(" ");
    return `<span class="c">${esc(nm)}${steps} · ${c.credits ?? 0} cr · ${c.latency_ms ?? "?"} ms${c.attempts > 1 ? ` · attempt ${c.attempts}` : ""}${c.source === "replay" ? " · recorded" : ""}</span>${retr ? " " + retr : ""}`;
  }).join("") + `</div>`;
}

function eventHtml(e) {
  const d = e.data || {};
  const v = d.verdict || {};
  const credits = e.credits ? `${e.credits} cr` : "";
  let body = "";
  if (e.stage === "task") body = `<div class="code light">${esc(d.text)}</div>`;
  else if (e.stage === "final") body = `<div class="code light">${esc(d.text)}</div>`;
  else if (d.segments) {
    const hasAlt = d.sanitized && d.sanitized.length;
    const altLabel = e.stage === "inbound" ? "What the agent saw" : "What gets written";
    body = `<div class="code" data-orig="1">${segHtml(d.segments)}</div>`;
    if (hasAlt) body = `<div class="tabs"><button class="ghost tab-o">Original (flagged)</button><button class="tab-s">${altLabel}</button></div>
      <div class="code orig">${segHtml(d.segments)}</div><div class="code light san" hidden>${esc(d.sanitized)}</div>`;
  }
  const reasons = (v.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("");
  const cap = d.caption ? `<div class="cap">${esc(d.caption)}</div>` : "";
  const effect = d.effect ? `<div class="effect">${esc(d.effect)}</div>` : "";
  const hookJson = d.hook_response !== undefined ? `<details><summary>Hook response sent to Claude Code</summary><pre>${esc(JSON.stringify(d.hook_response, null, 2))}</pre></details>` : "";
  return `<div class="ev ${e.action}" id="ev-${e.id}">
    <div class="h"><span class="step">${d.step ? "#" + d.step : ""}</span><span class="stage">${STAGES[e.stage] || e.stage}</span>
      ${e.tool ? `<span class="tool">${esc(e.tool)}</span>` : ""}<span class="hook">${esc(e.hook)}</span>
      <span class="pill ${e.action}">${ACTION_LABEL[e.action] || e.action}</span>${v.uncertain ? `<span class="chip mid">uncertainty band</span>` : ""}
      <span class="meta">${credits}</span></div>
    ${cap}${body}${signalsHtml(e)}<ul class="reasons">${reasons}</ul>${effect}${callsHtml(d.calls)}${hookJson}</div>`;
}

function wireTabs(el) {
  const o = el.querySelector(".tab-o"), s = el.querySelector(".tab-s");
  if (!o) return;
  const show = (san) => {
    el.querySelector(".orig").hidden = san; el.querySelector(".san").hidden = !san;
    o.classList.toggle("ghost", san); s.classList.toggle("ghost", !san);
  };
  o.onclick = () => show(false); s.onclick = () => show(true);
  show(false);
}

/* ---------------- panels ---------------- */
function renderTotals(st) {
  const t = st.totals || {};
  $("#totals").innerHTML = [["events", t.events], ["blocked", t.blocked], ["asked human", t.asked], ["sanitized", t.sanitized], ["credits", Math.round(t.credits || 0)]]
    .map(([k, v]) => `<div class="total"><b>${v ?? 0}</b><span>${k}</span></div>`).join("");
  const m = $("#mode");
  const label = { live: "LIVE · calling Clocked", record: "LIVE · recording fixtures", replay: "REPLAY · recorded Clocked responses", recorded: "RECORDED DEMO · static" }[st.mode] || st.mode;
  m.textContent = label; m.className = "mode" + (st.mode === "live" || st.mode === "record" ? " live" : "");
  const s = st.settings || {};
  $("#bands").innerHTML = `
    <div><b>Guard</b>: ≥${pct(s.guard_block)} quarantine/withhold · ${pct(s.guard_caution)}–${pct(s.guard_block)} caution + taint</div>
    <div><b>Inspect</b>: malicious ≥${pct(s.inspect_deny)} deny · other non-benign → ask</div>
    <div><b>Decide</b>: follows-injection ≥${pct(s.follow_deny)} + impact → deny (ask if taint severity low) · ${pct(s.follow_ask)}–${pct(s.follow_deny)} ask · exfiltration ≥${pct(s.exfil_ask)} ask</div>
    <div><b>Protect</b>: secrets → deny · personal data → redacted copy (updatedInput / updatedToolOutput)</div>
    <div><b>Verify</b>: claim contradicted ≥${pct(s.contradicted_block)} → block Stop once</div>
    <div><b>Clocked unavailable</b>: fail mode <b>${esc(s.fail_mode)}</b></div>`;
}

async function renderScenarios() {
  const list = await api("/api/scenarios");
  $("#scenarios").innerHTML = list.map((s) => `<div class="scn"><div class="t">${esc(s.title)}<button data-run="${s.id}">Run</button></div><p>${esc(s.blurb)}</p></div>`).join("");
  document.querySelectorAll("[data-run]").forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    const r = await api(`/api/scenarios/${b.dataset.run}/run`, { method: "POST" });
    await refreshSessions();
    select(r.session_id);
    setTimeout(() => (b.disabled = false), 4000);
  }));
}

async function refreshSessions() {
  const list = await api("/api/sessions");
  $("#sessions").innerHTML = list.map((s) => `<div class="s ${s.id === state.sid ? "on" : ""}" data-sid="${esc(s.id)}">
      <div class="l">${esc(s.label || s.id)}</div>
      <div class="m"><span>${s.events} events</span><span><i class="dot" style="background:var(--deny)"></i>${s.blocked}</span>
      <span><i class="dot" style="background:var(--ask)"></i>${s.asked}</span><span>${Math.round(s.credits || 0)} cr</span></div></div>`).join("")
    || `<p class="hint">No sessions yet.</p>`;
  document.querySelectorAll("[data-sid]").forEach((el) => (el.onclick = () => select(el.dataset.sid)));
  if (!state.sid && list.length && !location.hash) select(list[0].id);
}

function select(sid) {
  state.sid = sid; state.lastId = 0; state.events = [];
  $("#timeline").innerHTML = ""; $("#empty").hidden = true; $("#session").hidden = false;
  document.querySelectorAll("[data-sid]").forEach((el) => el.classList.toggle("on", el.dataset.sid === sid));
  pollSession(true);
}

function renderSessionHeader(sess) {
  $("#slabel").textContent = sess.label || sess.id;
  $("#goal").textContent = sess.goal || "(waiting for the first prompt)";
  const ev = state.events;
  const n = (f) => ev.filter(f).length;
  $("#sstats").innerHTML = [["events", ev.length], ["denied", n((e) => ["deny", "withhold"].includes(e.action))], ["asked", n((e) => e.action === "ask")],
    ["sanitized", n((e) => ["quarantine", "redact"].includes(e.action))], ["credits", Math.round(ev.reduce((a, e) => a + (e.credits || 0), 0))]]
    .map(([k, v]) => `<div class="sstat"><b>${v}</b><span>${k}</span></div>`).join("");
  const taint = sess.taint || [];
  $("#taint").innerHTML = taint.length ? `<div class="taint"><b>Session tainted.</b> Untrusted content tried to instruct the agent; every later command is cross-checked by Decide against it.
      ${taint.map((t) => `<div style="margin-top:6px"><b>${esc(t.source)}</b> · ${pct(t.injection)} ${esc(t.category || t.level)} · severity ${esc(t.severity || "?")}
      ${(t.quotes || []).slice(0, 2).map((q) => `<q>“${esc(q)}”</q>`).join("")}</div>`).join("")}</div>` : "";
  // endpoints panel
  const counts = {};
  for (const e of ev) for (const c of (e.data && e.data.calls) || []) {
    const add = (ep, cr) => { counts[ep] = counts[ep] || { n: 0, cr: 0 }; counts[ep].n++; counts[ep].cr += cr || 0; };
    add(c.endpoint, c.credits);
    for (const st of c.steps || []) if (!st.skipped) add(st.endpoint, 0);
  }
  $("#endpoints").innerHTML = `<div class="epl">` + Object.entries(ENDPOINTS).map(([k, [nm, path]]) => {
    const c = counts[k];
    return `<span class="n">${nm} <span class="p">${path}</span></span><span class="k">${c ? c.n + "×" : "–"}</span><span class="k">${c && k === "pipeline" ? Math.round(c.cr) + " cr" : ""}</span>`;
  }).join("") + `</div><p class="hint" style="margin-top:8px">Steps inside one Pipeline round trip are counted under their endpoint; credits are billed once per pipeline.</p>`;
}

async function pollSession(first) {
  if (!state.sid) return;
  const sid = state.sid;
  const r = await api(`/api/sessions/${encodeURIComponent(sid)}?after=${state.lastId}`);
  if (sid !== state.sid) return;
  for (const e of r.events) {
    state.events.push(e);
    state.lastId = Math.max(state.lastId, e.id);
    const div = document.createElement("div");
    div.innerHTML = eventHtml(e);
    const el = div.firstElementChild;
    $("#timeline").appendChild(el);
    wireTabs(el);
    const flag = el.querySelector(".code .seg.injection, .code .seg.pii, .code .seg.script");
    if (flag) { const box = flag.closest(".code"); box.scrollTop = Math.max(0, flag.offsetTop - box.offsetTop - 40); }
    if (!first) el.scrollIntoView({ behavior: "smooth", block: "end" });
  }
  renderSessionHeader(r.session);
}

async function tick() {
  try {
    state.status = await api("/api/status");
    renderTotals(state.status);
    await pollSession(false);
  } catch (e) { /* server restarting */ }
}

async function boot() {
  try {
    if (location.search.includes("static")) throw new Error("static");
    await fetch("/api/status").then((r) => { if (!r.ok) throw new Error(); });
  } catch (e) {
    STATIC = await fetch("static/demo-data.json").then((r) => r.json());
    STATIC.sessions.forEach((s) => (staticPlayed[s.session.id] = s.events.length));
  }
  state.status = await api("/api/status");
  renderTotals(state.status);
  await renderScenarios();
  await refreshSessions();
  setInterval(tick, 800);
  setInterval(refreshSessions, 2500);
}
window.bulkhead = { select, state };
boot();
