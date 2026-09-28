/* ===========================================================================
 * ADORecon — read-only Azure DevOps recon + cloud reachability mapping
 * ---------------------------------------------------------------------------
 * Released by Zer0byte. Authorized security assessments only: run this only
 * against Azure DevOps organizations you own or are contracted to test.
 *
 * Paste into DevTools console on a tab logged into Azure DevOps.
 * Injects a resizable control panel (Shadow DOM). Rides the live session
 * cookies. No PAT. STRICTLY READ-ONLY.
 *
 * SAFETY MODEL
 *   - Transport is GET-only. A single guarded readQuery() allows the two
 *     read-only query POSTs the platform requires (WIQL, permission batch).
 *     No code path writes, queues, edits, mints, or installs.
 *   - Deliberately NOT implemented (change/execute in a live tenant; these
 *     belong in the report as "reachable / demonstrate on sign-off"):
 *     queue/edit pipelines, PAT minting, decorator/extension install,
 *     service-hook creation, group/ACL changes, repo pushes.
 *
 * The target org is detected from the page URL at runtime; nothing about any
 * organization is hardcoded. Every finding deep-links to the exact resource.
 * Console: window.ADORecon.data
 * =========================================================================== */
(() => {
  'use strict';
  document.getElementById('adorecon-host')?.remove();

  // ------------------------------ context -------------------------------
  function detectContext() {
    const h = location.hostname, seg = location.pathname.split('/').filter(Boolean);
    if (h === 'dev.azure.com') {
      const org = seg[0];
      if (!org) throw new Error('No org in URL. Go to dev.azure.com/<org> first.');
      return { org, base: `https://dev.azure.com/${org}`, vssps: `https://vssps.dev.azure.com/${org}`,
        vsrm: `https://vsrm.dev.azure.com/${org}`, feeds: `https://feeds.dev.azure.com/${org}`,
        extmgmt: `https://extmgmt.dev.azure.com/${org}` };
    }
    if (h.endsWith('.visualstudio.com')) {
      const org = h.split('.')[0];
      return { org, base: `https://${org}.visualstudio.com`, vssps: `https://${org}.vssps.visualstudio.com`,
        vsrm: `https://${org}.vsrm.visualstudio.com`, feeds: `https://${org}.feeds.visualstudio.com`,
        extmgmt: `https://${org}.extmgmt.visualstudio.com` };
    }
    throw new Error('Run from an Azure DevOps page (dev.azure.com/<org> or <org>.visualstudio.com).');
  }
  let CTX;
  try { CTX = detectContext(); } catch (e) { alert('[ADORecon] ' + e.message); return; }
  const API = '7.1';
  const NS = { endpoints: '49b48001-ca20-4adc-8111-5b60c903a50c', git: '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87' };

  // ---- deep links: build exact portal URLs for each resource type -------
  const enc = encodeURIComponent;
  const LINK = {
    varGroup: (proj, id) => `${CTX.base}/${enc(proj)}/_library?view=VariableGroupView&variableGroupId=${id}`,
    secureFiles: (proj) => `${CTX.base}/${enc(proj)}/_library?view=SecureFilesView`,
    wiki: (proj, wiki, path) => `${CTX.base}/${enc(proj)}/_wiki/wikis/${enc(wiki)}?pagePath=${enc(path)}`,
    pipeline: (proj, id) => `${CTX.base}/${enc(proj)}/_build?definitionId=${id}`,
    repoFile: (proj, repo, path) => `${CTX.base}/${enc(proj)}/_git/${enc(repo)}?path=${enc(path)}`,
    buildLog: (proj, id) => `${CTX.base}/${enc(proj)}/_build/results?buildId=${id}&view=logs`,
    workItem: (proj, id) => `${CTX.base}/${enc(proj)}/_workitems/edit/${id}`,
    serviceConn: (proj, id) => `${CTX.base}/${enc(proj)}/_settings/adminservices?resourceId=${id}`,
    repos: (proj) => `${CTX.base}/${enc(proj)}/_settings/repositories`,
    agentPool: (id) => `${CTX.base}/_settings/agentpools?poolId=${id}&view=agents`,
    extensions: () => `${CTX.base}/_settings/extensions`,
    feeds: () => `${CTX.base}/_packaging`,
  };

  // ============================== UI SHELL ==============================
  const host = document.createElement('div');
  host.id = 'adorecon-host';
  host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647';
  const R = host.attachShadow({ mode: 'open' });
  R.innerHTML = `
<style>
  :host{ all:initial; }
  *{ box-sizing:border-box; font-family:ui-sans-serif,system-ui,-apple-system,sans-serif; }
  .panel{ position:relative; width:460px; height:600px; min-width:360px; min-height:380px;
    max-width:96vw; max-height:94vh; display:flex; flex-direction:column; background:#171a21; color:#e5e7eb;
    border:1px solid #2a2f3a; border-radius:10px; box-shadow:0 10px 40px rgba(0,0,0,.5); font-size:13px; overflow:hidden; }
  .hdr{ display:flex; align-items:center; gap:8px; padding:10px 12px; background:#0f1117; border-bottom:1px solid #2a2f3a; cursor:move; user-select:none; flex:0 0 auto; }
  .dot{ width:9px; height:9px; border-radius:50%; background:#8b5cf6; box-shadow:0 0 8px #8b5cf6; }
  .ro{ font-size:10px; color:#34d399; border:1px solid #14532d; background:#0b2a1c; padding:1px 6px; border-radius:10px; letter-spacing:.4px; }
  .org{ color:#9ca3af; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; min-width:0; } .sp{ flex:1; min-width:0; }
  .hdr b{ white-space:nowrap; }
  .minbadge{ display:none; font-size:11px; color:#c4b5fd; white-space:nowrap; }
  .panel.min .ro, .panel.min .org{ display:none; } .panel.min .minbadge{ display:inline; } .panel.min .hdr{ border-bottom:none; }
  .iconbtn{ background:none; border:none; color:#9ca3af; cursor:pointer; font-size:15px; padding:2px 6px; border-radius:5px; }
  .iconbtn:hover{ background:#232838; color:#e5e7eb; }
  .tabs{ display:flex; border-bottom:1px solid #2a2f3a; background:#0f1117; flex:0 0 auto; }
  .tab{ flex:1; padding:8px 0; text-align:center; cursor:pointer; color:#9ca3af; font-weight:600; border-bottom:2px solid transparent; }
  .tab.on{ color:#e5e7eb; border-bottom-color:#8b5cf6; }
  .tab .n{ min-width:18px; padding:0 5px; margin-left:5px; border-radius:9px; background:#232838; color:#c4b5fd; font-size:11px; }
  .prog{ height:4px; background:#232838; overflow:hidden; display:none; flex:0 0 auto; } .prog.on{ display:block; }
  .prog > i{ display:block; height:100%; width:0; background:#8b5cf6; transition:width .2s; }
  .body{ flex:1 1 auto; min-height:0; overflow:auto; padding:12px; } .body::-webkit-scrollbar{ width:9px; height:9px; } .body::-webkit-scrollbar-thumb{ background:#2a2f3a; border-radius:5px; }
  section{ display:none; } section.on{ display:block; }
  .hint{ color:#6b7280; font-size:11px; margin:2px 0 10px; line-height:1.45; }
  .banner{ background:#0b2a1c; border:1px solid #14532d; color:#86efac; border-radius:7px; padding:7px 9px; font-size:11.5px; margin-bottom:11px; line-height:1.4; }
  .grp{ font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#6b7280; margin:12px 0 6px; }
  .mods{ display:grid; grid-template-columns:1fr 1fr; gap:6px 14px; margin:2px 0 4px; }
  .chk{ display:flex; align-items:center; gap:7px; cursor:pointer; color:#cbd5e1; }
  input[type=checkbox]{ accent-color:#8b5cf6; width:15px; height:15px; }
  input[type=text],input[type=number]{ background:#0f1117; border:1px solid #2a2f3a; color:#e5e7eb; border-radius:6px; padding:6px 8px; font-size:13px; width:100%; }
  input[type=number]{ width:72px; }
  .grid2{ display:grid; grid-template-columns:1fr 1fr; gap:8px 12px; }
  .fld{ display:flex; flex-direction:column; gap:4px; } .fld small{ color:#6b7280; font-size:11px; }
  .run{ width:100%; margin-top:12px; padding:10px; border:none; border-radius:7px; cursor:pointer; background:linear-gradient(135deg,#8b5cf6,#6d28d9); color:#fff; font-weight:700; font-size:13px; }
  .run:disabled{ opacity:.5; cursor:not-allowed; }
  .counts{ display:flex; gap:8px; margin-bottom:10px; }
  .pill{ flex:1; text-align:center; padding:7px 0; border-radius:7px; background:#0f1117; border:1px solid #2a2f3a; }
  .pill b{ display:block; font-size:18px; } .pill small{ color:#9ca3af; text-transform:uppercase; font-size:10px; letter-spacing:.5px; }
  .pill.a b{ color:#e5e7eb; } .pill.c b{ color:#ef4444; } .pill.h b{ color:#f97316; } .pill.m b{ color:#f59e0b; } .pill.l b{ color:#94a3b8; }
  .filters{ display:flex; gap:6px; margin-bottom:8px; flex-wrap:wrap; align-items:center; }
  .fbtn{ padding:4px 10px; border:1px solid #2a2f3a; background:#0f1117; color:#9ca3af; border-radius:14px; cursor:pointer; font-size:12px; }
  .fbtn.on{ background:#232838; color:#e5e7eb; border-color:#8b5cf6; }
  .tablescroll{ overflow-x:auto; border:1px solid #232838; border-radius:7px; }
  table{ width:100%; border-collapse:collapse; font-size:12px; }
  th,td{ text-align:left; padding:6px 8px; border-bottom:1px solid #232838; border-right:1px solid #232838; vertical-align:top; } th:last-child,td:last-child{ border-right:none; }
  th{ color:#9ca3af; font-weight:600; white-space:nowrap; position:sticky; top:0; background:#171a21; }
  tr:last-child td{ border-bottom:none; }
  td.val{ font-family:ui-monospace,monospace; cursor:pointer; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  td.val:hover{ color:#c4b5fd; }
  td.src{ color:#9ca3af; word-break:break-all; }
  td.src a{ color:#93c5fd; text-decoration:none; } td.src a:hover{ text-decoration:underline; }
  .colrz{ position:absolute; top:0; right:-4px; width:8px; height:100%; cursor:col-resize; user-select:none; z-index:3; }
  .colrz:hover{ background:#8b5cf6; opacity:.5; }
  .sev{ font-weight:700; text-transform:uppercase; font-size:10px; padding:2px 6px; border-radius:4px; white-space:nowrap; }
  .sev.critical{ background:#b91c1c; color:#fff; } .sev.high{ background:#ea580c; color:#fff; }
  .sev.medium{ background:#fde68a; color:#412402; } .sev.low{ background:#334155; color:#cbd5e1; } .sev.info{ background:#0c447c; color:#cfe4ff; }
  .empty{ color:#6b7280; text-align:center; padding:20px; }
  .card{ background:#0f1117; border:1px solid #232838; border-radius:8px; padding:9px 10px; margin-bottom:10px; }
  .card h4{ margin:0 0 7px; font-size:12px; color:#c4b5fd; font-weight:600; letter-spacing:.3px; }
  .kv{ display:flex; justify-content:space-between; gap:10px; padding:2px 0; } .kv span:first-child{ color:#9ca3af; } .kv span:last-child{ text-align:right; word-break:break-all; }
  .find{ display:flex; align-items:flex-start; gap:8px; padding:7px 0; border-bottom:1px solid #232838; } .find:last-child{ border-bottom:none; }
  .find > .sev{ flex:0 0 auto; min-width:58px; text-align:center; margin-top:1px; }
  .find .txt{ flex:1; } .find .txt b{ display:block; font-weight:600; } .find .txt small{ color:#9ca3af; } .find .txt a{ color:#93c5fd; font-size:11px; text-decoration:none; } .find .txt a:hover{ text-decoration:underline; }
  .tag{ display:inline-block; font-size:10px; padding:1px 6px; border-radius:4px; background:#232838; color:#9ca3af; margin-left:6px; }
  pre.log{ margin:0; white-space:pre-wrap; word-break:break-word; font-family:ui-monospace,monospace; font-size:11.5px; line-height:1.55; color:#cbd5e1; }
  pre.log .w{ color:#f59e0b; } pre.log .e{ color:#ef4444; } pre.log .ok{ color:#34d399; } pre.log .d{ color:#6b7280; }
  .footer{ display:flex; gap:8px; padding:10px 12px; border-top:1px solid #2a2f3a; background:#0f1117; flex:0 0 auto; }
  .footer button{ flex:1; padding:8px; border:1px solid #2a2f3a; background:#171a21; color:#e5e7eb; border-radius:6px; cursor:pointer; font-weight:600; font-size:12px; } .footer button:hover{ border-color:#8b5cf6; }
  .grip{ position:absolute; right:2px; bottom:2px; width:16px; height:16px; cursor:nwse-resize; z-index:5; }
  .grip::after{ content:''; position:absolute; right:3px; bottom:3px; width:8px; height:8px; border-right:2px solid #4b5563; border-bottom:2px solid #4b5563; }
  .toast{ position:absolute; bottom:52px; left:50%; transform:translateX(-50%); background:#8b5cf6; color:#fff; padding:5px 12px; border-radius:6px; font-size:12px; opacity:0; transition:opacity .2s; pointer-events:none; z-index:6; }
  .toast.on{ opacity:1; }
</style>
<div class="panel">
  <div class="hdr" id="hdr">
    <span class="dot"></span><b>ADORecon</b><span class="ro">READ-ONLY</span><span class="org" id="org"></span><span class="minbadge" id="minbadge">ready</span>
    <span class="sp"></span>
    <button class="iconbtn" id="min" title="minimize">–</button>
    <button class="iconbtn" id="max" title="maximize">▢</button>
    <button class="iconbtn" id="close" title="close">✕</button>
  </div>
  <div class="tabs">
    <div class="tab on" data-t="cfg">Config</div>
    <div class="tab" data-t="find">Secrets<span class="n" id="nfind">0</span></div>
    <div class="tab" data-t="recon">Recon<span class="n" id="nrec">0</span></div>
    <div class="tab" data-t="log">Log</div>
  </div>
  <div class="prog" id="prog"><i id="progbar"></i></div>
  <div class="body">
    <section class="on" data-s="cfg">
      <div class="banner"><b>Read-only.</b> Enumerates, evaluates permissions, and maps cloud reachability on <b id="orgn"></b>. Never queues, edits, mints, or installs anything.</div>
      <div class="grp">Secret modules</div>
      <div class="mods">
        <label class="chk"><input type="checkbox" id="m_wiki" checked>Wiki scraper</label>
        <label class="chk"><input type="checkbox" id="m_pipelines" checked>Pipeline + library</label>
        <label class="chk"><input type="checkbox" id="m_repos" checked>Repo secret sweep</label>
        <label class="chk"><input type="checkbox" id="m_logs" checked>Build log grep</label>
        <label class="chk"><input type="checkbox" id="m_workitems" checked>Work item sweep</label>
      </div>
      <div class="grp">Recon modules</div>
      <div class="mods">
        <label class="chk"><input type="checkbox" id="m_identity" checked>Identity + privilege</label>
        <label class="chk"><input type="checkbox" id="m_reach" checked>Cloud reachability</label>
        <label class="chk"><input type="checkbox" id="m_agents" checked>Agent pools</label>
        <label class="chk"><input type="checkbox" id="m_ext" checked>Extensions + feeds</label>
      </div>
      <div class="grp">Scope</div>
      <div class="fld" style="margin-bottom:10px">
        <label>Projects <small>(comma-separated, blank = all)</small></label>
        <input type="text" id="projects" placeholder="e.g. Payments, Platform">
      </div>
      <div class="grid2">
        <div class="fld"><label>Concurrency</label><input type="number" id="conc" value="5" min="1" max="20"></div>
        <div class="fld"><label>Max projects <small>(0=all)</small></label><input type="number" id="maxp" value="0" min="0"></div>
        <div class="fld"><label>Builds / project</label><input type="number" id="maxb" value="20" min="0"></div>
        <div class="fld" style="justify-content:end;gap:8px"><label class="chk"><input type="checkbox" id="allfiles">Scan all repo files</label><label class="chk"><input type="checkbox" id="entropy" checked>High-entropy scan</label></div>
      </div>
      <button class="run" id="run">▶ Run recon</button>
    </section>

    <section data-s="find">
      <div class="counts">
        <div class="pill a"><b id="ca">0</b><small>all</small></div>
        <div class="pill c"><b id="cc">0</b><small>critical</small></div>
        <div class="pill h"><b id="ch">0</b><small>high</small></div>
        <div class="pill m"><b id="cm">0</b><small>medium</small></div>
        <div class="pill l"><b id="cl">0</b><small>low</small></div>
      </div>
      <div class="filters" id="filters">
        <span class="fbtn on" data-f="all">All</span><span class="fbtn" data-f="firm">Firm</span><span class="fbtn" data-f="critical">Critical</span>
        <span class="fbtn" data-f="high">High</span><span class="fbtn" data-f="medium">Medium</span>
        <label class="chk" style="margin-left:auto"><input type="checkbox" id="mask" checked>mask</label>
      </div>
      <input type="text" id="search" placeholder="filter by rule or source…" style="margin-bottom:8px">
      <div id="findmeta" class="hint" style="margin:0 0 8px"></div>
      <div id="tablewrap"><div class="empty">No run yet.</div></div>
    </section>

    <section data-s="recon">
      <div id="reconwrap"><div class="empty">No run yet.</div></div>
    </section>

    <section data-s="log"><pre class="log" id="logpre">Ready.\n</pre></section>
  </div>
  <div class="footer">
    <button id="ejson">⬇ JSON</button>
    <button id="ehtml">⬇ HTML report</button>
  </div>
  <div class="grip" id="grip" title="drag to resize"></div>
  <div class="toast" id="toast"></div>
</div>`;
  document.body.appendChild(host);
  const $ = (s) => R.querySelector(s);
  $('#org').textContent = $('#orgn').textContent = CTX.org;

  // ---------------------------- UI plumbing -----------------------------
  R.querySelectorAll('.tab').forEach(t => t.onclick = () => {
    R.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === t));
    R.querySelectorAll('section').forEach(s => s.classList.toggle('on', s.dataset.s === t.dataset.t));
    if (t.dataset.t === 'find' && typeof F !== 'undefined' && F) renderFindings();
    if (t.dataset.t === 'recon' && typeof F !== 'undefined' && F) renderRecon();
  });
  $('#close').onclick = () => host.remove();
  const bodyEl = R.querySelector('.body'), panel = R.querySelector('.panel');
  const tabsEl = R.querySelector('.tabs'), footEl = R.querySelector('.footer'), progEl = $('#prog'), gripEl = $('#grip');
  let uiState = 'normal', savedGeom = null;
  function chrome(state) {
    const norm = state !== 'min';
    tabsEl.style.display = norm ? '' : 'none';
    bodyEl.style.display = norm ? '' : 'none';
    footEl.style.display = norm ? '' : 'none';
    progEl.style.display = norm ? '' : 'none';
    gripEl.style.display = state === 'normal' ? '' : 'none';
  }
  function snapshot() { savedGeom = { left: host.style.left, top: host.style.top, right: host.style.right, bottom: host.style.bottom, width: panel.style.width, height: panel.style.height, minWidth: panel.style.minWidth, minHeight: panel.style.minHeight }; }
  function restoreGeom() { const g = savedGeom || {}; host.style.left = g.left || ''; host.style.top = g.top || '16px'; host.style.right = g.right || '16px'; host.style.bottom = g.bottom || ''; panel.style.width = g.width || ''; panel.style.height = g.height || ''; panel.style.minWidth = g.minWidth || ''; panel.style.minHeight = g.minHeight || ''; }
  function toNormal() { chrome('normal'); restoreGeom(); panel.classList.remove('min'); uiState = 'normal'; $('#max').textContent = '▢'; $('#max').title = 'maximize'; $('#min').title = 'minimize'; }
  function toMin() { if (uiState === 'normal') snapshot(); chrome('min'); panel.classList.add('min'); host.style.left = 'auto'; host.style.top = 'auto'; host.style.right = '16px'; host.style.bottom = '16px'; panel.style.minWidth = '0'; panel.style.minHeight = '0'; panel.style.width = '270px'; panel.style.height = 'auto'; uiState = 'min'; $('#max').textContent = '▢'; $('#min').title = 'restore'; updateMinBadge(); }
  function toMax() { if (uiState === 'normal') snapshot(); chrome('max'); panel.classList.remove('min'); host.style.left = '2vw'; host.style.top = '2vh'; host.style.right = 'auto'; host.style.bottom = 'auto'; panel.style.minWidth = ''; panel.style.minHeight = ''; panel.style.width = '96vw'; panel.style.height = '94vh'; uiState = 'max'; $('#max').textContent = '❐'; $('#max').title = 'restore'; $('#min').title = 'minimize'; }
  function updateMinBadge() { const b = $('#minbadge'); if (typeof F === 'undefined' || !F || !F.secrets.length) { b.textContent = 'ready'; return; } const c = { critical: 0, high: 0 }; F.secrets.forEach(s => { if (c[s.sev] !== undefined) c[s.sev]++; }); b.textContent = `${F.secrets.length} · ${c.critical}C ${c.high}H · ${F.findings.length} posture`; }
  $('#min').onclick = () => uiState === 'min' ? toNormal() : toMin();
  $('#max').onclick = () => uiState === 'max' ? toNormal() : toMax();
  (() => { // drag by header
    const hdr = $('#hdr'); let sx, sy, ox, oy, drag = false;
    hdr.onmousedown = (e) => { drag = true; sx = e.clientX; sy = e.clientY; const r = host.getBoundingClientRect(); ox = r.left; oy = r.top; host.style.right = 'auto'; e.preventDefault(); };
    window.addEventListener('mousemove', (e) => { if (!drag) return; host.style.left = (ox + e.clientX - sx) + 'px'; host.style.top = (oy + e.clientY - sy) + 'px'; });
    window.addEventListener('mouseup', () => drag = false);
  })();
  (() => { // resize by grip
    const grip = $('#grip'), panel = R.querySelector('.panel'); let rw, rh, rx, ry, rz = false;
    grip.onmousedown = (e) => { rz = true; const r = panel.getBoundingClientRect(); rw = r.width; rh = r.height; rx = e.clientX; ry = e.clientY; e.preventDefault(); e.stopPropagation(); };
    window.addEventListener('mousemove', (e) => { if (!rz) return; panel.style.width = Math.max(360, Math.min(innerWidth * 0.96, rw + e.clientX - rx)) + 'px'; panel.style.height = Math.max(380, Math.min(innerHeight * 0.94, rh + e.clientY - ry)) + 'px'; });
    window.addEventListener('mouseup', () => rz = false);
  })();
  let corsHinted = false;
  function corsHint() { if (corsHinted) return; corsHinted = true; sink.log('  → graph/extensions/feeds live on sibling hosts blocked by CORS here. Run from the org\'s *.visualstudio.com origin to enable them.', 'w'); }
  function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('on'); setTimeout(() => t.classList.remove('on'), 1100); }
  const sink = {
    log(msg, cls = '') { const p = $('#logpre'); p.innerHTML += cls ? `<span class="${cls}">${msg}</span>\n` : `${msg}\n`; p.parentElement.scrollTop = p.parentElement.scrollHeight; },
    progress(done, total) { $('#prog').classList.add('on'); $('#progbar').style.width = total ? (100 * done / total).toFixed(1) + '%' : '0%'; },
  };

  // ============================== TRANSPORT ============================
  // GET-only. readQuery() is the ONLY POST path, gated to read-only queries.
  const READ_QUERY_OK = [/\/_apis\/wit\/wiql/i, /\/_apis\/permissions\/.+\/permissionevaluationbatch/i];
  // Suppress ADO's federated-auth 302 (same headers the ADO SPA sends).
  const AUTH_HEADERS = { 'X-TFS-FedAuthRedirect': 'Suppress', 'X-VSS-ReauthenticationAction': 'Suppress' };
  function classifyFail(res, e) {
    if (e) return Object.assign(new Error('blocked (CORS / preflight) — sibling host not reachable with credentials from this origin'), { code: 'CORS' });
    if (res.type === 'opaqueredirect') return Object.assign(new Error('auth redirect to sign-in — session not valid for the API from this origin'), { code: 'AUTHREDIR' });
    if (res.status === 401 || res.status === 403) return Object.assign(new Error(`auth ${res.status}`), { code: res.status });
    return Object.assign(new Error(`${res.status} ${res.statusText}`), { code: res.status });
  }
  async function req(url, { host: hk = 'base', asText = false } = {}) {
    const full = /^https?:/.test(url) ? url : `${CTX[hk]}${url}`;
    let res;
    try { res = await fetch(full, { method: 'GET', credentials: 'include', redirect: 'manual', headers: { 'Accept': asText ? '*/*' : `application/json;api-version=${API}`, ...AUTH_HEADERS } }); }
    catch (e) { throw classifyFail(null, e); }
    if (res.type === 'opaqueredirect' || !res.ok) throw classifyFail(res);
    if (asText) return res.text();
    const ct = res.headers.get('content-type') || '';
    return ct.includes('json') ? res.json() : res.text();
  }
  async function readQuery(url, body, hk = 'base') {
    const full = /^https?:/.test(url) ? url : `${CTX[hk]}${url}`;
    if (!READ_QUERY_OK.some(rx => rx.test(full))) throw new Error('readQuery blocked: not an allow-listed read query');
    let res;
    try { res = await fetch(full, { method: 'POST', credentials: 'include', redirect: 'manual', headers: { 'Accept': `application/json;api-version=${API}`, 'Content-Type': 'application/json', ...AUTH_HEADERS }, body: JSON.stringify(body) }); }
    catch (e) { throw classifyFail(null, e); }
    if (res.type === 'opaqueredirect' || !res.ok) throw classifyFail(res);
    return res.json();
  }
  async function listAll(path, hk = 'base') {
    const sep = path.includes('?') ? '&' : '?';
    const u = path.includes('api-version') ? path : `${path}${sep}api-version=${API}`;
    const p = await req(u, { host: hk });
    return (p && Array.isArray(p.value)) ? p.value : [];
  }
  function pool(items, worker, limit) {
    return new Promise((resolve) => {
      const out = new Array(items.length); let i = 0, active = 0, done = 0;
      if (!items.length) return resolve(out);
      const next = () => { while (active < limit && i < items.length) { const idx = i++; active++;
        Promise.resolve(worker(items[idx], idx)).then(r => out[idx] = r).catch(e => out[idx] = { __error: e.message }).finally(() => { active--; if (++done === items.length) resolve(out); else next(); }); } };
      next();
    });
  }
  async function can(namespace, bit, token) {
    try { const r = await req(`/_apis/permissions/${namespace}/${bit}?tokens=${enc(token)}&api-version=${API}`);
      return Array.isArray(r.value) ? !!r.value[0] : null; } catch { return null; }
  }

  // ========================= SECRET ENGINE =============================
  const shannon = (s) => { const m = {}; for (const c of s) m[c] = (m[c] || 0) + 1; let h = 0; for (const k in m) { const p = m[k] / s.length; h -= p * Math.log2(p); } return h; };
  const PLACEHOLDER = /^(?:true|false|null|none|nil|undefined|changeme|change_me|example|placeholder|redacted|removed|your[_-]?\w*|xxx+|\*{3,}|\.{3,}|<[^>]+>|\$\(|\$\{|%[a-z_.]+%|#\{|@@[a-z]|\{\{|\bsecret\b|\bpassword\b|\btoken\b|00000|123456|abcdef)/i;
  const RULES = [
    { id: 'private-key', sev: 'critical', conf: 'firm', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, desc: 'Private key block', dedupeBySource: true, maxLen: 8000 },
    { id: 'aws-akid', sev: 'high', conf: 'firm', re: /\bAKIA[0-9A-Z]{16}\b/g, desc: 'AWS access key id' },
    { id: 'azure-storage', sev: 'high', conf: 'firm', re: /AccountKey=[A-Za-z0-9+/=]{60,}/g, desc: 'Azure Storage key' },
    { id: 'github-pat', sev: 'high', conf: 'firm', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, desc: 'GitHub token' },
    { id: 'slack', sev: 'high', conf: 'firm', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, desc: 'Slack token' },
    { id: 'google-key', sev: 'high', conf: 'firm', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, desc: 'Google API key' },
    { id: 'npm', sev: 'high', conf: 'firm', re: /\bnpm_[A-Za-z0-9]{36}\b/g, desc: 'npm token' },
    { id: 'azure-sas', sev: 'high', conf: 'firm', re: /\bsig=[A-Za-z0-9%]{40,}&?/g, desc: 'Azure SAS signature' },
    { id: 'db-conn', sev: 'high', conf: 'firm', re: /(?:Server|Data Source|Host)=[^;\n]{1,200};[^\n]{0,300}?(?:Password|Pwd)=[^;'"\s]{4,200}/gi, desc: 'DB connection string w/ password', rejectIf: /(?:Password|Pwd)=(?:\$\(|\$\{|<|%|\{\{|changeme|password|yourpass|xxx|\*{3,})/i },
    { id: 'jwt', sev: 'medium', conf: 'firm', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, desc: 'JWT' },
    { id: 'aws-secret', sev: 'high', conf: 'heuristic', re: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, desc: 'AWS secret (heuristic)', minEntropy: 4.3, needCtx: /aws|s3|secret[_-]?access/i },
    // Keyword-independent: catches high-entropy secrets stored as bare config
    // values (real AWS/API keys often sit next to no obvious keyword). Restricted
    // to QUOTED values 32-45 chars so it doesn't match PEM cert lines (64-char,
    // unquoted) or URL/path fragments. Gated by the "High-entropy scan" toggle.
    { id: 'high-entropy', sev: 'medium', conf: 'heuristic', re: /["']([A-Za-z0-9+/=_-]{32,45})["']/g, desc: 'High-entropy secret (heuristic)', minEntropy: 4.5, requireMixed: true, rejectIf: /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f-]{27})$/i },
    { id: 'ado-pat', sev: 'high', conf: 'heuristic', re: /\b[a-z2-7]{52}\b/g, desc: 'Azure DevOps PAT (heuristic)', minEntropy: 4.0 },
    { id: 'bearer', sev: 'medium', conf: 'heuristic', re: /(?:authorization|bearer)\s*[:=]\s*['"]?([A-Za-z0-9._\-]{20,})/gi, desc: 'Authorization / bearer', minEntropy: 3.5, denyVal: PLACEHOLDER },
    { id: 'assign', sev: 'low', conf: 'heuristic', re: /(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|conn(?:ection)?[_-]?str(?:ing)?)\s*[:=]\s*['"]?([^\s'"`,;]{8,})/gi, desc: 'Credential-like assignment', minEntropy: 3.2, denyVal: PLACEHOLDER },
  ];
  function scan(text, source, link) {
    if (!text || typeof text !== 'string') return [];
    const hits = [], seen = new Set();
    for (const r of RULES) { if (r.id === 'high-entropy' && CFG && CFG.entropy === false) continue; r.re.lastIndex = 0; let m;
      while ((m = r.re.exec(text)) !== null) {
        const val = (m[1] || m[0]).trim();
        if (val.length > (r.maxLen || 400)) continue;
        if (r.rejectIf && r.rejectIf.test(val)) continue;
        if (r.denyVal && r.denyVal.test(val)) continue;
        if (r.requireMixed && !(/[a-z]/.test(val) && /[A-Z]/.test(val) && /[0-9]/.test(val))) continue;
        if (r.needCtx && !r.needCtx.test(text.slice(Math.max(0, m.index - 40), m.index + 60))) continue;
        if (r.minEntropy && shannon(val) < r.minEntropy) continue;
        const key = r.id + '::' + val; if (seen.has(key)) continue; seen.add(key);
        // dkey drives global dedupe. Marker rules (value is a fixed header, not
        // the secret itself) dedupe per-source so distinct keys/files are kept.
        const dkey = r.dedupeBySource ? `${r.id}::${val}::${source}` : `${r.id}::${val}`;
        hits.push({ rule: r.id, sev: r.sev, conf: r.conf, desc: r.desc, value: val, line: text.slice(0, m.index).split('\n').length, source, link, dkey });
      } }
    return hits;
  }
  // Rich-text fields (work items, wiki) embed pasted screenshots as huge base64
  // data URIs; a 40-char window of that trips the aws-secret/high-entropy
  // heuristics but is an image, not a credential. Strip data URIs and HTML tags
  // before scanning so those false positives never fire.
  function cleanRich(t) {
    return String(t || '')
      .replace(/data:[a-z0-9.+-]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+/gi, ' [inline-image] ')
      .replace(/<[^>]+>/g, ' ');
  }
  const REPO_PATTERNS = [/\.env(\..+)?$/i, /(^|\/)web\.config$/i, /appsettings.*\.json$/i, /\.tfvars$/i, /\.pfx$/i, /\.p12$/i, /(^|\/)id_rsa$/i, /\.pem$/i, /\.key$/i, /\.ya?ml$/i, /\.ps1$/i, /(^|\/)[^/]*\.sh$/i, /(^|\/)Dockerfile$/i, /docker-compose.*\.ya?ml$/i, /\.sql$/i, /settings.*\.json$/i, /config.*\.(json|xml|ini|toml|conf)$/i, /credentials?$/i, /secrets?\.(json|ya?ml|txt)$/i, /\.npmrc$/i, /\.netrc$/i];

  let F, CFG, addSecret, addFinding;

  // ---------------------------- secret modules --------------------------
  async function mWiki(proj) {
    const wikis = await listAll(`/${enc(proj.name)}/_apis/wiki/wikis`);
    for (const w of wikis) {
      F.wikis.push({ project: proj.name, name: w.name, id: w.id, link: LINK.wiki(proj.name, w.name, '/') });
      let paths = [];
      try { const p = await req(`/${enc(proj.name)}/_apis/wiki/wikis/${w.id}/pages?path=/&recursionLevel=full&api-version=${API}`);
        const flat = []; (function walk(n) { if (!n) return; if (n.path) flat.push(n.path); (n.subPages || []).forEach(walk); })(p);
        paths = [...new Set(flat)].filter(Boolean);
      } catch (e) { sink.log(`  wiki ${w.name}: ${e.message}`, 'w'); continue; }
      await pool(paths, async (path) => { try { const pg = await req(`/${enc(proj.name)}/_apis/wiki/wikis/${w.id}/pages?path=${enc(path)}&includeContent=true&api-version=${API}`); addSecret(scan(cleanRich(pg.content), `wiki:${proj.name}/${w.name}${path}`, LINK.wiki(proj.name, w.name, path))); } catch { } }, CFG.conc);
    }
  }
  async function mPipe(proj) {
    const p = enc(proj.name);
    try { const vgs = await listAll(`/${p}/_apis/distributedtask/variablegroups`);
      for (const vg of vgs) { const rec = { project: proj.name, name: vg.name, id: vg.id, link: LINK.varGroup(proj.name, vg.id), secretVars: [], plainVars: {} };
        for (const [k, v] of Object.entries(vg.variables || {})) {
          if (v && v.isSecret) rec.secretVars.push(k);
          else {
            rec.plainVars[k] = v ? v.value : null;
            const hits = scan(`${k}=${v && v.value}`, `varGroup:${proj.name}/${vg.name} [${k}]`, LINK.varGroup(proj.name, vg.id));
            addSecret(hits);
            if (hits.some(h => h.conf === 'firm')) addFinding('high', `Plaintext credential in Library variable: ${vg.name} / ${k}`, `Variable "${k}" in variable group "${vg.name}" (project ${proj.name}) holds a credential in plaintext — it is not marked secret, so its value is readable by anyone with pipeline/library read access and is returned in cleartext by the REST API. Mark it secret, or link it from a Key Vault.`, `varGroup:${vg.id}`, LINK.varGroup(proj.name, vg.id));
          }
        }
        F.variableGroups.push(rec); }
    } catch (e) { sink.log(`  varGroups: ${e.message}`, 'w'); }
    try { (await listAll(`/${p}/_apis/distributedtask/securefiles`)).forEach(f => F.secureFiles.push({ project: proj.name, name: f.name, id: f.id, link: LINK.secureFiles(proj.name) })); } catch { }
    try { const defs = await listAll(`/${p}/_apis/build/definitions?$top=1000`);
      await pool(defs, async (d) => { try { const full = await req(`/${p}/_apis/build/definitions/${d.id}?api-version=${API}`);
        const link = LINK.pipeline(proj.name, full.id);
        F.pipelines.push({ project: proj.name, name: full.name, id: full.id, type: full.process?.type === 2 ? 'yaml' : 'classic', link });
        addSecret(scan(JSON.stringify(full.process || {}), `pipeline:${proj.name}/${full.name}`, link));
        addSecret(scan(JSON.stringify(full.variables || {}), `pipelineVars:${proj.name}/${full.name}`, link)); } catch { } }, CFG.conc);
    } catch (e) { sink.log(`  buildDefs: ${e.message}`, 'w'); }
  }
  async function mRepos(proj) {
    const p = enc(proj.name);
    let repos = [];
    try { repos = await listAll(`/${p}/_apis/git/repositories`); } catch (e) { sink.log(`  repos: ${e.message}`, 'w'); return; }
    let empty = 0;
    for (const repo of repos) { const rec = { project: proj.name, name: repo.name, files: 0, scanned: 0, link: LINK.repoFile(proj.name, repo.name, '/') };
      let items = [];
      try { const r = await req(`/${p}/_apis/git/repositories/${repo.id}/items?recursionLevel=full&api-version=${API}`); items = (r.value || []).filter(i => !i.isFolder && i.path); }
      catch (e) { if (e.code === 404) { rec.empty = true; empty++; } else sink.log(`  items ${repo.name}: ${e.message}`, 'w'); F.repos.push(rec); continue; }
      rec.files = items.length;
      const targets = CFG.allfiles ? items : items.filter(i => REPO_PATTERNS.some(rx => rx.test(i.path)));
      await pool(targets, async (it) => { try { const buf = await req(`/${p}/_apis/git/repositories/${repo.id}/items?path=${enc(it.path)}&$format=text&api-version=${API}`, { asText: true }); if (buf.length > 512 * 1024) return; rec.scanned++; addSecret(scan(buf, `repo:${proj.name}/${repo.name}${it.path}`, LINK.repoFile(proj.name, repo.name, it.path))); } catch { } }, CFG.conc);
      F.repos.push(rec);
    }
    if (empty) sink.log(`  ${empty}/${repos.length} repo(s) empty or no default branch (skipped)`, 'd');
  }
  async function mLogs(proj) {
    if (!CFG.maxb) return;
    const p = enc(proj.name);
    let builds = [];
    try { builds = (await listAll(`/${p}/_apis/build/builds?statusFilter=completed&queryOrder=finishTimeDescending&$top=${CFG.maxb}`)).slice(0, CFG.maxb); }
    catch (e) { sink.log(`  builds: ${e.message}`, 'w'); return; }
    await pool(builds, async (b) => { try { const logs = await listAll(`/${p}/_apis/build/builds/${b.id}/logs`);
      await pool(logs, async (lg) => { try { const t = await req(`/${p}/_apis/build/builds/${b.id}/logs/${lg.id}?api-version=${API}`, { asText: true }); addSecret(scan(t, `buildLog:${proj.name}/build-${b.id}/log-${lg.id}`, LINK.buildLog(proj.name, b.id))); } catch { } }, 3); } catch { } }, 3);
  }
  async function mWorkItems(proj) {
    const p = enc(proj.name);
    let ids = [];
    try { const q = await readQuery(`/${p}/_apis/wit/wiql?api-version=${API}`, { query: "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.ChangedDate] >= @today - 365 ORDER BY [System.ChangedDate] DESC" });
      ids = (q.workItems || []).map(w => w.id).slice(0, 200);
    } catch (e) { sink.log(`  workitems ${proj.name}: ${e.message}${e.code === 400 ? ' (Boards likely disabled or query too broad)' : ''}`, 'w'); return; }
    const fields = 'System.Title,System.Description,Microsoft.VSTS.TCM.ReproSteps,System.History,System.TeamProject';
    for (let i = 0; i < ids.length; i += 200) { const chunk = ids.slice(i, i + 200);
      try { const wi = await listAll(`/_apis/wit/workitems?ids=${chunk.join(',')}&fields=${enc(fields)}&errorPolicy=omit`);
        for (const w of wi) { const f = w.fields || {}; const wproj = f['System.TeamProject'] || proj.name;
          const txt = Object.entries(f).filter(([k]) => k !== 'System.TeamProject').map(([, v]) => v).join('\n');
          addSecret(scan(cleanRich(txt), `workItem:${wproj}/#${w.id}`, LINK.workItem(wproj, w.id))); } } catch { }
    }
  }

  // ----------------------------- recon modules --------------------------
  async function mIdentity() {
    try { const cd = await req('/_apis/connectionData');
      const u = cd.authenticatedUser || {};
      F.recon.identity = { displayName: u.providerDisplayName || u.customDisplayName || u.subjectDescriptor, id: u.id, descriptor: u.descriptor, subjectDescriptor: u.subjectDescriptor };
      sink.log(`  identity: ${F.recon.identity.displayName || '(unknown)'}`, 'd');
    } catch (e) { sink.log(`  connectionData: ${e.message}`, 'w'); }
    try {
      const users = await listAll(`/_apis/graph/users?api-version=${API}-preview.1`, 'vssps');
      const groups = await listAll(`/_apis/graph/groups?api-version=${API}-preview.1`, 'vssps');
      F.recon.userCount = users.length; F.recon.groupCount = groups.length;
      F.recon.svcPrincipals = users.filter(u => /servicePrincipal|service account/i.test(u.subjectKind || '') || /\.svc$|service/i.test(u.principalName || '')).map(u => u.principalName || u.displayName).slice(0, 50);
      const admin = /(Collection Administrators|Project Administrators|Build Administrators|Endpoint Administrators|Security Administrators)/i;
      F.recon.adminGroups = groups.filter(g => admin.test(g.displayName || '')).map(g => g.displayName);
      sink.log(`  graph: ${users.length} users, ${groups.length} groups, ${F.recon.adminGroups.length} admin group(s)`, 'd');
    } catch (e) { sink.log(`  graph host unreachable from this origin (${e.message}); identity-graph partial`, 'w'); corsHint(); }
  }
  function classifyEndpoint(ep) {
    const t = (ep.type || '').toLowerCase(), a = ep.authorization || {}, d = ep.data || {}, ap = a.parameters || {};
    let provider = ep.type || 'generic', target = ep.url || '';
    if (t === 'azurerm') { provider = 'Azure RM'; target = `${d.subscriptionName || ''} (${d.subscriptionId || ''})`.trim(); }
    else if (t === 'aws') { provider = 'AWS'; target = ap.username ? `AccessKeyId ${ap.username}` : (ep.url || ''); }
    else if (t === 'kubernetes') { provider = 'Kubernetes'; target = ep.url || d.clusterName || ''; }
    else if (/dockerregistry|azurecontainerregistry|acr/.test(t)) { provider = 'Container registry'; target = ep.url || d.registry || d.registryId || ''; }
    else if (/github/.test(t)) { provider = 'GitHub'; target = ep.url || ''; }
    else if (/azure|servicefabric/.test(t)) { provider = ep.type; target = ep.url || d.subscriptionId || ''; }
    return { provider, target, scheme: a.scheme || d.authorizationType || '' };
  }
  async function mReach(proj) {
    const p = enc(proj.name);
    let eps = [];
    try { eps = await listAll(`/${p}/_apis/serviceendpoint/endpoints?includeDetails=true`); } catch (e) { sink.log(`  endpoints ${proj.name}: ${e.message}`, 'w'); return; }
    for (const ep of eps) {
      const c = classifyEndpoint(ep), link = LINK.serviceConn(proj.name, ep.id);
      const token = `endpoints/${proj.id}/${ep.id}`;
      const [canUse, canAdmin] = await Promise.all([can(NS.endpoints, 16, token), can(NS.endpoints, 2, token)]);
      F.recon.cloudReach.push({ project: proj.name, name: ep.name, provider: c.provider, target: c.target, scheme: c.scheme, ready: ep.isReady !== false, shared: !!ep.isShared, canUse, canAdmin, link });
      const cloud = /Azure RM|AWS|Kubernetes|Container/.test(c.provider);
      if (cloud && canUse) addFinding('high', `Reachable cloud connection: ${ep.name}`, `Current identity can USE this ${c.provider} connection in a pipeline → executes against ${c.target || 'the target'} (${c.scheme}). Session-to-cloud pivot path. Demonstrate only on sign-off.`, token, link);
      else if (cloud && canUse === null) addFinding('medium', `Cloud connection present: ${ep.name}`, `${c.provider} → ${c.target}. Use-permission could not be evaluated; confirm manually whether the foothold identity can queue against it.`, token, link);
      if (canAdmin) addFinding('high', `Over-privileged on connection: ${ep.name}`, `Current identity has Administer on this ${c.provider} service connection.`, token, link);
    }
    const gitContribute = await can(NS.git, 4, `repoV2/${proj.id}`);
    if (gitContribute) addFinding('high', `Repo write in ${proj.name}`, 'Current identity can push to repositories in this project (build-script / template poisoning surface). Read-only tool flags reachability only.', `repoV2/${proj.id}`, LINK.repos(proj.name));
  }
  async function mAgents() {
    try { const pools = await listAll(`/_apis/distributedtask/pools`);
      let selfHosted = 0;
      for (const pool_ of pools) { const rec = { name: pool_.name, id: pool_.id, isHosted: !!pool_.isHosted, size: pool_.size, agents: [], link: LINK.agentPool(pool_.id) };
        if (!pool_.isHosted) { selfHosted++;
          try { const agents = await listAll(`/_apis/distributedtask/pools/${pool_.id}/agents?includeCapabilities=true`);
            rec.agents = agents.map(a => ({ name: a.name, status: a.status, os: (a.systemCapabilities || {})['Agent.OS'] || (a.systemCapabilities || {})['OS'], host: (a.systemCapabilities || {})['Agent.ComputerName'] || (a.systemCapabilities || {})['COMPUTERNAME'], version: a.version }));
          } catch { }
          const hosts = rec.agents.map(a => a.host).filter(Boolean);
          const detail = hosts.length
            ? `Queuing against this pool is code execution on internal host(s): ${[...new Set(hosts)].slice(0, 6).join(', ')}. Lateral-movement surface. Read-only tool enumerates; it does not queue.`
            : `Self-hosted agent pool with ${rec.agents.length} registered agent(s). Jobs queued here run on private/self-managed infrastructure rather than Microsoft-hosted runners — a code-execution and lateral-movement surface. Review who can queue against it.`;
          addFinding('medium', `Self-hosted pool: ${pool_.name}`, detail, `pool:${pool_.id}`, LINK.agentPool(pool_.id));
        }
        F.recon.agentPools.push(rec);
      }
      sink.log(`  pools: ${pools.length} total, ${selfHosted} self-hosted`, 'd');
    } catch (e) { sink.log(`  agent pools: ${e.message}`, 'w'); }
  }
  async function mExt() {
    try { const exts = await listAll(`/_apis/extensionmanagement/installedextensions?api-version=${API}-preview.1`, 'extmgmt');
      for (const x of exts) { const contribs = x.contributions || [];
        const decorators = contribs.filter(c => /pipeline-decorator/i.test(c.type || ''));
        F.recon.extensions.push({ name: x.extensionName, publisher: x.publisherName, id: `${x.publisherId}.${x.extensionId}`, decorators: decorators.length, link: LINK.extensions() });
        if (decorators.length) { F.recon.decorators.push({ ext: `${x.publisherId}.${x.extensionId}`, count: decorators.length });
          addFinding('high', `Pipeline decorator installed: ${x.extensionName}`, `Publisher ${x.publisherName}. A decorator runs on every pipeline in the org — org-wide code-exec / secret-harvest surface and a persistence primitive. Review its source and scope. (Detection: extension install + contribution type ms.azure-pipelines.pipeline-decorator.)`, `${x.publisherId}.${x.extensionId}`, LINK.extensions()); }
      }
      sink.log(`  extensions: ${exts.length}, decorators: ${F.recon.decorators.length}`, 'd');
    } catch (e) { sink.log(`  extmgmt unreachable from this origin (${e.message}); extension enum skipped`, 'w'); corsHint(); }
    try { const feeds = await listAll(`/_apis/packaging/feeds?api-version=${API}-preview.1`, 'feeds');
      F.recon.feeds = feeds.map(f => ({ name: f.name, id: f.id, upstream: !!f.upstreamEnabled, link: LINK.feeds() }));
      if (feeds.length) addFinding('info', `${feeds.length} artifact feed(s)`, 'Enumerated packaging feeds. Review view scope and upstream sources for package-substitution exposure.', 'feeds', LINK.feeds());
      sink.log(`  feeds: ${feeds.length}`, 'd');
    } catch (e) { sink.log(`  feeds unreachable from this origin (${e.message}); feed enum skipped`, 'w'); corsHint(); }
  }

  // ---------------------------- render: secrets -------------------------
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const mask = (v) => v.length <= 8 ? v[0] + '***' : v.slice(0, 4) + '…' + v.slice(-4);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const secSort = (a, b) => (a.conf === 'firm' ? 0 : 1) - (b.conf === 'firm' ? 0 : 1) || SEV[a.sev] - SEV[b.sev] || (b.count || 1) - (a.count || 1);
  function updateCounts() {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    F.secrets.forEach(s => { if (c[s.sev] !== undefined) c[s.sev]++; });
    $('#ca').textContent = F.secrets.length; $('#cc').textContent = c.critical; $('#ch').textContent = c.high; $('#cm').textContent = c.medium; $('#cl').textContent = c.low;
    $('#nfind').textContent = F.secrets.length;
    if (uiState === 'min') updateMinBadge();
  }
  let filter = 'all';
  const colW = [72, 150, 300, 460]; // sev, rule, value, location — user-resizable
  function applyCols() {
    R.querySelectorAll('#tablewrap col').forEach((c, i) => { if (colW[i]) c.style.width = colW[i] + 'px'; });
    const t = R.querySelector('#tablewrap table'); if (t) t.style.width = colW.reduce((a, b) => a + b, 0) + 'px';
  }
  function wireResizers() {
    R.querySelectorAll('#tablewrap .colrz').forEach(rz => rz.onmousedown = (e) => {
      e.preventDefault(); e.stopPropagation();
      const idx = +rz.dataset.c, startX = e.clientX, startW = colW[idx];
      const move = (ev) => { colW[idx] = Math.max(44, startW + ev.clientX - startX); applyCols(); };
      const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
      window.addEventListener('mousemove', move); window.addEventListener('mouseup', up);
    });
  }
  function renderFindings() {
    const q = $('#search').value.trim().toLowerCase(), masking = $('#mask').checked;
    const firm = F.secrets.filter(s => s.conf === 'firm').length;
    updateCounts();
    $('#findmeta').innerHTML = `<b style="color:#86efac">${firm} firm</b> · ${F.secrets.length - firm} heuristic · ${F.secrets.length} unique values`;
    let rows = F.secrets.filter(s => (filter === 'all' ? true : filter === 'firm' ? s.conf === 'firm' : s.sev === filter) && (!q || s.rule.includes(q) || (s.occurrences || []).map(o => o.source).join(' ').toLowerCase().includes(q)));
    rows.sort(secSort); rows = rows.slice(0, 500);
    const wrap = $('#tablewrap');
    if (!F.secrets.length) { wrap.innerHTML = '<div class="empty">No secrets matched.</div>'; return; }
    if (!rows.length) { wrap.innerHTML = '<div class="empty">Nothing for this filter.</div>'; return; }
    wrap.innerHTML = `<div class="tablescroll"><table style="table-layout:fixed"><colgroup><col><col><col><col></colgroup><thead><tr><th>sev<span class="colrz" data-c="0"></span></th><th>rule<span class="colrz" data-c="1"></span></th><th>value<span class="colrz" data-c="2"></span></th><th>location<span class="colrz" data-c="3"></span></th></tr></thead><tbody>${rows.map((s, i) => {
      const src = esc(s.source);
      const loc = s.link ? `<a href="${esc(s.link)}" target="_blank" rel="noopener">${src} ↗</a>` : src;
      return `<tr><td><span class="sev ${s.sev}">${s.sev}</span></td><td>${s.rule}${s.conf === 'heuristic' ? '<div style="color:#6b7280;font-size:10px">heuristic</div>' : ''}</td><td class="val" data-i="${i}" title="click to copy">${esc(masking ? mask(s.value) : s.value)}</td><td class="src">${loc}${(s.count || 1) > 1 ? ` <span class="tag">×${s.count}</span>` : ''}</td></tr>`;
    }).join('')}</tbody></table></div>` + (rows.length >= 500 ? `<div class="hint">Showing first 500. Export for the full set.</div>` : '');
    wrap.querySelectorAll('td.val').forEach(td => td.onclick = () => { navigator.clipboard.writeText(rows[+td.dataset.i].value); toast('copied'); });
    applyCols(); wireResizers();
  }
  R.querySelectorAll('#filters .fbtn').forEach(b => b.onclick = () => { filter = b.dataset.f; R.querySelectorAll('#filters .fbtn').forEach(x => x.classList.toggle('on', x === b)); renderFindings(); });
  $('#search').oninput = renderFindings; $('#mask').onchange = renderFindings;

  // ---------------------------- render: recon ---------------------------
  function renderRecon() {
    $('#nrec').textContent = F.findings.length;
    const rc = F.recon;
    const A = (link, label) => link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${esc(label || 'open')} ↗</a>` : '';
    const findings = [...F.findings].sort((a, b) => SEV[a.sev] - SEV[b.sev]);
    let html = '';
    html += `<div class="card"><h4>Posture findings (${findings.length})</h4>${findings.length ? findings.map(f => `<div class="find"><span class="sev ${f.sev}">${f.sev}</span><div class="txt"><b>${esc(f.title)}</b><small>${esc(f.detail)}</small>${f.link ? `<div style="margin-top:3px">${A(f.link, 'open in portal')}</div>` : ''}</div></div>`).join('') : '<div class="empty">None.</div>'}</div>`;
    if (rc.identity) html += `<div class="card"><h4>Identity</h4><div class="kv"><span>user</span><span>${esc(rc.identity.displayName)}</span></div>${rc.userCount != null ? `<div class="kv"><span>org users / groups</span><span>${rc.userCount} / ${rc.groupCount}</span></div>` : ''}${rc.adminGroups && rc.adminGroups.length ? `<div class="kv"><span>admin groups</span><span>${esc(rc.adminGroups.join(', '))}</span></div>` : ''}${rc.svcPrincipals && rc.svcPrincipals.length ? `<div class="kv"><span>service identities</span><span>${rc.svcPrincipals.length}</span></div>` : ''}</div>`;
    if (rc.cloudReach.length) html += `<div class="card"><h4>Cloud reachability (${rc.cloudReach.length})</h4><div class="tablescroll"><table><thead><tr><th>provider</th><th>target</th><th>use</th><th></th></tr></thead><tbody>${rc.cloudReach.map(r => `<tr><td>${esc(r.provider)}<div style="color:#6b7280;font-size:11px">${esc(r.name)}</div></td><td class="src">${esc(r.target)}<span class="tag">${esc(r.scheme)}</span></td><td>${r.canUse === true ? '<span class="sev high">yes</span>' : r.canUse === false ? '<span class="sev low">no</span>' : '<span class="sev info">?</span>'}</td><td class="src">${A(r.link)}</td></tr>`).join('')}</tbody></table></div></div>`;
    if (rc.agentPools.length) { const sh = rc.agentPools.filter(p => !p.isHosted);
      html += `<div class="card"><h4>Agent pools (${rc.agentPools.length}, ${sh.length} self-hosted)</h4>${sh.length ? sh.map(p => `<div class="kv"><span>${esc(p.name)} ${A(p.link)}</span><span>${(p.agents || []).map(a => esc(a.host || a.name)).slice(0, 4).join(', ') || p.size + ' agents'}</span></div>`).join('') : '<div class="hint">All Microsoft-hosted.</div>'}</div>`; }
    if (rc.extensions.length) html += `<div class="card"><h4>Extensions (${rc.extensions.length}${rc.decorators.length ? `, ${rc.decorators.length} with decorators` : ''})</h4>${rc.extensions.filter(x => x.decorators).map(x => `<div class="kv"><span>${esc(x.name)} ${A(x.link)}</span><span class="sev high">decorator</span></div>`).join('') || '<div class="hint">No pipeline decorators found.</div>'}</div>`;
    $('#reconwrap').innerHTML = html || '<div class="empty">No recon data.</div>';
  }

  // ------------------------------ exports -------------------------------
  function dl(name, mime, content) { const b = new Blob([content], { type: mime }); const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
  const stamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  $('#ejson').onclick = () => { if (!F) return toast('run first'); dl(`adorecon-${CTX.org}-${stamp()}.json`, 'application/json', JSON.stringify(F, null, 2)); };
  $('#ehtml').onclick = () => { if (!F) return toast('run first'); dl(`adorecon-${CTX.org}-${stamp()}.html`, 'text/html', buildReport()); };

  function buildReport() {
    const rc = F.recon;
    const A = (link, label) => link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${esc(label || 'open ↗')}</a>` : '';
    const sc = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; F.secrets.forEach(s => sc[s.sev]++);
    const fc = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; F.findings.forEach(f => fc[f.sev]++);
    const firmN = F.secrets.filter(s => s.conf === 'firm').length;

    const findingsTbl = [...F.findings].sort((a, b) => SEV[a.sev] - SEV[b.sev]).map(f =>
      `<tr class="${f.sev}"><td>${f.sev}</td><td>${esc(f.title)}</td><td>${esc(f.detail)}</td><td>${A(f.link)}</td></tr>`).join('');
    const reachTbl = rc.cloudReach.map(r =>
      `<tr><td>${esc(r.provider)}</td><td>${esc(r.name)}</td><td>${esc(r.target)}</td><td>${esc(r.scheme)}</td><td>${r.canUse === true ? '<b>YES</b>' : r.canUse === false ? 'no' : '?'}</td><td>${r.canAdmin ? 'YES' : ''}</td><td>${A(r.link)}</td></tr>`).join('');
    const poolsTbl = rc.agentPools.map(p =>
      `<tr><td>${esc(p.name)}</td><td>${p.isHosted ? 'MS-hosted' : 'self-hosted'}</td><td>${esc((p.agents || []).map(a => `${a.host || a.name} (${a.os || '?'})`).join(', ')) || p.size || ''}</td><td>${A(p.link)}</td></tr>`).join('');
    const extTbl = rc.extensions.map(x =>
      `<tr class="${x.decorators ? 'high' : ''}"><td>${esc(x.name)}</td><td>${esc(x.publisher)}</td><td>${x.decorators ? '<b>decorator</b>' : ''}</td><td>${A(x.link)}</td></tr>`).join('');
    const feedTbl = (rc.feeds || []).map(f => `<tr><td>${esc(f.name)}</td><td>${f.upstream ? 'upstream enabled' : ''}</td><td>${A(f.link)}</td></tr>`).join('');
    const secTbl = [...F.secrets].sort(secSort).map(s => {
      const occ = s.occurrences || [{ source: s.source, link: s.link }];
      const shown = occ.slice(0, 12).map(o => o.link ? `<a href="${esc(o.link)}" target="_blank" rel="noopener">${esc(o.source)}</a>` : esc(o.source)).join('<br>');
      const more = occ.length > 12 ? `<br><i>+${s.count - 12} more</i>` : (s.count > occ.length ? `<br><i>(×${s.count} total)</i>` : '');
      return `<tr class="${s.sev}"><td>${s.sev}</td><td>${esc(s.conf)}</td><td>${esc(s.rule)}</td><td><code>${esc(s.value)}</code></td><td>${shown}${more}</td></tr>`;
    }).join('');
    // inventory
    const vgTbl = F.variableGroups.map(v => `<tr><td>${esc(v.project)}</td><td>${esc(v.name)}</td><td>${v.secretVars.length}</td><td>${Object.keys(v.plainVars).length}</td><td>${A(v.link)}</td></tr>`).join('');
    const pipeTbl = F.pipelines.map(p => `<tr><td>${esc(p.project)}</td><td>${esc(p.name)}</td><td>${esc(p.type)}</td><td>${A(p.link)}</td></tr>`).join('');
    const repoTbl = F.repos.map(r => `<tr><td>${esc(r.project)}</td><td>${esc(r.name)}</td><td>${r.files}</td><td>${r.scanned}</td><td>${A(r.link)}</td></tr>`).join('');
    const wikiTbl = F.wikis.map(w => `<tr><td>${esc(w.project)}</td><td>${esc(w.name)}</td><td>${A(w.link)}</td></tr>`).join('');
    const sfTbl = F.secureFiles.map(s => `<tr><td>${esc(s.project)}</td><td>${esc(s.name)}</td><td>${A(s.link)}</td></tr>`).join('');

    const sec = (id, title, count, inner) => `<section id="${id}"><h2>${esc(title)}${count != null ? ` <span class="c">${count}</span>` : ''}</h2>${inner}</section>`;
    const tbl = (head, body, cols) => `<div class="scroll"><table><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${body || `<tr><td colspan="${cols || head.length}" class="none">None found.</td></tr>`}</tbody></table></div>`;
    const idBlock = rc.identity ? `<div class="kv"><b>Authenticated identity</b> ${esc(rc.identity.displayName || '')}</div>
      ${rc.userCount != null ? `<div class="kv"><b>Org users / groups</b> ${rc.userCount} / ${rc.groupCount}</div>` : '<div class="kv note">Org identity graph not reachable from this origin (cross-origin CORS); run from the org visualstudio.com URL or collect via PAT for full graph.</div>'}
      ${rc.adminGroups && rc.adminGroups.length ? `<div class="kv"><b>Admin groups</b> ${esc(rc.adminGroups.join(', '))}</div>` : ''}
      ${rc.svcPrincipals && rc.svcPrincipals.length ? `<div class="kv"><b>Service identities</b> ${rc.svcPrincipals.length}</div>` : ''}` : '<div class="none">Identity module did not run.</div>';

    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADORecon — ${esc(CTX.org)}</title>
<style>
  :root{ --bd:#e2e8f0; --mut:#64748b; --ink:#0f172a; }
  *{ box-sizing:border-box; } body{ font:14px/1.55 system-ui,-apple-system,sans-serif; color:var(--ink); margin:0; background:#f8fafc; }
  .wrap{ max-width:1080px; margin:0 auto; padding:28px 22px 80px; }
  header{ border-bottom:2px solid var(--ink); padding-bottom:14px; margin-bottom:8px; }
  h1{ margin:0; font-size:22px; } header .meta{ color:var(--mut); font-size:12.5px; margin-top:4px; }
  .ro{ display:inline-block; font-size:11px; color:#166534; background:#dcfce7; border:1px solid #bbf7d0; padding:1px 7px; border-radius:10px; margin-left:8px; vertical-align:middle; }
  .summary{ display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
  .stat{ flex:1; min-width:120px; background:#fff; border:1px solid var(--bd); border-radius:8px; padding:10px 12px; }
  .stat b{ display:block; font-size:20px; } .stat small{ color:var(--mut); text-transform:uppercase; font-size:10.5px; letter-spacing:.5px; }
  nav{ background:#fff; border:1px solid var(--bd); border-radius:8px; padding:10px 14px; margin-bottom:22px; font-size:13px; }
  nav a{ color:#1d4ed8; text-decoration:none; margin-right:14px; white-space:nowrap; } nav a:hover{ text-decoration:underline; }
  section{ background:#fff; border:1px solid var(--bd); border-radius:8px; padding:16px 18px; margin-bottom:18px; }
  h2{ margin:0 0 10px; font-size:16px; border-bottom:1px solid var(--bd); padding-bottom:8px; }
  h2 .c{ color:var(--mut); font-weight:400; font-size:13px; }
  .scroll{ overflow-x:auto; } table{ border-collapse:collapse; width:100%; font-size:12.5px; }
  th,td{ border-bottom:1px solid var(--bd); padding:7px 9px; text-align:left; vertical-align:top; word-break:break-word; }
  th{ background:#f1f5f9; white-space:nowrap; } code{ font:12px ui-monospace,monospace; word-break:break-all; }
  td a,.kv a{ color:#1d4ed8; text-decoration:none; } td a:hover{ text-decoration:underline; }
  tr.critical td:first-child,tr.high td:first-child,tr.medium td:first-child,tr.low td:first-child,tr.info td:first-child{ font-weight:700; text-transform:uppercase; font-size:11px; }
  tr.critical td:first-child{ color:#fff; background:#b91c1c; } tr.high td:first-child{ color:#fff; background:#ea580c; }
  tr.medium td:first-child{ background:#fde68a; } tr.low td:first-child{ background:#e2e8f0; } tr.info td:first-child{ background:#dbeafe; }
  .kv{ padding:3px 0; } .kv b{ display:inline-block; min-width:180px; color:var(--mut); font-weight:600; }
  .kv.note,.none{ color:var(--mut); font-style:italic; } .none{ text-align:center; padding:14px; }
  footer{ color:var(--mut); font-size:11.5px; margin-top:24px; text-align:center; }
</style></head><body><div class="wrap">
<header>
  <h1>ADORecon — ${esc(CTX.org)}<span class="ro">READ-ONLY ASSESSMENT</span></h1>
  <div class="meta">${esc(F.meta.started)} → ${esc(F.meta.finished || '')} · ${F.meta.durationSec || '?'}s · scope: ${esc(F.projects.join(', ') || 'all projects')} · source ${esc(F.meta.url)}</div>
</header>
<div class="summary">
  <div class="stat"><b>${F.findings.length}</b><small>posture findings</small></div>
  <div class="stat"><b>${firmN}</b><small>firm secrets</small></div>
  <div class="stat"><b>${F.secrets.length}</b><small>secret values</small></div>
  <div class="stat"><b>${rc.cloudReach.length}</b><small>cloud connections</small></div>
  <div class="stat"><b>${F.projects.length}</b><small>projects</small></div>
</div>
<nav><b>Jump to:</b>
  <a href="#posture">Posture findings</a><a href="#identity">Identity</a><a href="#reach">Cloud reachability</a>
  <a href="#agents">Agent pools</a><a href="#ext">Extensions</a><a href="#feeds">Feeds</a>
  <a href="#secrets">Secrets</a><a href="#inventory">Inventory</a>
</nav>

${sec('posture', 'Posture findings', `${fc.critical}C / ${fc.high}H / ${fc.medium}M / ${fc.low}L / ${fc.info}I`, tbl(['sev', 'finding', 'detail', 'link'], findingsTbl, 4))}

${sec('identity', 'Identity & privilege', null, idBlock)}

${sec('reach', 'Cloud reachability', rc.cloudReach.length, `<p class="kv note">"use" = current identity can run a pipeline that uses the connection (evaluated via the permissions API). "?" means the check could not be evaluated and needs manual confirmation.</p>` + tbl(['provider', 'connection', 'target', 'scheme', 'can use', 'can admin', 'link'], reachTbl, 7))}

${sec('agents', 'Agent pools', rc.agentPools.length, tbl(['pool', 'type', 'agents (host / OS)', 'link'], poolsTbl, 4))}

${sec('ext', 'Extensions & decorators', rc.extensions.length, tbl(['extension', 'publisher', 'flag', 'link'], extTbl, 4))}

${sec('feeds', 'Artifact feeds', (rc.feeds || []).length, tbl(['feed', 'note', 'link'], feedTbl, 3))}

${sec('secrets', `Secrets — ${firmN} firm (${sc.critical}C / ${sc.high}H / ${sc.medium}M / ${sc.low}L)`, null, `<p class="kv note">Firm = fixed-format token, low false-positive. Heuristic = entropy/format guess, review-required. Values shown in full for the assessment.</p>` + tbl(['sev', 'conf', 'rule', 'value', 'location(s)'], secTbl, 5))}

${sec('inventory', 'Inventory (scan coverage)', null,
  `<h3 style="font-size:13px;margin:6px 0">Variable groups</h3>${tbl(['project', 'name', 'secret vars', 'plaintext vars', 'link'], vgTbl, 5)}
   <h3 style="font-size:13px;margin:14px 0 6px">Pipelines</h3>${tbl(['project', 'name', 'type', 'link'], pipeTbl, 4)}
   <h3 style="font-size:13px;margin:14px 0 6px">Repositories</h3>${tbl(['project', 'repo', 'files', 'scanned', 'link'], repoTbl, 5)}
   <h3 style="font-size:13px;margin:14px 0 6px">Wikis</h3>${tbl(['project', 'wiki', 'link'], wikiTbl, 3)}
   <h3 style="font-size:13px;margin:14px 0 6px">Secure files</h3>${tbl(['project', 'name', 'link'], sfTbl, 3)}`)}

<footer>Generated by ADORecon (read-only). All findings link to the live resource in the Azure DevOps portal. Handle secret values per engagement data-handling rules.</footer>
</div></body></html>`;
  }

  // ------------------------------- run ----------------------------------
  let running = false;
  $('#run').onclick = async () => {
    if (running) return; running = true;
    $('#run').disabled = true; $('#run').textContent = '⏳ running…';
    R.querySelector('.tab[data-t="log"]').click();
    CFG = { conc: +$('#conc').value || 5, maxp: +$('#maxp').value || 0, maxb: +$('#maxb').value || 0, allfiles: $('#allfiles').checked, entropy: $('#entropy').checked };
    const perProj = [['wiki', $('#m_wiki').checked, mWiki], ['pipelines', $('#m_pipelines').checked, mPipe], ['repos', $('#m_repos').checked, mRepos], ['logs', $('#m_logs').checked, mLogs], ['workitems', $('#m_workitems').checked, mWorkItems], ['reach', $('#m_reach').checked, mReach]].filter(m => m[1]);
    const orgMods = [['identity', $('#m_identity').checked, mIdentity], ['agents', $('#m_agents').checked, mAgents], ['extensions', $('#m_ext').checked, mExt]].filter(m => m[1]);
    F = { meta: { org: CTX.org, base: CTX.base, started: new Date().toISOString(), url: location.href, mode: 'read-only' }, projects: [], secrets: [], findings: [], wikis: [], variableGroups: [], secureFiles: [], pipelines: [], repos: [], recon: { identity: null, cloudReach: [], agentPools: [], extensions: [], decorators: [], feeds: [] } };
    const seenSecret = new Map();
    addSecret = (arr) => {
      if (!arr || !arr.length) return;
      for (const h of arr) { const ex = seenSecret.get(h.dkey);
        if (ex) { ex.count++; if (ex.occurrences.length < 50 && !ex.occurrences.some(o => o.source === h.source)) ex.occurrences.push({ source: h.source, link: h.link }); }
        else { h.count = 1; h.occurrences = [{ source: h.source, link: h.link }]; seenSecret.set(h.dkey, h); F.secrets.push(h); } }
      updateCounts();
    };
    addFinding = (sev, title, detail, ref, link) => { F.findings.push({ sev, title, detail, ref, link }); $('#nrec').textContent = F.findings.length; };
    window.ADORecon = { data: F };
    const t0 = performance.now();
    $('#logpre').innerHTML = `<span class="ok">ADORecon PRO</span> <span class="d">read-only</span> org "${CTX.org}"\n`;
    try {
      const projFilter = $('#projects').value.split(',').map(s => s.trim()).filter(Boolean);
      let projects = (await listAll('/_apis/projects?$top=1000')).map(p => ({ id: p.id, name: p.name }));
      if (projFilter.length) projects = projects.filter(p => projFilter.includes(p.name));
      if (CFG.maxp > 0) projects = projects.slice(0, CFG.maxp);
      F.projects = projects.map(p => p.name);
      sink.log(`${projects.length} project(s): ${F.projects.join(', ') || '(none)'}`);
      const total = orgMods.length + projects.length * perProj.length; let done = 0;
      for (const [name, , fn] of orgMods) { const t = performance.now();
        try { await fn(); sink.log(`✔ ${name.padEnd(10)} org  (${((performance.now() - t) / 1000).toFixed(1)}s)`, 'ok'); } catch (e) { sink.log(`✘ ${name}: ${e.message}`, 'e'); }
        sink.progress(++done, total); }
      for (const proj of projects) { for (const [name, , fn] of perProj) { const t = performance.now();
        try { await fn(proj); sink.log(`✔ ${name.padEnd(10)} ${proj.name}  (${((performance.now() - t) / 1000).toFixed(1)}s)`, 'ok'); } catch (e) { sink.log(`✘ ${name} ${proj.name}: ${e.message}`, 'e'); }
        sink.progress(++done, total); } }
      F.meta.finished = new Date().toISOString(); F.meta.durationSec = +((performance.now() - t0) / 1000).toFixed(1);
      // Cross-rule dedupe: a value already caught by a firm rule (e.g. google-key)
      // shouldn't also list under the generic high-entropy heuristic.
      const firmVals = new Set(F.secrets.filter(s => s.conf === 'firm').map(s => s.value));
      F.secrets = F.secrets.filter(s => !(s.rule === 'high-entropy' && firmVals.has(s.value)));
      sink.log(`done in ${F.meta.durationSec}s — ${F.secrets.length} secrets, ${F.findings.length} posture findings`, 'ok');
      renderFindings(); renderRecon();
      R.querySelector('.tab[data-t="recon"]').click();
    } catch (e) {
      sink.log(`fatal: ${e.message}`, 'e');
      if (e.code === 'AUTHREDIR' || e.code === 401 || e.code === 403) {
        sink.log('  → the API bounced to sign-in. Confirm this tab is signed in and reload it.', 'w');
        sink.log('  → if this org is visualstudio.com-backed, run the tool from https://<org>.visualstudio.com', 'w');
        sink.log('    so the session cookies live on the same site as the API you are calling.', 'w');
      }
      if (e.code === 'CORS') sink.log('  → this host answers with wildcard CORS, blocked for credentialed calls. Same-origin modules are unaffected.', 'w');
    }
    finally { running = false; $('#run').disabled = false; $('#run').textContent = '▶ Run recon'; setTimeout(() => $('#prog').classList.remove('on'), 1500); }
  };

  console.log('%c[ADORecon PRO]', 'color:#8b5cf6;font-weight:bold', 'read-only panel injected. Configure and Run.');
})();
