// ─── Config ────────────────────────────────────────────────────────────────
const API = '';  // empty = same origin; set to 'http://localhost:8000' for dev

const TOOL_DEFS = {
  git:                  { icon: '⎇', desc: 'Clone remote repositories' },
  trivy:                { icon: '⬡', desc: 'Container & SCA vulnerability scan' },
  tainter:              { icon: '⇝', desc: 'Source-to-sink taint analysis' },
  python_reachability:  { icon: '⊕', desc: 'Python call-graph reachability' },
  dynamic_reachability: { icon: '◉', desc: 'Runtime reachability tracing' },
  semgrep:              { icon: '§',  desc: 'Static pattern-based SAST' },
  route_extractor:      { icon: '⌥', desc: 'HTTP route extraction & mapping' },
  metadata:             { icon: '◇', desc: 'Dependency metadata enrichment' },
};

// ─── State ─────────────────────────────────────────────────────────────────
let scans = [];
let selectedTools = new Set(['trivy','tainter','python_reachability']);
let currentScan = null;
let currentTab = 'overview';
let autoRefreshInterval = null;
let currentRepoName = null;

// ─── Repo name extraction ─────────────────────────────────────────────────
function repoName(scan) {
  const raw = scan.repo_path || scan.repo_url || '';
  if (!raw) return '(unknown)';
  // strip trailing slash/whitespace, remove .git suffix
  const clean = raw.replace(/\/+$/, '').replace(/\.git$/, '');
  // return last path/URL segment
  return clean.split(/[\/]/).filter(Boolean).pop() || clean;
}

// Group scans by repo name, newest-scan-first within each group
function groupByRepo(scanList) {
  const map = {};
  for (const s of scanList) {
    const name = repoName(s);
    if (!map[name]) map[name] = [];
    map[name].push(s);
  }
  // Sort each group newest first
  for (const name of Object.keys(map)) {
    map[name].sort((a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0));
  }
  return map;
}

// ─── Init ──────────────────────────────────────────────────────────────────
(async () => {
  buildToolChips();
  buildToolsPage();
  await loadScans();
  startAutoRefresh();
})();

// ─── Navigation ────────────────────────────────────────────────────────────
const PAGES = ['scans','repo','new','tools','api','findings','settings'];

function setPage(id) {
  PAGES.forEach(p => {
    const el = document.getElementById('page-' + p);
    if (el) el.style.display = p === id ? '' : 'none';
  });
  // Highlight Scans nav item for both the repo list and repo drilldown
  const activeId = id === 'repo' ? 'scans' : id;
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.textContent.trim().toLowerCase().startsWith(
      activeId === 'new' ? 'new' : activeId === 'api' ? 'api' : activeId === 'settings' ? 'settings' : activeId
    ));
  });
}

// ─── API helpers ───────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

// ─── Normalisation ─────────────────────────────────────────────────────────
// Flatten list-level scan row (only basic fields from /scans)
function normaliseListScan(s) {
  const meta = s.metadata || {};
  return {
    ...s,
    repo_path:      s.repo_path  || meta.repo_path  || null,
    repo_url:       s.repo_url   || meta.repo_url   || null,
    tools:          s.tools      || meta.tools       || [],
    started_at:     s.started_at || s.created_at     || null,
    findings_count: s.findings_count ?? meta.findings_count ?? null,
  };
}

// Full scan normalisation — joins correlation + reachability into findings[]
function normaliseScan(full) {
  const meta = full.metadata || {};
  const findings = buildFindings(full);
  return {
    ...full,
    repo_path:       full.repo_path  || meta.repo_path  || null,
    repo_url:        full.repo_url   || meta.repo_url   || null,
    tools:           full.tools      || meta.tools       || [],
    started_at:      full.started_at || full.created_at  || null,
    findings_count:  findings.length || null,
    failed_tools:    meta.failed_tools    || [],
    pipeline_status: meta.pipeline_status || null,
    findings,
  };
}

// Join correlation results with reachability evidence keyed by cve_id
function buildFindings(scan) {
  const correlation = scan.correlation || [];
  // Fall back to pre-built findings if no correlation data (e.g. list scan or demo)
  if (!correlation.length) return scan.findings || [];

  const reachMap = {};
  for (const r of (scan.reachability || [])) {
    if (r.cve_id) reachMap[r.cve_id] = r;
  }

  const vulnMap = {};
  for (const v of (scan.vulnerabilities || [])) {
    const ids = Array.isArray(v.cve_id) ? v.cve_id : [v.cve_id];
    for (const cid of ids) { if (cid) vulnMap[cid] = v; }
  }

  return correlation.map(c => {
    const r = reachMap[c.cve_id] || {};
    const v = vulnMap[c.cve_id]  || {};
    // Support both new schema (finding_type + evidence{}) and legacy flat schema
    const ev = c.evidence || {};
    const findingType = c.finding_type || c.evidence_type || null;
    return {
      cve_id:            c.cve_id,
      verdict:           c.verdict,
      risk_score:        c.risk_score,
      priority:          c.priority,
      confidence:        c.confidence,
      finding_type:      findingType,
      // Static evidence fields (may live in evidence{} or at root for legacy)
      import_detected:   ev.import_detected   ?? r.import_detected   ?? false,
      call_chain_exists: ev.call_chain_exists  ?? r.call_chain_exists  ?? false,
      sink_reachable:    ev.sink_reachable     ?? r.sink_reachable     ?? false,
      // Dynamic evidence fields
      has_taint_flow:    ev.has_taint_flow  ?? false,
      has_coverage_hit:  ev.has_coverage_hit ?? false,
      files:             Array.isArray(ev.files) ? ev.files : (Array.isArray(r.files) ? r.files : (r.file ? [r.file] : [])),
      function:          ev.function || r.function || null,
      package:           v.package  || null,
      severity:          v.severity || null,
    };
  });
}

// ─── Load scans ────────────────────────────────────────────────────────────
async function loadScans() {
  try {
    const data = await apiFetch('/scans');
    scans = (data.scans || []).map(normaliseListScan);
    renderScans();
    updateStats();
    document.getElementById('nav-count').textContent = Object.keys(groupByRepo(scans)).length;
    document.getElementById('api-status').textContent = 'API connected';
  } catch(e) {
    renderMockScans();
    document.getElementById('api-status').textContent = 'API offline (demo)';
  }
}

function renderMockScans() {
  scans = [
    { scan_id:'sc-a1b2c3d4', repo_path:'/app/payment-service', tools:['trivy','tainter','semgrep'], status:'completed', started_at:'2025-02-28T09:12:00Z', findings_count: 7 },
    { scan_id:'sc-a1b2c3d5', repo_path:'/app/payment-service', tools:['trivy','tainter'], status:'completed', started_at:'2025-02-27T08:00:00Z', findings_count: 5 },
    { scan_id:'sc-e5f6a7b8', repo_url:'https://github.com/org/api-gateway', tools:['git','trivy','python_reachability'], status:'running', started_at:'2025-02-28T10:55:00Z', findings_count: null },
    { scan_id:'sc-c9d0e1f2', repo_path:'/app/auth-service', tools:['trivy','tainter','dynamic_reachability'], status:'partial', started_at:'2025-02-27T16:30:00Z', findings_count: 3 },
    { scan_id:'sc-k7l8m9n0', repo_url:'https://github.com/org/ml-service', tools:['git','trivy','tainter','python_reachability'], status:'pending', started_at:'2025-02-28T11:10:00Z', findings_count: null },
    { scan_id:'sc-x1y2z3w4', repo_path:'/app/checkout-service', tools:['trivy','tainter'], status:'blocked', started_at:'2025-02-28T12:00:00Z', findings_count: 2 },
    { scan_id:'sc-x1y2z3w5', repo_path:'/app/checkout-service', tools:['trivy','tainter'], status:'completed', started_at:'2025-02-27T10:00:00Z', findings_count: 1 },
  ];
  renderScans();
  updateStats();
  document.getElementById('nav-count').textContent = Object.keys(groupByRepo(scans)).length;
}

function renderScans() {
  const body = document.getElementById('scans-body');
  if (!scans.length) {
    body.innerHTML = `<div class="empty-state">
      <div class="empty-icon">⬡</div>
      <div class="empty-text">No scans yet</div>
      <div class="empty-sub">Launch your first scan from the New Scan page</div>
    </div>`;
    return;
  }

  const groups = groupByRepo(scans);
  // Sort repo names by their latest scan date (newest repo first)
  const sortedNames = Object.keys(groups).sort((a, b) => {
    const la = groups[a][0]?.started_at || '';
    const lb = groups[b][0]?.started_at || '';
    return lb.localeCompare(la);
  });

  body.innerHTML = sortedNames.map(name => {
    const repoScans  = groups[name];
    const latest     = repoScans[0];
    const statusCounts = {};
    for (const s of repoScans) statusCounts[s.status] = (statusCounts[s.status] || 0) + 1;
    // Choose worst status badge for the row
    const worstStatus = ['blocked','failed','partial','running','started','pending','completed']
      .find(st => statusCounts[st]) || latest.status;
    const fullPath = latest.repo_path || latest.repo_url || '';
    return `
    <div class="table-row" onclick="openRepoPage('${encodeURIComponent(name)}')">
      <div class="scan-id" style="color:var(--text);font-size:0.85rem;font-weight:600">${name}</div>
      <div class="repo-path" title="${fullPath}" style="font-size:0.7rem">${truncate(fullPath, 40)}</div>
      <div style="font-size:0.75rem;color:var(--text-mute)">${repoScans.length} scan${repoScans.length !== 1 ? 's' : ''}</div>
      <div><span class="badge-status ${worstStatus}"><span class="s-dot"></span>${worstStatus}</span></div>
      <div class="ts">${fmtDate(latest.started_at)}</div>
      <div><button class="action-btn" onclick="event.stopPropagation();openRepoPage('${encodeURIComponent(name)}')">View →</button></div>
    </div>`;
  }).join('');
}

// ─── Repo drilldown ───────────────────────────────────────────────────────
function openRepoPage(encodedName) {
  currentRepoName = decodeURIComponent(encodedName);
  const groups = groupByRepo(scans);
  const repoScans = groups[currentRepoName] || [];

  const fullPath = repoScans[0]?.repo_path || repoScans[0]?.repo_url || '';
  document.getElementById('repo-page-title').textContent = currentRepoName;
  document.getElementById('repo-page-subtitle').textContent = fullPath;

  const body = document.getElementById('repo-scans-body');
  if (!repoScans.length) {
    body.innerHTML = `<div class="empty-state"><div class="empty-text">No scans</div></div>`;
  } else {
    body.innerHTML = repoScans.map(s => `
      <div class="table-row" onclick="openPanel('${s.scan_id}')">
        <div class="scan-id">${s.scan_id}</div>
        <div><span class="badge-status ${s.status}"><span class="s-dot"></span>${s.status}</span></div>
        <div class="ts">${fmtDate(s.started_at)}</div>
        <div style="font-size:0.75rem;color:var(--text-mute)">${s.findings_count != null ? s.findings_count + ' findings' : '—'}</div>
        <div class="tools-pills">${(s.tools||[]).slice(0,3).map(t=>`<span class="pill">${t}</span>`).join('')}${(s.tools||[]).length>3?`<span class="pill">+${s.tools.length-3}</span>`:''}</div>
        <div><button class="action-btn" onclick="event.stopPropagation();openPanel('${s.scan_id}')">View →</button></div>
      </div>`).join('');
  }
  setPage('repo');
}

function updateStats() {
  const repos = Object.keys(groupByRepo(scans)).length;
  document.getElementById('stat-total').textContent = repos ? `${repos} repo${repos !== 1 ? 's' : ''} · ${scans.length} scans` : '—';
  document.getElementById('stat-running').textContent = scans.filter(s => s.status === 'running' || s.status === 'started').length;
  document.getElementById('stat-confirmed').textContent = '—';
  document.getElementById('stat-likely').textContent = '—';
}

// ─── Tool chips ────────────────────────────────────────────────────────────
function buildToolChips() {
  const wrap = document.getElementById('tool-chips');
  wrap.innerHTML = Object.keys(TOOL_DEFS).map(t => `
    <div class="tool-chip ${selectedTools.has(t)?'selected':''}" onclick="toggleTool('${t}',this)">
      <span class="chip-dot"></span>${t}
    </div>
  `).join('');
}

function toggleTool(name, el) {
  if (selectedTools.has(name)) { selectedTools.delete(name); el.classList.remove('selected'); }
  else { selectedTools.add(name); el.classList.add('selected'); }
}

// ─── Tools page ────────────────────────────────────────────────────────────
function buildToolsPage() {
  const grid = document.getElementById('tools-grid');
  grid.innerHTML = Object.entries(TOOL_DEFS).map(([k,v]) => `
    <div class="stat-card green" style="padding:1.25rem">
      <div style="font-size:1.4rem;margin-bottom:0.5rem;opacity:0.7">${v.icon}</div>
      <div style="font-weight:600;color:var(--text);margin-bottom:0.3rem;font-family:var(--sans)">${k}</div>
      <div style="font-size:0.75rem;color:var(--text-dim)">${v.desc}</div>
    </div>
  `).join('');
}

// ─── Launch scan ───────────────────────────────────────────────────────────
async function launchScan() {
  const repo_path   = document.getElementById('f-repo-path').value.trim();
  const repo_url    = document.getElementById('f-repo-url').value.trim();
  const config_path = document.getElementById('f-config-path').value.trim();

  if (!config_path) { showHint('Config path is required'); return; }
  if (!repo_path && !repo_url) { showHint('Provide a repo path or URL'); return; }

  const btn = document.getElementById('launch-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Launching…';

  showProgress(0, 'Submitting scan request…');

  try {
    const body = {
      config_path,
      tools: [...selectedTools],
      ...(repo_path ? { repo_path } : {}),
      ...(repo_url  ? { repo_url  } : {}),
    };
    const res = await apiFetch('/scan', { method:'POST', body: JSON.stringify(body) });
    showProgress(100, 'Scan queued — ID: ' + res.scan_id);
    toast(`Scan started: ${res.scan_id}`, 'success');
    setTimeout(() => { setPage('scans'); loadScans(); hideProgress(); }, 1500);
  } catch(e) {
    // Demo mode — fake a pending scan
    const fakeId = 'sc-' + Math.random().toString(36).slice(2,10);
    showProgress(100, 'Demo: Scan queued — ID: ' + fakeId);
    toast(`Demo scan started: ${fakeId}`, 'info');
    scans.unshift({ scan_id: fakeId, repo_path, repo_url, tools:[...selectedTools], status:'pending', started_at: new Date().toISOString() });
    setTimeout(() => { setPage('scans'); renderScans(); updateStats(); hideProgress(); }, 1500);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '▶ Launch Scan';
  }
}

function resetForm() {
  ['f-repo-path','f-repo-url','f-config-path'].forEach(id => document.getElementById(id).value='');
  selectedTools = new Set(['trivy','tainter','python_reachability']);
  buildToolChips();
  hideProgress();
}

function showHint(msg) {
  const h = document.getElementById('form-hint');
  h.style.color = 'var(--red)';
  h.textContent = '⚠ ' + msg;
  setTimeout(() => h.textContent='', 3000);
}

function showProgress(pct, label) {
  document.getElementById('launch-progress').style.display = '';
  document.getElementById('progress-fill').style.width = pct+'%';
  document.getElementById('progress-label').textContent = label;
}

function hideProgress() {
  document.getElementById('launch-progress').style.display = 'none';
}

// ─── Detail panel ──────────────────────────────────────────────────────────
async function openPanel(scanId) {
  currentScan = scans.find(s => s.scan_id === scanId) || { scan_id: scanId };
  document.getElementById('panel-title').textContent = scanId;
  document.getElementById('panel-overlay').classList.add('open');
  document.getElementById('detail-panel').classList.add('open');

  renderPanelOverview(currentScan);

  try {
    const full = await apiFetch('/scan/' + scanId);
    currentScan = normaliseScan(full);
    renderPanelOverview(currentScan);
    renderPanelFindings(currentScan);
    renderPanelRaw(full);  // show raw API response, not normalised
  } catch(e) {
    renderPanelFindings(normaliseScan(currentScan));
    renderPanelRaw(currentScan);
  }
}

function closePanel() {
  document.getElementById('panel-overlay').classList.remove('open');
  document.getElementById('detail-panel').classList.remove('open');
}

function setTab(name, el) {
  currentTab = name;
  ['overview','findings','raw'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t===name ? '' : 'none';
  });
  document.querySelectorAll('.tab-item').forEach(i => i.classList.remove('active'));
  el.classList.add('active');
}

function renderPanelOverview(scan) {
  const failedBanner = scan.failed_tools && scan.failed_tools.length
    ? `<div style="margin-top:1rem;padding:0.6rem 0.75rem;background:var(--amber-dim);border:1px solid #f5a62330;border-radius:4px;font-size:0.7rem;color:var(--amber)">
        ⚠ ${scan.failed_tools.length} tool(s) skipped: <strong>${scan.failed_tools.join(', ')}</strong> — results may be incomplete
      </div>`
    : '';

  document.getElementById('tab-overview').innerHTML = `
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-key">Scan ID</div><div class="meta-val green">${scan.scan_id||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Status</div><div class="meta-val"><span class="badge-status ${scan.status||'pending'}"><span class="s-dot"></span>${scan.status||'—'}</span></div></div>
      <div class="meta-item"><div class="meta-key">Repository</div><div class="meta-val">${scan.repo_path||scan.repo_url||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Started</div><div class="meta-val">${fmtDate(scan.started_at)||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Tools</div><div class="meta-val">${(scan.tools||[]).join(', ')||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Findings</div><div class="meta-val">${scan.findings_count != null ? scan.findings_count : '—'}</div></div>
    </div>
    ${failedBanner}
    ${scan.status==='running'||scan.status==='started'
      ? `<div class="progress-bar-wrap"><div class="progress-bar" style="width:60%"></div></div>
         <div style="font-size:0.7rem;color:var(--text-dim);margin-top:0.4rem">Scan in progress…</div>`
      : ''}
  `;
}

function renderPanelFindings(scan) {
  // Use real normalised findings; fall back to demo data only when API is offline
  const findings = (scan.findings && scan.findings.length)
    ? scan.findings
    : generateMockFindings(scan.scan_id);

  const el = document.getElementById('tab-findings');
  if (!findings.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon">✓</div>
      <div class="empty-text">No findings</div>
      <div class="empty-sub">Nothing reachable detected in this scan</div>
    </div>`;
    return;
  }

  // Summary bar
  const counts = { CONFIRMED:0, LIKELY:0, POSSIBLE:0, NOT_OBSERVED:0 };
  for (const f of findings) counts[f.verdict] = (counts[f.verdict]||0) + 1;
  const summaryBar = `
    <div class="findings-summary">
      ${counts.CONFIRMED   ? `<span class="fsumm red">  ● ${counts.CONFIRMED}   CONFIRMED</span>`   : ''}
      ${counts.LIKELY      ? `<span class="fsumm amber">● ${counts.LIKELY}      LIKELY</span>`      : ''}
      ${counts.POSSIBLE    ? `<span class="fsumm blue"> ● ${counts.POSSIBLE}    POSSIBLE</span>`    : ''}
      ${counts.NOT_OBSERVED? `<span class="fsumm dim">  ● ${counts.NOT_OBSERVED} NOT OBSERVED</span>`: ''}
    </div>`;

  el.innerHTML = summaryBar + findings.map(f => {
    const verdict      = f.verdict || 'NOT_OBSERVED';
    const findingType  = f.finding_type || null;
    const isDynamic    = findingType === 'dynamic';
    const isStatic     = findingType === 'static';
    const isSemgrep    = findingType === 'semgrep';
    const severityCol  = { CRITICAL:'var(--red)', HIGH:'var(--amber)', MEDIUM:'var(--blue)', LOW:'var(--text-dim)' }[f.severity] || 'var(--text-dim)';
    const scoreBar     = f.risk_score != null
      ? `<div class="risk-bar-wrap"><div class="risk-bar" style="width:${Math.min(f.risk_score/10*100,100)}%;background:${f.risk_score>=5?'var(--red)':f.risk_score>=3?'var(--amber)':'var(--green)'}"></div></div>`
      : '';

    // Dynamic findings: taint-flow + coverage chain
    // Static findings:  import → call-chain → sink chain
    let chain;
    if (isDynamic) {
      chain = [
        { label: 'Taint flow',    hit: f.has_taint_flow,  tip: 'Tainter traced a source-to-sink taint flow for this package' },
        { label: 'Runtime hit',   hit: f.has_coverage_hit, tip: 'Package executed at runtime (dynamic coverage confirmed)' },
      ].map((step, i) => `
        <div class="chain-step ${step.hit ? 'hit' : 'miss'}" title="${step.tip}">
          <span class="chain-dot">${step.hit ? '●' : '○'}</span>
          <span class="chain-label">${step.label}</span>
          ${i < 1 ? '<span class="chain-arrow">→</span>' : ''}
        </div>
      `).join('');
    } else {
      chain = [
        { label: 'Import',     hit: f.import_detected,   tip: 'Package is imported in the codebase' },
        { label: 'Call chain', hit: f.call_chain_exists,  tip: 'Call chain traced to vulnerable function' },
        { label: 'Sink hit',   hit: f.sink_reachable,     tip: 'Sink statically reachable' },
      ].map((step, i) => `
        <div class="chain-step ${step.hit ? 'hit' : 'miss'}" title="${step.tip}">
          <span class="chain-dot">${step.hit ? '●' : '○'}</span>
          <span class="chain-label">${step.label}</span>
          ${i < 2 ? '<span class="chain-arrow">→</span>' : ''}
        </div>
      `).join('');
    }

    const findingTypeBadge = findingType
      ? `<span class="evidence-badge ${findingType}">${isDynamic ? '◉ dynamic' : isStatic ? '◧ static' : '§ semgrep'}</span>`
      : '<span class="evidence-badge none">no evidence</span>';

    const filesHtml = f.files && f.files.length
      ? `<div class="finding-files">${f.files.map(fp => `<span class="file-pill">${fp}</span>`).join('')}</div>`
      : '';

    const fnHtml = f.function
      ? `<div class="finding-fn"><span class="fn-label">fn</span> <code>${f.function}</code></div>`
      : '';

    return `
    <div class="finding-item verdict-${verdict}">
      <!-- Row 1: verdict + CVE + priority + package + severity + finding type -->
      <div class="finding-header">
        <span class="verdict-badge ${verdict}">${verdict}</span>
        <span class="finding-cve">${f.cve_id || f.check_id || 'N/A'}</span>
        ${f.priority ? `<span class="priority-badge ${f.priority}">${f.priority}</span>` : ''}
        ${f.severity ? `<span class="sev-chip" style="color:${severityCol}">${f.severity}</span>` : ''}
        ${findingTypeBadge}
        <span class="finding-pkg">${f.package || ''}</span>
      </div>

      <!-- Row 2: risk score bar -->
      ${f.risk_score != null ? `
      <div class="finding-risk-row">
        <span class="risk-label">Risk</span>
        <span class="risk-value" style="color:${f.risk_score>=5?'var(--red)':f.risk_score>=3?'var(--amber)':'var(--green)'}">${f.risk_score}</span>
        ${scoreBar}
        <span class="risk-conf">${f.confidence != null ? Math.round(f.confidence*100)+'% confidence' : ''}</span>
      </div>` : ''}

      <!-- Row 3: reachability chain (dynamic=taint+coverage, static=import+callchain+sink) -->
      ${!isSemgrep ? `
      <div class="finding-chain">
        <span class="chain-title">${isDynamic ? '◉ dynamic' : '◧ static'}</span>
        <div class="chain-steps">${chain}</div>
      </div>` : ''}

      <!-- Row 4: files + function -->
      ${filesHtml}${fnHtml}
    </div>`;
  }).join('');
}

function renderPanelRaw(scan) {
  const raw = JSON.stringify(scan, null, 2);
  document.getElementById('tab-raw').innerHTML = `
    <div style="position:relative">
      <button
        id="copy-raw-btn"
        onclick="copyRawJson(this)"
        style="position:absolute;top:0.5rem;right:0.5rem;z-index:2;padding:0.25rem 0.6rem;font-size:0.65rem;font-family:var(--mono);background:var(--surface);border:1px solid var(--border);border-radius:3px;color:var(--text-dim);cursor:pointer;transition:all 0.15s"
        onmouseover="this.style.color='var(--text)';this.style.borderColor='var(--text-mute)'"
        onmouseout="this.style.color='var(--text-dim)';this.style.borderColor='var(--border)'"
      >⎘ Copy</button>
      <pre id="raw-json-pre" style="font-size:0.7rem;color:var(--text-dim);white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1rem;max-height:500px;overflow:auto">${raw.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
    </div>
  `;
}

async function copyRawJson(btn) {
  const pre = document.getElementById('raw-json-pre');
  if (!pre) return;
  try {
    await navigator.clipboard.writeText(pre.textContent);
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied';
    btn.style.color = 'var(--green)';
    btn.style.borderColor = 'var(--green)';
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.style.color = 'var(--text-dim)';
      btn.style.borderColor = 'var(--border)';
    }, 2000);
  } catch {
    toast('Copy failed — select and copy manually', 'error');
  }
}

// Demo fallback — only used when API is offline
function generateMockFindings(scanId) {
  if (!scanId || scanId.includes('c9d0') || scanId.includes('k7l8')) return [];
  return [
    // Dynamic: taint flow confirmed + runtime coverage hit → CONFIRMED
    { cve_id:'CVE-2024-12345', package:'pyyaml',   verdict:'CONFIRMED',    priority:'P1', finding_type:'dynamic', has_taint_flow:true,  has_coverage_hit:true,  confidence:0.95, risk_score:7.8, severity:'CRITICAL', files:['src/app.py'] },
    // Static: import detected + call chain → LIKELY
    { cve_id:'CVE-2024-12345', package:'pyyaml',   verdict:'LIKELY',       priority:'P2', finding_type:'static',  import_detected:true, call_chain_exists:true, sink_reachable:false, confidence:0.70, risk_score:4.68, severity:'CRITICAL', files:['src/app.py'] },
    // Static: import only → POSSIBLE
    { cve_id:'CVE-2024-67890', package:'requests', verdict:'POSSIBLE',     priority:'P3', finding_type:'static',  import_detected:true, call_chain_exists:false, sink_reachable:false, confidence:0.40, risk_score:2.6, severity:'HIGH', files:[] },
    // Static: no evidence
    { cve_id:'CVE-2023-11111', package:'pillow',   verdict:'NOT_OBSERVED', priority:'P4', finding_type:'static',  import_detected:false, call_chain_exists:false, sink_reachable:false, confidence:0.10, risk_score:1.0, severity:'LOW',  files:[] },
  ].slice(0, scanId.includes('a1b2')?4:1);
}

// ─── Auto refresh ──────────────────────────────────────────────────────────
function startAutoRefresh() {
  autoRefreshInterval = setInterval(() => {
    if (scans.some(s => s.status === 'running' || s.status === 'pending' || s.status === 'started')) {
      loadScans();
    }
  }, 8000);
}

// ─── Auth info ─────────────────────────────────────────────────────────────
function showAuthInfo() {
  setPage('api');
  toast('Auth page — Google SSO + API keys planned', 'info');
}

// ─── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type='info') {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type==='success'?'✓':type==='error'?'✕':'ℹ'}</span>${msg}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+'…' : (s||'—'); }

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60)    return `${Math.round(diff)}s ago`;
  if (diff < 3600)  return `${Math.round(diff/60)}m ago`;
  if (diff < 86400) return `${Math.round(diff/3600)}h ago`;
  return d.toLocaleDateString();
}
