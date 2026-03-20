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

// ─── Auth state ────────────────────────────────────────────────────────────
// Token survives page reloads via sessionStorage.
// On server restart (file change during dev), boot_id changes → auto-logout.
let authToken = sessionStorage.getItem('vr_token') || null;
let _loggedInUsername = sessionStorage.getItem('vr_user') || '';

function isLoggedIn() { return !!authToken; }

function setAuthToken(token) {
  authToken = token;
  if (token) {
    sessionStorage.setItem('vr_token', token);
    sessionStorage.setItem('vr_user', _loggedInUsername);
  } else {
    sessionStorage.removeItem('vr_token');
    sessionStorage.removeItem('vr_user');
    sessionStorage.removeItem('vr_boot_id');
  }
  updateAuthUI();
}

// Check if the server restarted (new boot_id) — if so, force logout
async function checkBootId() {
  try {
    const res = await fetch(API + '/health');
    if (!res.ok) return;
    const data = await res.json();
    const prevBoot = sessionStorage.getItem('vr_boot_id');
    if (prevBoot && data.boot_id && prevBoot !== data.boot_id) {
      // Server restarted — clear session
      authToken = null;
      _loggedInUsername = '';
      sessionStorage.removeItem('vr_token');
      sessionStorage.removeItem('vr_user');
      sessionStorage.removeItem('vr_boot_id');
      updateAuthUI();
      toast('Server restarted — please sign in again', 'info');
      return;
    }
    if (data.boot_id) sessionStorage.setItem('vr_boot_id', data.boot_id);
  } catch(e) { /* server unreachable — leave state as-is */ }
}

function updateAuthUI() {
  const loginPage = document.getElementById('login-page');
  const appLayout = document.getElementById('app-layout');
  const topbar = document.getElementById('topbar');
  if (isLoggedIn()) {
    loginPage.style.display = 'none';
    appLayout.style.display = '';
    topbar.style.display = '';
    const un = document.getElementById('profile-username');
    if (un) un.textContent = _loggedInUsername || 'user';
  } else {
    loginPage.style.display = '';
    appLayout.style.display = 'none';
    topbar.style.display = 'none';
  }
}

async function doLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  if (!username || !password) { errEl.textContent = 'Username and password required'; return; }
  try {
    const res = await fetch(API + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      errEl.textContent = body.detail || 'Invalid credentials';
      return;
    }
    const data = await res.json();
    _loggedInUsername = username;
    setAuthToken(data.access_token);
    // Store current boot_id so we detect server restarts
    try {
      const h = await fetch(API + '/health');
      if (h.ok) { const hd = await h.json(); if (hd.boot_id) sessionStorage.setItem('vr_boot_id', hd.boot_id); }
    } catch(e) {}
    toast('Signed in', 'success');
    loadScans();
    startAutoRefresh();
  } catch (e) {
    errEl.textContent = 'Cannot reach API — is the server running?';
  }
}

function doLogout() {
  setAuthToken(null);
  scans = [];
  toast('Signed out', 'info');
}

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
  // Check if server restarted since last session
  if (isLoggedIn()) {
    await checkBootId();
  }
  updateAuthUI();
  if (isLoggedIn()) {
    await loadScans();
    startAutoRefresh();
  }
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
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
  const res = await fetch(API + path, { headers, ...opts });
  if (res.status === 401) {
    // Token expired or invalid — clear and prompt login
    setAuthToken(null);
    toast('Session expired — please sign in again', 'error');
    throw new Error('Unauthorized');
  }
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

    // DAST findings carry their own evidence structure
    if (findingType === 'dast') {
      return {
        cve_id:            c.cve_id,
        verdict:           c.verdict,
        risk_score:        c.risk_score,
        priority:          c.priority,
        confidence:        c.confidence,
        finding_type:      'dast',
        severity:          ev.severity || 'HIGH',
        evidence:          ev,
        iterations_used:   ev.iterations_used || null,
      };
    }

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
      fix_version:       v.fix_version || v.fixed_version || null,
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
    scans = [];
    renderScans();
    updateStats();
    document.getElementById('api-status').textContent = 'API offline';
  }
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
    showProgress(0, '');
    hideProgress();
    toast('Failed to launch scan: ' + e.message, 'error');
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
  const panel = document.getElementById('detail-panel');
  document.getElementById('panel-overlay').classList.remove('open');
  panel.classList.remove('open', 'dragging', 'maximised');
  panel.style.width = '';
  _updateMaxIcon();
}

function toggleMaxPanel() {
  const panel = document.getElementById('detail-panel');
  if (!panel.classList.contains('open')) return;
  panel.classList.toggle('maximised');
  if (panel.classList.contains('maximised')) {
    panel.style.width = '';
  }
  _updateMaxIcon();
}

function _updateMaxIcon() {
  const btn = document.getElementById('panel-max-btn');
  if (!btn) return;
  const panel = document.getElementById('detail-panel');
  const icon = btn.querySelector('i');
  if (panel.classList.contains('maximised')) {
    icon.className = 'fas fa-compress';
    btn.title = 'Restore';
  } else {
    icon.className = 'fas fa-expand';
    btn.title = 'Maximise';
  }
}

// ─── Sidebar toggle ──────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById('app-layout').classList.toggle('sidebar-collapsed');
}

// ─── Profile menu ─────────────────────────────────────────────────────────
function toggleProfileMenu(event) {
  event.stopPropagation();
  document.getElementById('profile-menu').classList.toggle('open');
}
document.addEventListener('click', () => {
  const menu = document.getElementById('profile-menu');
  if (menu) menu.classList.remove('open');
});

// ─── Resizable panel (drag left edge to widen) ───────────────────────────
(function() {
  let resizing = false, startX = 0, startW = 0;
  const MIN_W = 400;

  document.addEventListener('mousemove', function(e) {
    const panel = document.getElementById('detail-panel');
    if (!panel || !panel.classList.contains('open')) return;
    if (panel.classList.contains('maximised')) { document.body.style.cursor = ''; return; }

    if (resizing) {
      const delta = startX - e.clientX;
      const newW = Math.max(MIN_W, Math.min(window.innerWidth - 20, startW + delta));
      panel.style.width = newW + 'px';
      return;
    }

    // Show resize cursor when hovering near the left edge of the panel
    const rect = panel.getBoundingClientRect();
    if (Math.abs(e.clientX - rect.left) < 6 && e.clientY >= rect.top && e.clientY <= rect.bottom) {
      document.body.style.cursor = 'ew-resize';
    } else {
      document.body.style.cursor = '';
    }
  });

  document.addEventListener('mousedown', function(e) {
    const panel = document.getElementById('detail-panel');
    if (!panel || !panel.classList.contains('open')) return;
    if (panel.classList.contains('maximised')) return;

    const rect = panel.getBoundingClientRect();
    if (Math.abs(e.clientX - rect.left) < 6 && e.clientY >= rect.top && e.clientY <= rect.bottom) {
      resizing = true;
      startX = e.clientX;
      startW = rect.width;
      panel.classList.add('dragging');
      e.preventDefault();
    }
  });

  document.addEventListener('mouseup', function() {
    if (!resizing) return;
    resizing = false;
    document.body.style.cursor = '';
    const panel = document.getElementById('detail-panel');
    if (panel) panel.classList.remove('dragging');
  });
})();

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
  const findings = scan.findings || [];

  const el = document.getElementById('tab-findings');
  if (!findings.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon">✓</div>
      <div class="empty-text">No findings</div>
      <div class="empty-sub">Nothing reachable detected in this scan</div>
    </div>`;
    return;
  }

  // Split DAST findings from package findings
  const dastFindings = findings.filter(f => f.finding_type === 'dast');
  const pkgFindings  = findings.filter(f => f.finding_type !== 'dast');

  // Summary bar — count all (normalise verdict buckets)
  const _confirmedVerdicts = new Set(['CONFIRMED','STATICALLY_REACHABLE','DYNAMICALLY_CONFIRMED','DYNAMICALLY_REACHABLE']);
  const _notReachVerdicts  = new Set(['NOT_OBSERVED','NOT_REACHABLE','UNREACHABLE']);
  const counts = { CONFIRMED:0, LIKELY:0, POSSIBLE:0, NOT_OBSERVED:0 };
  for (const f of findings) {
    const v = f.verdict || 'NOT_OBSERVED';
    if (_confirmedVerdicts.has(v))     counts.CONFIRMED++;
    else if (v === 'LIKELY')           counts.LIKELY++;
    else if (v === 'POSSIBLE')         counts.POSSIBLE++;
    else if (_notReachVerdicts.has(v))  counts.NOT_OBSERVED++;
    else                               counts.LIKELY++;  // fallback
  }
  const notReachCount = counts.NOT_OBSERVED;
  const summaryBar = `
    <div class="findings-summary">
      ${counts.CONFIRMED   ? `<span class="fsumm red">  ● ${counts.CONFIRMED} CONFIRMED</span>`   : ''}
      ${counts.LIKELY      ? `<span class="fsumm amber">● ${counts.LIKELY} LIKELY</span>`      : ''}
      ${counts.POSSIBLE    ? `<span class="fsumm blue"> ● ${counts.POSSIBLE} POSSIBLE</span>`    : ''}
      ${notReachCount       ? `<span class="fsumm dim">  ● ${notReachCount} Not Reachable</span>`: ''}
    </div>`;

  // ── DAST section ──────────────────────────────────────────────────
  let dastHtml = '';
  if (dastFindings.length) {
    const dastConfirmed = dastFindings.filter(f => f.verdict === 'CONFIRMED').length;
    const ev = dastFindings[0].evidence || dastFindings[0];
    const vulnClass = (ev.vuln_class || 'sql_injection').replace(/_/g, ' ').toUpperCase();

    dastHtml = `
    <div class="dast-section">
      <div class="dast-header">
        <span class="dast-title">INTELLIGENT DAST — ${vulnClass} (${dastConfirmed} CONFIRMED)</span>
      </div>
      ${dastFindings.map(df => {
        const de = df.evidence || df;
        const sev = de.severity || df.severity || 'HIGH';
        const sevCol = { CRITICAL:'var(--red)', HIGH:'var(--amber)', MEDIUM:'var(--blue)', LOW:'var(--text-dim)' }[sev] || 'var(--amber)';
        return `
        <div class="dast-finding">
          <div class="dast-finding-row">
            <span class="sev-chip" style="color:${sevCol}">${sev}</span>
            <span style="font-weight:600;color:var(--text)">${(de.vuln_class||'sql_injection').replace(/_/g,' ').toUpperCase()}</span>
            <span class="verdict-badge CONFIRMED" style="margin-left:auto">CONFIRMED</span>
          </div>
          <div class="dast-meta-grid">
            <div class="dast-meta-item"><span class="dast-meta-key">ENDPOINT</span><span class="dast-meta-val">${de.endpoint || '—'}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">ITERATIONS</span><span class="dast-meta-val">${df.iterations_used || '—'}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">COVERAGE DELTA</span><span class="dast-meta-val">${(de.files||[]).length}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">METHOD</span><span class="dast-meta-val">${(de.confirmation_method||'—').replace(/_/g,' ')}</span></div>
          </div>
          ${de.payload ? `<div class="dast-payload"><code>${escHtml(de.payload)}</code></div>` : ''}
          ${de.reasoning ? `<div class="dast-reasoning">${escHtml(de.reasoning)}</div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
  }

  // ── Package findings table ────────────────────────────────────────
  // Group by package — merge CVEs per package
  const pkgMap = {};
  for (const f of pkgFindings) {
    const pkg = f.package || f.cve_id || 'unknown';
    if (!pkgMap[pkg]) pkgMap[pkg] = { ...f, cves: [], allFiles: [] };
    if (f.cve_id) pkgMap[pkg].cves.push(f.cve_id);
    if (f.files) pkgMap[pkg].allFiles.push(...f.files);
    // Upgrade verdict: CONFIRMED > LIKELY > POSSIBLE > NOT_OBSERVED
    const rank = { CONFIRMED:4, LIKELY:3, POSSIBLE:2, NOT_OBSERVED:1 };
    if ((rank[f.verdict]||0) > (rank[pkgMap[pkg].verdict]||0)) {
      pkgMap[pkg].verdict = f.verdict;
      pkgMap[pkg].confidence = f.confidence;
      pkgMap[pkg].risk_score = f.risk_score;
    }
    // Merge evidence
    if (f.import_detected) pkgMap[pkg].import_detected = true;
    if (f.call_chain_exists) pkgMap[pkg].call_chain_exists = true;
    if (f.sink_reachable) pkgMap[pkg].sink_reachable = true;
    if (f.has_taint_flow) pkgMap[pkg].has_taint_flow = true;
    if (f.has_coverage_hit) pkgMap[pkg].has_coverage_hit = true;
    // Collect functions
    if (f.function) {
      if (!pkgMap[pkg].allFunctions) pkgMap[pkg].allFunctions = [];
      pkgMap[pkg].allFunctions.push(f.function);
    }
    // Track finding types for status line
    if (f.finding_type) {
      if (!pkgMap[pkg].findingTypes) pkgMap[pkg].findingTypes = new Set();
      pkgMap[pkg].findingTypes.add(f.finding_type);
    }
  }

  const pkgCards = Object.entries(pkgMap).map(([pkg, f]) => {
    const verdict = f.verdict || 'NOT_OBSERVED';
    const verdictMap = {
      'CONFIRMED':             { label: 'CONFIRMED',             cls: 'CONFIRMED' },
      'LIKELY':                { label: 'LIKELY',                 cls: 'LIKELY' },
      'POSSIBLE':              { label: 'POSSIBLE',              cls: 'POSSIBLE' },
      'NOT_OBSERVED':          { label: 'NOT REACHABLE',         cls: 'not-reachable' },
      'STATICALLY_REACHABLE':  { label: 'STATICALLY REACHABLE',  cls: 'CONFIRMED' },
      'DYNAMICALLY_CONFIRMED': { label: 'DYNAMICALLY CONFIRMED', cls: 'CONFIRMED' },
      'DYNAMICALLY_REACHABLE': { label: 'DYNAMICALLY REACHABLE', cls: 'DYNAMICALLY_REACHABLE' },
      'NOT_REACHABLE':         { label: 'NOT REACHABLE',         cls: 'not-reachable' },
      'UNREACHABLE':           { label: 'UNREACHABLE',           cls: 'not-reachable' },
    };
    const vm = verdictMap[verdict] || { label: verdict.replace(/_/g, ' '), cls: 'LIKELY' };
    const isReachable = _confirmedVerdicts.has(verdict) || verdict === 'LIKELY';
    const cardBorder = isReachable ? 'reachable' : 'not-reachable';

    // Severity chip
    const sev = (f.severity || '').toUpperCase();
    const sevCls = sev ? `sev-chip-sm ${sev.toLowerCase()}` : '';
    const sevHtml = sev ? `<span class="${sevCls}">${sev}</span>` : '';

    // --- Status line ---
    const fTypes = f.findingTypes || new Set();
    let statusLabel = 'Not Imported';
    let statusCls = 'status-none';
    if (fTypes.has('dynamic') || f.has_coverage_hit) {
      statusLabel = 'Dynamically Reachable';
      statusCls = 'status-dynamic';
    } else if (fTypes.has('static') || f.call_chain_exists || f.sink_reachable) {
      statusLabel = 'Statically Reachable';
      statusCls = 'status-static';
    } else if (f.import_detected) {
      statusLabel = 'Imported';
      statusCls = 'status-imported';
    }

    // --- Path section (only show what we actually know) ---
    const pathChecks = [];
    if (f.import_detected)   pathChecks.push({ hit: true, text: 'Package imported in application code' });
    if (f.call_chain_exists) pathChecks.push({ hit: true, text: 'Call graph confirms execution path' });
    if (f.sink_reachable)    pathChecks.push({ hit: true, text: 'Vulnerable sink is reachable' });
    if (f.has_taint_flow)    pathChecks.push({ hit: true, text: 'Taint flow from user input to sink' });
    if (f.has_coverage_hit)  pathChecks.push({ hit: true, text: 'Confirmed at runtime via coverage' });
    if (!pathChecks.length)  pathChecks.push({ hit: false, text: 'No reachability evidence found' });
    const pathHtml = pathChecks.map(p =>
      `<div class="path-check ${p.hit ? 'hit' : 'miss'}">${p.hit ? '✔' : '✘'} ${p.text}</div>`
    ).join('');

    // --- Evidence chain ---
    const evSteps = [];
    if (f.import_detected)   evSteps.push('Request');
    const uniqueFiles = [...new Set(f.allFiles)].slice(0, 2);
    if (uniqueFiles.length)  evSteps.push(uniqueFiles[0].split('/').pop());
    evSteps.push(pkg);
    if (f.has_taint_flow || f.sink_reachable) evSteps.push('vulnerable API');
    if (f.sink_reachable)    evSteps.push('sink ✅');
    const evHtml = evSteps.length > 1
      ? evSteps.map(e => `<span class="ev-step">${e}</span>`).join('<span class="ev-arrow">→</span>')
      : '<span class="ev-step miss">no evidence</span>';

    // --- CVE badges ---
    const cveCls = isReachable ? 'cve-badge reachable' : 'cve-badge';
    const maxCves = 4;
    const cveHtml = f.cves.length
      ? f.cves.slice(0, maxCves).map(c => `<span class="${cveCls}">${escHtml(c)}</span>`).join('')
        + (f.cves.length > maxCves ? `<span class="cve-toggle" onclick="expandCves(this,'${cveCls}')">+${f.cves.length - maxCves} more</span>` : '')
      : '<span style="color:var(--text-mute)">—</span>';

    // --- Files ---
    const allUniqueFiles = [...new Set(f.allFiles)].slice(0, 4);
    const filesHtml = allUniqueFiles.length
      ? allUniqueFiles.map(fp => `<span class="file-pill">${fp}</span>`).join('')
      : '';

    // --- Functions ---
    const funcs = [...new Set(f.allFunctions || [])].slice(0, 4);
    const funcsHtml = funcs.length
      ? funcs.map(fn => `<span class="func-pill">${fn}()</span>`).join('')
      : '';

    // --- Fix ---
    const fixVer = f.fix_version || f.fixed_version || '';

    return `
    <div class="pkg-card ${cardBorder}">
      <div class="pkg-card-top">
        <span class="pkg-name">${pkg}</span>
        ${sevHtml}
        <span class="verdict-badge-sm ${vm.cls}">${vm.label}</span>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Status</div>
        <span class="status-pill ${statusCls}">${statusLabel}</span>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Path</div>
        <div class="path-checks">${pathHtml}</div>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Evidence</div>
        <div class="ev-chain">${evHtml}</div>
      </div>

      <div class="pkg-card-grid">
        ${f.cves.length ? `<div><div class="pkg-detail-label">CVEs (${f.cves.length})</div><div class="cve-list" data-cves="${escHtml(JSON.stringify(f.cves))}">${cveHtml}</div></div>` : ''}
        ${filesHtml ? `<div><div class="pkg-detail-label">Files</div><div class="file-list">${filesHtml}</div></div>` : ''}
        ${funcsHtml ? `<div><div class="pkg-detail-label">Functions</div><div class="func-list">${funcsHtml}</div></div>` : ''}
        ${fixVer ? `<div><div class="pkg-detail-label">Fix</div><span class="fix-ver">Upgrade → ${fixVer}</span></div>` : ''}
      </div>
    </div>`;
  }).join('');

  el.innerHTML = summaryBar + dastHtml + pkgCards;
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

// ─── Auto refresh ──────────────────────────────────────────────────────────
function startAutoRefresh() {
  autoRefreshInterval = setInterval(() => {
    if (scans.some(s => s.status === 'running' || s.status === 'pending' || s.status === 'started')) {
      loadScans();
    }
  }, 8000);
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
function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function expandCves(el, cls) {
  const list = el.parentNode;
  const cves = JSON.parse(list.dataset.cves || '[]');
  list.innerHTML = cves.map(c => `<span class="${cls}">${escHtml(c)}</span>`).join('');
}
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
