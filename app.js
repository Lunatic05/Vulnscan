const API = 'http://localhost:5000';
let currentScan = null, scanStartTime = null, timerInterval = null;
let severityChart = null, categoryChart = null;
let allHistory = [];
let authMode = 'none';

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  startClock();
  setupNavigation();
  setupTabs();
  setupScanInput();
  loadDashboard();
  checkBackend();
});

function startClock() {
  const tick = () => {
    const now = new Date();
    const ist = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
    const formatted = ist.toISOString().replace('T', ' ').slice(0, 19) + ' IST';
    ['topbarClock', 'sidebarTime'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = formatted;
    });
  };
  tick();
  setInterval(tick, 1000);
}

function setupNavigation() {
  document.querySelectorAll('.nav-link[data-page]').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      navigate(link.dataset.page);
    });
  });
}

function navigate(page) {
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const link   = document.querySelector(`.nav-link[data-page="${page}"]`);
  const pageEl = document.getElementById('page-' + page);
  if (link)   link.classList.add('active');
  if (pageEl) pageEl.classList.add('active');
  document.getElementById('bcPage').textContent = {
    dashboard: 'Dashboard', scanner: 'New Scan', history: 'Scan History',
    intel: 'Threat Intel', reports: 'Reports', settings: 'Settings',
  }[page] || page;
  if (page === 'history')  loadHistory();
  if (page === 'settings') checkApiStatus();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
  document.getElementById('sidebar').classList.toggle('open');
}

function setupTabs() {
  document.querySelectorAll('.rtab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.rtab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });
  document.addEventListener('click', e => {
    const h = e.target.closest('.vc-header');
    if (h) h.closest('.vuln-card').classList.toggle('open');
  });
}

function setupScanInput() {
  const input = document.getElementById('targetUrl');
  input.addEventListener('input', () => {
    const v = input.value;
    document.getElementById('scanProto').textContent =
      v.startsWith('http://') ? 'http://' : 'https://';
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
  });
}

function showReportTitle() {
  const title = document.getElementById('reportTitle');
  if (title) title.style.display = 'block';
}

function hideReportTitle() {
  const title = document.getElementById('reportTitle');
  if (title) title.style.display = 'none';
}

// ── Score helpers (FIX 4: thresholds aligned to new logarithmic curve) ────────
// Old curve: >= 70 = red/critical. New curve is more generous, so we shift:
//   < 30  → green  (LOW)
//   30–59 → yellow (MEDIUM)
//   60–79 → orange (HIGH)
//   >= 80 → red    (CRITICAL)
function scoreColor(score) {
  if (score >= 80) return '#ff003c';
  if (score >= 60) return '#ff6b35';
  if (score >= 30) return '#f0b429';
  return '#39ff14';
}

function scoreLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const resp  = await fetch(API + '/stats');
    const stats = await resp.json();
    document.getElementById('kpiTotalVulns').textContent = (stats.total_vulns  || 0).toLocaleString();
    document.getElementById('kpiTotalScans').textContent = (stats.total_scans  || 0).toLocaleString();
    document.getElementById('kpiCritical').textContent   = (stats.by_severity?.critical || 0).toLocaleString();
    document.getElementById('kpiWeek').textContent       = (stats.scans_this_week || 0).toLocaleString();
    renderSeverityChart(stats.by_severity || {});
    renderCategoryChart(stats.by_severity || {});
  } catch {
    ['kpiTotalVulns', 'kpiTotalScans', 'kpiCritical', 'kpiWeek'].forEach(id => {
      document.getElementById(id).textContent = '—';
    });
    renderSeverityChart({ critical: 8, high: 15, medium: 22, low: 10, info: 5 });
    renderCategoryChart({ critical: 8, high: 15, medium: 22, low: 10, info: 5 });
  }
  loadDashboardScans();
}

function renderSeverityChart(data) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0, data.info || 0],
        backgroundColor: ['#ff003c', '#ff6b35', '#f0b429', '#00ffe7', '#4a9eff'],
        borderColor: '#0d1520', borderWidth: 3, hoverOffset: 6,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#6a8a9a', font: { family: 'JetBrains Mono', size: 10 }, padding: 12, boxWidth: 10 },
        },
      },
      cutout: '65%',
    },
  });
}

function renderCategoryChart(data) {
  const ctx = document.getElementById('categoryChart');
  if (!ctx) return;
  if (categoryChart) categoryChart.destroy();
  categoryChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['OWASP', 'Injection', 'DNS', 'SSL', 'Exposure', 'Ports'],
      datasets: [{
        data: [
          (data.critical || 0) + (data.high || 0),
          (data.medium || 0),
          Math.floor((data.low  || 0) * 0.4),
          Math.floor((data.low  || 0) * 0.3),
          Math.floor((data.info || 0) * 0.6),
          Math.floor((data.info || 0) * 0.4),
        ],
        backgroundColor: [
          'rgba(255,0,60,0.6)', 'rgba(255,107,53,0.6)', 'rgba(240,180,41,0.6)',
          'rgba(0,255,231,0.6)', 'rgba(74,158,255,0.6)', 'rgba(157,110,255,0.6)',
        ],
        borderRadius: 4, borderSkipped: false,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#162030' }, ticks: { color: '#6a8a9a', font: { family: 'JetBrains Mono', size: 9 } } },
        y: { grid: { color: '#162030' }, ticks: { color: '#6a8a9a', font: { family: 'JetBrains Mono', size: 9 } }, beginAtZero: true },
      },
    },
  });
}

async function loadDashboardScans() {
  const el = document.getElementById('dashRecentScans');
  try {
    const resp = await fetch(API + '/scans');
    const data = await resp.json();
    const scans = (data.scans || []).slice(0, 5);
    if (!scans.length) {
      el.innerHTML = '<div class="empty-state"><i class="fa fa-radar"></i><p>No scans yet.</p></div>';
      return;
    }
    el.innerHTML = renderScanTable(scans, true);
  } catch {
    el.innerHTML = '<div class="empty-state"><i class="fa fa-plug-circle-xmark"></i><p>Service offline</p></div>';
  }
}

// ── Scanner ───────────────────────────────────────────────────────────────────
async function startScan() {
  let url = document.getElementById('targetUrl').value.trim();
  if (!url) { flashInput(); return; }
  if (!url.startsWith('http')) url = 'https://' + url;
  document.getElementById('targetUrl').value = url.replace('https://', '').replace('http://', '');

  const auth = collectAuthOptions();
  if (!auth) return;

  const opts = {
    scan_owasp:        document.getElementById('optOwasp').checked,
    scan_injection:    document.getElementById('optInjection').checked,
    scan_ports:        document.getElementById('optPorts').checked,
    scan_tech:         document.getElementById('optTech').checked,
    scan_ssl:          document.getElementById('optSsl').checked,
    scan_dns:          document.getElementById('optDns').checked,
    scan_threat_intel: document.getElementById('optThreat').checked,
    auth,
  };

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('terminalPanel').classList.remove('hidden');
  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('termLog').innerHTML = '';
  document.getElementById('activeScanBadge').style.display = '';
  document.getElementById('termTitle').textContent = `scanning ${url}`;
  scanStartTime = Date.now();

  startTimer();
  tlog('info', `Target acquired: ${url}`);
  tlog('info', 'Initializing VulnScan 1.0 engine...');
  if (auth.mode === 'cookie') tlog('info', 'Authenticated scan: session cookie attached');
  if (auth.mode === 'credentials') tlog('info', `Authenticated scan: logging in as ${auth.username}`);
  setProgress(3, 'Bootstrapping scanner');

  try {
    const resp = await fetch(API + '/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, options: opts }),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    tlog('ok', `Scan job created: ID=${data.scan_id}`);
    pollScan(data.scan_id, url, auth);
  } catch (err) {
    tlog('warn', `Service unreachable (${err.message}) — running demo mode`);
    runDemoScan(url, opts);
  }
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const s  = Math.floor((Date.now() - scanStartTime) / 1000);
    const mm = String(Math.floor(s / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    document.getElementById('termElapsed').textContent = `${mm}:${ss}`;
  }, 1000);
}

function stopTimer() {
  if (timerInterval) clearInterval(timerInterval);
}

function tlog(type, msg) {
  const el  = document.getElementById('termLog');
  const now = new Date().toISOString().slice(11, 19);
  const div = document.createElement('div');
  div.innerHTML = `<span class="log-time">[${now}]</span> <span class="log-${type}">${msg}</span>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function setProgress(pct, label) {
  document.getElementById('termProgBar').style.width   = pct + '%';
  document.getElementById('termProgLabel').textContent = `${Math.round(pct)}% — ${label}`;
}

function pollScan(scanId, url, auth = { mode: 'none' }) {
  const steps = [
    [8,  'DNS resolution & host reachability',          'info'],
    [15, 'Fetching response headers & body',             'info'],
    [22, 'Checking security headers (A05:2025)',         'warn'],
    [30, 'Testing broken access control (A01:2025)',     'warn'],
    [38, 'Running SQL injection payloads...',            'err'],
    [45, 'Testing XSS / SSTI / CSRF vectors...',        'warn'],
    [52, 'Scanning 29 ports with concurrency...',       'info'],
    [60, 'Fingerprinting tech stack + CVE lookup',      'info'],
    [68, 'SSL/TLS certificate analysis...',             'info'],
    [75, 'DNS security: SPF / DMARC / DNSSEC...',       'info'],
    [82, 'Threat Intel: VirusTotal + Shodan + HIBP...', 'api'],
    [88, 'Checking sensitive files & CORS...',          'warn'],
    [94, 'Saving results to MySQL...',                  'ok'],
  ];
  if (auth.mode === 'cookie') {
    steps.unshift([5, 'Attaching session cookie to scanner session...', 'info']);
  } else if (auth.mode === 'credentials') {
    steps.unshift([5, `Authenticating as ${auth.username}...`, 'info']);
  }
  let i = 0;
  const logInterval = setInterval(() => {
    if (i < steps.length) {
      const [p, m, t] = steps[i++];
      setProgress(p, m);
      tlog(t, m);
    }
  }, 2000);

  const pollInterval = setInterval(async () => {
    try {
      const r = await fetch(API + '/scan/' + scanId);
      const d = await r.json();
      if (d.status === 'complete') {
        clearInterval(logInterval);
        clearInterval(pollInterval);
        setProgress(100, 'Scan complete');
        tlog('ok', `Scan complete — ${d.total_vulns} vulnerabilities found · Risk score: ${d.score}/100`);
        stopTimer();
        document.getElementById('activeScanBadge').style.display = 'none';
        setTimeout(() => renderResults(d, scanId, url), 600);
        document.getElementById('scanBtn').disabled = false;
      }
    } catch { /* ignore polling errors */ }
  }, 4000);
}

function runDemoScan(url, opts) {
  const steps = [
    [8,   'DNS ok · Target reachable',                    'info'],
    [16,  'Missing: CSP, X-Frame-Options, HSTS',          'warn'],
    [24,  '/admin returned HTTP 200 — BAC detected!',     'err'],
    [32,  'SQL error pattern in ?id= parameter',          'err'],
    [40,  'XSS payload reflected in search',              'warn'],
    [48,  'CSRF token missing on POST /account/update',   'warn'],
    [56,  'Ports 22, 80, 443, 3306, 6379 open',          'info'],
    [64,  'WordPress 6.4.1 · jQuery 3.5.0 (outdated)',   'warn'],
    [72,  'TLS cert expires in 12 days',                  'err'],
    [80,  'No SPF or DMARC record',                       'warn'],
    [88,  'VirusTotal: 3 engines flagged URL',            'api'],
    [94,  '.env file accessible (HTTP 200)',              'err'],
    [100, 'Demo scan complete',                           'ok'],
  ];
  let i = 0;
  const iv = setInterval(() => {
    if (i < steps.length) {
      const [p, m, t] = steps[i++];
      setProgress(p, m);
      tlog(t, m);
    } else {
      clearInterval(iv);
      stopTimer();
      tlog('ok', 'Demo mode — showing sample data (start service for live scans)');
      document.getElementById('activeScanBadge').style.display = 'none';
      setTimeout(() => renderResults(getDemoData(url, opts.auth), 'DEMO-001', url), 600);
      document.getElementById('scanBtn').disabled = false;
    }
  }, 700);
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(data, scanId, url) {
  document.getElementById('resultsPanel').classList.remove('hidden');
  currentScan = { ...data, _scanId: scanId, _url: url };

  const vulns    = data.vulnerabilities || [];
  const duration = ((Date.now() - scanStartTime) / 1000).toFixed(1);

  document.getElementById('rTarget').textContent   = url;
  document.getElementById('rScanId').textContent   = scanId;
  document.getElementById('rDuration').textContent = duration + 's';
  document.getElementById('rWaf').textContent      = data.waf || 'Not detected';

  const authInfo  = data.auth || { mode: 'none', status: 'not_attempted' };
  const authLabel = {
    success: 'AUTHENTICATED', applied: 'COOKIE APPLIED',
    failed: 'LOGIN FAILED', error: 'AUTH ERROR', not_attempted: 'NONE',
  }[authInfo.status] || authInfo.status.toUpperCase();
  const authColor = {
    success: '#39ff14', applied: '#39ff14',
    failed: '#ff003c', error: '#ff003c', not_attempted: '#6a8a9a',
  }[authInfo.status] || '#6a8a9a';
  const rAuthEl = document.getElementById('rAuth');
  rAuthEl.textContent   = authLabel;
  rAuthEl.style.color   = authColor;
  rAuthEl.title         = authInfo.detail || '';

  // FIX 4: Use updated scoreColor() helper that matches the new logarithmic curve
  const score   = data.score || 0;
  const scoreEl = document.getElementById('rScore');
  scoreEl.textContent  = score + '/100';
  scoreEl.style.color  = scoreColor(score);

  // Severity bar
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  document.getElementById('severityBar').innerHTML =
    Object.entries(counts).map(([sev, n]) =>
      `<div class="sev-card ${sev}"><div class="sev-num">${n}</div><div class="sev-label">${sev.toUpperCase()}</div></div>`
    ).join('');

  // Risk gauge
  drawRiskGauge(score);

  // Threat intel
  if (data.threat_intel && Object.keys(data.threat_intel).length) {
    renderThreatIntel(data.threat_intel);
  }

  // Categorise vulns
  const cats = { owasp: [], injection: [], exposure: [], dns: [], cve: [] };
  vulns.forEach(v => {
    if      (v.category === 'owasp')     cats.owasp.push(v);
    else if (v.category === 'injection') cats.injection.push(v);
    else if (v.category === 'exposure')  cats.exposure.push(v);
    else if (v.category === 'dns')       cats.dns.push(v);
    else if (v.category === 'cve')       cats.cve.push(v);
    else                                 cats.owasp.push(v);
  });

  document.getElementById('tab-owasp').innerHTML     = renderVulnCards(cats.owasp);
  document.getElementById('tab-injection').innerHTML = renderVulnCards(cats.injection);
  document.getElementById('tab-exposure').innerHTML  = renderVulnCards(cats.exposure);
  document.getElementById('tab-dns').innerHTML       = renderDnsTab(data.dns_security || {}, data.ssl_info || {}, cats.dns);
  document.getElementById('tab-ports').innerHTML     = renderPortsTab(data.ports || []);
  document.getElementById('tab-tech').innerHTML      = renderTechTab(data.technologies || []);
  document.getElementById('tab-cve').innerHTML       = renderVulnCards(cats.cve);

  if (data.threat_intel) renderIntelPage(data.threat_intel, url);

  // Activate first tab
  document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.rtab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('.rtab[data-tab="owasp"]').classList.add('active');
  document.getElementById('tab-owasp').classList.add('active');

  showReportTitle();
}

function clearReports() {
  document.getElementById('reportsContent').innerHTML =
    '<div class="empty-state"><i class="fa fa-file-shield"></i><p>Complete a scan to generate a report.</p></div>';

  hideReportTitle();
}

function drawRiskGauge(score) {
  const canvas = document.getElementById('riskGauge');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  canvas.width = 200; canvas.height = 110;
  const cx = 100, cy = 100, r = 80;
  const startAngle = Math.PI, endAngle = 2 * Math.PI;
  const angle = startAngle + (score / 100) * Math.PI;

  ctx.clearRect(0, 0, 200, 110);

  // Track background
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = '#162030';
  ctx.lineWidth   = 14;
  ctx.stroke();

  // Filled arc with gradient
  const gradient = ctx.createLinearGradient(20, 0, 180, 0);
  gradient.addColorStop(0,   '#39ff14');
  gradient.addColorStop(0.5, '#f0b429');
  gradient.addColorStop(1,   '#ff003c');

  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, angle);
  ctx.strokeStyle = gradient;
  ctx.lineWidth   = 14;
  ctx.lineCap     = 'round';
  ctx.stroke();

  // Inner mask
  ctx.beginPath();
  ctx.arc(cx, cy, r - 20, startAngle, endAngle);
  ctx.strokeStyle = '#0d1520';
  ctx.lineWidth   = 24;
  ctx.stroke();

  // FIX 4: Use shared scoreColor/scoreLabel helpers
  document.getElementById('rmScore').textContent = score;
  document.getElementById('rmScore').style.color = scoreColor(score);
  document.getElementById('rmText').textContent  = scoreLabel(score);
}

function renderThreatIntel(intel) {
  const row = document.getElementById('intelRow');
  row.style.display = '';
  const cards = Object.values(intel).filter(i => i.enabled).map(i => {
    const src    = i.source || 'Unknown';
    let rows = '', status = '';
    if (src === 'VirusTotal') {
      const mal = i.malicious || 0;
      status = `<span class="vc-badge badge-${mal > 0 ? 'high' : 'safe'}">${mal > 0 ? mal + ' THREATS' : 'CLEAN'}</span>`;
      rows   = `<div class="ir"><span class="il">MALICIOUS</span><span class="iv" style="color:${i.malicious > 0 ? '#ff003c' : '#39ff14'}">${i.malicious || 0}</span></div>
                <div class="ir"><span class="il">ENGINES</span><span class="iv">${i.total_engines || '—'}</span></div>
                <div class="ir"><span class="il">REPUTATION</span><span class="iv">${i.reputation_score ?? '—'}</span></div>`;
    } else if (src === 'Shodan') {
      status = `<span class="vc-badge badge-info">INTEL</span>`;
      rows   = `<div class="ir"><span class="il">IP</span><span class="iv">${i.ip || '—'}</span></div>
                <div class="ir"><span class="il">ORG</span><span class="iv">${(i.org || '—').slice(0, 18)}</span></div>
                <div class="ir"><span class="il">OPEN PORTS</span><span class="iv">${(i.open_ports || []).length}</span></div>
                <div class="ir"><span class="il">CVEs</span><span class="iv" style="color:${(i.cves || []).length ? '#ff003c' : '#39ff14'}">${(i.cves || []).length}</span></div>`;
    } else if (src === 'Google Safe Browsing') {
      const threat = i.threats_found;
      status = `<span class="vc-badge badge-${threat ? 'critical' : 'safe'}">${threat ? 'THREATS' : 'CLEAN'}</span>`;
      rows   = `<div class="ir"><span class="il">THREATS</span><span class="iv" style="color:${threat ? '#ff003c' : '#39ff14'}">${threat ? i.threats?.length : 0}</span></div>`;
    } else if (src === 'HaveIBeenPwned') {
      const breached = i.breached;
      status = `<span class="vc-badge badge-${breached ? 'high' : 'safe'}">${breached ? 'BREACHED' : 'CLEAN'}</span>`;
      rows   = `<div class="ir"><span class="il">BREACHED</span><span class="iv" style="color:${breached ? '#ff6b35' : '#39ff14'}">${breached ? 'YES' : 'NO'}</span></div>`;
    }
    const icons = {
      'VirusTotal': 'fa-virus', 'Shodan': 'fa-magnifying-glass-location',
      'Google Safe Browsing': 'fa-shield', 'HaveIBeenPwned': 'fa-database', 'URLScan.io': 'fa-globe',
    };
    return `<div class="intel-card">
      <div class="intel-card-header">
        <i class="fa ${icons[src] || 'fa-satellite'} intel-icon"></i>
        <span class="intel-source">${src}</span>
        ${status}
      </div>
      <div class="intel-rows">${rows}</div>
    </div>`;
  });
  row.innerHTML = cards.join('') || '';
}

function renderVulnCards(vulns) {
  if (!vulns.length) return '<div class="empty-state"><i class="fa fa-check-circle" style="color:#39ff14"></i><p>No issues in this category.</p></div>';
  const order  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...vulns].sort((a, b) => (order[a.severity] || 5) - (order[b.severity] || 5));
  return '<div class="vuln-list">' + sorted.map(v => `
    <div class="vuln-card">
      <div class="vc-header">
        <div class="vc-sev-stripe ${v.severity}"></div>
        <span class="vc-id">${v.owasp_id || v.id || '—'}</span>
        <span class="vc-name">${v.name}</span>
        ${v.cvss ? `<span class="vc-cvss">CVSS ${v.cvss}</span>` : ''}
        <span class="vc-badge badge-${v.severity}">${v.severity.toUpperCase()}</span>
        <i class="fa fa-chevron-down vc-chevron"></i>
      </div>
      <div class="vc-body">
        <div class="vc-desc">${v.description}</div>
        <div class="vc-rows">
          ${v.impact          ? `<div class="vc-row"><span class="vcr-l">IMPACT</span><span class="vcr-v">${v.impact}</span></div>`          : ''}
          ${v.recommendation  ? `<div class="vc-row"><span class="vcr-l">REMEDIATION</span><span class="vcr-v">${v.recommendation}</span></div>` : ''}
        </div>
        ${v.evidence ? `<div class="vc-evidence"><span style="color:#6a8a9a">EVIDENCE: </span>${v.evidence}</div>` : ''}
      </div>
    </div>`).join('') + '</div>';
}

function renderDnsTab(dns, ssl, dnsVulns) {
  const check    = v => v
    ? '<span style="color:#39ff14">✓ SET</span>'
    : '<span style="color:#ff003c">✗ NOT DETECTED</span>';
  const sslColor = ssl.expired ? '#ff003c' : ssl.expiring_soon ? '#f0b429' : '#39ff14';
  return `
    <div class="dns-ssl-grid">
      <div class="dns-card">
        <h4><i class="fa fa-server" style="color:#00ffe7"></i> DNS Security</h4>
        <div class="dns-row"><span class="dns-key">SPF Record</span>${check(dns.spf)}</div>
        <div class="dns-row"><span class="dns-key">DMARC</span>${check(dns.dmarc)}</div>
        <div class="dns-row"><span class="dns-key">DNSSEC</span>${check(dns.dnssec)}</div>
        <div class="dns-row"><span class="dns-key">CAA Record</span>${check(dns.caa)}</div>
        ${dns.spf ? `<div class="dns-row" style="flex-wrap:wrap;gap:4px">
          <span class="dns-key">SPF Value</span>
          <span style="font-family:var(--font-mono);font-size:0.6rem;color:#6a8a9a;word-break:break-all">${dns.spf}</span>
        </div>` : ''}
      </div>
      <div class="dns-card">
        <h4><i class="fa fa-lock" style="color:#00ffe7"></i> SSL/TLS Certificate</h4>
        ${ssl.valid === false
          ? `<div style="color:#ff003c;font-family:var(--font-mono);font-size:0.75rem">SSL check failed: ${ssl.error}</div>`
          : ssl.valid === null
            ? '<div style="color:#f0b429">No HTTPS on target</div>'
            : `
          <div class="dns-row"><span class="dns-key">Status</span>
            <span style="color:${sslColor}">${ssl.expired ? 'EXPIRED' : ssl.expiring_soon ? 'EXPIRING SOON' : 'VALID'}</span>
          </div>
          <div class="dns-row"><span class="dns-key">Expires</span><span class="dns-val">${ssl.expires || '—'}</span></div>
          <div class="dns-row"><span class="dns-key">Days Left</span>
            <span style="color:${sslColor};font-family:var(--font-mono)">${ssl.days_remaining || '—'}</span>
          </div>
          <div class="dns-row"><span class="dns-key">Issuer</span><span class="dns-val">${ssl.issuer || '—'}</span></div>
          <div class="dns-row"><span class="dns-key">Cipher</span>
            <span class="dns-val" style="font-size:0.65rem">${ssl.cipher || '—'} (${ssl.bits || '—'}-bit)</span>
          </div>
          <div class="dns-row"><span class="dns-key">Protocol</span><span class="dns-val">${ssl.protocol || '—'}</span></div>`
        }
      </div>
    </div>
    ${renderVulnCards(dnsVulns)}`;
}

function renderPortsTab(ports) {
  if (!ports.length) return '<div class="empty-state"><i class="fa fa-network-wired"></i><p>No port data.</p></div>';
  const open = ports.filter(p => p.state === 'open');
  return `
    <div style="display:flex;gap:12px;margin-bottom:14px;font-family:var(--font-mono);font-size:0.75rem">
      <span style="color:#ff003c">● ${open.filter(p => p.risk === 'critical').length} critical open</span>
      <span style="color:#f0b429">● ${open.filter(p => p.risk === 'high').length} high risk open</span>
      <span style="color:#00ffe7">● ${open.length} total open</span>
    </div>
    <div class="table-wrap"><table class="data-table">
      <thead><tr><th>PORT</th><th>PROTOCOL</th><th>STATE</th><th>SERVICE</th><th>RISK</th></tr></thead>
      <tbody>${ports.sort((a, b) => a.port - b.port).map(p => `<tr>
        <td style="font-weight:700">${p.port}</td>
        <td style="color:var(--text-mid)">${p.protocol || 'TCP'}</td>
        <td class="port-${p.state}">${p.state.toUpperCase()}</td>
        <td>${p.service || '—'}</td>
        <td>${p.state === 'open'
          ? `<span class="vc-badge badge-${p.risk || 'info'}">${(p.risk || 'INFO').toUpperCase()}</span>`
          : '<span style="color:var(--text-dim)">—</span>'
        }</td>
      </tr>`).join('')}</tbody>
    </table></div>`;
}

function renderTechTab(techs) {
  if (!techs.length) return '<div class="empty-state"><i class="fa fa-microchip"></i><p>No technologies detected.</p></div>';
  const icons = {
    'Web Server': 'fa-server', 'Framework': 'fa-code', 'CMS': 'fa-layer-group',
    'Language': 'fa-terminal', 'Database': 'fa-database', 'CDN': 'fa-cloud',
    'Analytics': 'fa-chart-line', 'JavaScript': 'fa-js', 'SSL': 'fa-lock',
    'E-Commerce': 'fa-cart-shopping', 'CSS Framework': 'fa-palette', 'Runtime': 'fa-circle-play',
  };
  return '<div class="tech-grid">' + techs.map(t => `
    <div class="tech-card">
      <i class="fa ${icons[t.category] || 'fa-microchip'} tech-ico"></i>
      <div>
        <div class="tc-name">${t.name}</div>
        <div class="tc-cat">${t.category || '—'}</div>
        ${t.version ? `<div class="tc-ver">v${t.version}</div>` : ''}
      </div>
    </div>`).join('') + '</div>';
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const el = document.getElementById('historyContent');
  el.innerHTML = '<div class="empty-state"><i class="fa fa-spinner fa-spin"></i><p>Loading...</p></div>';
  try {
    const r = await fetch(API + '/scans');
    const d = await r.json();
    allHistory  = d.scans || [];
    el.innerHTML = renderScanTable(allHistory, false);
  } catch {
    el.innerHTML = '<div class="empty-state"><i class="fa fa-plug-circle-xmark"></i><p>Service offline.</p></div>';
  }
}

function filterHistory() {
  const q        = document.getElementById('historySearch').value.toLowerCase();
  const filtered = allHistory.filter(s =>
    s.url?.toLowerCase().includes(q) || s.id?.toLowerCase().includes(q)
  );
  document.getElementById('historyContent').innerHTML = renderScanTable(filtered, false);
}

function renderScanTable(scans, compact) {
  if (!scans.length) return '<div class="empty-state"><i class="fa fa-inbox"></i><p>No scan records.</p></div>';
  // FIX 4: Use shared scoreColor() helper for consistent colouring
  return `<table class="h-table">
    <thead><tr>
      <th>SCAN ID</th><th>TARGET URL</th><th>DATE</th><th>VULNS</th><th>RISK</th>
      ${compact ? '<th>WAF</th>' : '<th>WAF</th><th>STATUS</th>'}
      <th></th>
    </tr></thead>
    <tbody>${scans.map(s => `<tr>
      <td class="h-id">${s.id}</td>
      <td class="h-url">${s.url}</td>
      <td style="color:var(--text-mid);font-family:var(--font-mono);font-size:0.72rem">${s.created_at?.slice(0, 16) || '—'}</td>
      <td style="font-family:var(--font-mono);color:${(s.vuln_count || 0) > 0 ? '#ff6b35' : '#39ff14'}">${s.vuln_count || 0}</td>
      <td>
        <span class="score-pill" style="background:${scoreColor(s.risk_score || 0)}20;color:${scoreColor(s.risk_score || 0)}">
          ${s.risk_score || 0}/100
        </span>
      </td>
      <td style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-mid)">${s.waf || '—'}</td>
      ${compact ? '' : s.status
        ? `<td><span class="vc-badge badge-${s.status === 'complete' ? 'safe' : 'info'}">${s.status.toUpperCase()}</span></td>`
        : '<td>—</td>'
      }
      <td><button class="hbtn" onclick="loadScan('${s.id}')">VIEW</button></td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function loadScan(scanId) {
  navigate('scanner');
  try {
    const r = await fetch(API + '/scan/' + scanId);
    const d = await r.json();
    scanStartTime = Date.now();
    document.getElementById('targetUrl').value = (d.url || '').replace('https://', '').replace('http://', '');
    document.getElementById('terminalPanel').classList.add('hidden');
    renderResults(d, scanId, d.url || '');
  } catch (e) {
    alert('Load failed: ' + e.message);
  }
}

// ── Threat Intel Page ─────────────────────────────────────────────────────────
function renderIntelPage(intel, url) {
  const el = document.getElementById('intelPageContent');
  if (!Object.values(intel).some(i => i.enabled)) {
    el.innerHTML = '<div class="empty-state"><i class="fa fa-key"></i><p>Add API keys in Settings to enable threat intelligence.</p></div>';
    return;
  }

  const shodan = intel.shodan;
  let html     = `<div class="panel" style="margin-bottom:16px">
    <div class="panel-header"><span class="panel-title"><i class="fa fa-globe"></i> ${url}</span></div>
    <div style="padding:16px">`;

  if (shodan?.enabled && !shodan.error) {
    html += `<div class="dns-ssl-grid" style="margin-bottom:0">
      <div class="dns-card">
        <h4><i class="fa fa-magnifying-glass-location" style="color:#00ffe7"></i> Shodan Intelligence</h4>
        <div class="dns-row"><span class="dns-key">IP Address</span><span class="dns-val">${shodan.ip || '—'}</span></div>
        <div class="dns-row"><span class="dns-key">Organization</span><span class="dns-val">${shodan.org || '—'}</span></div>
        <div class="dns-row"><span class="dns-key">ISP</span><span class="dns-val">${shodan.isp || '—'}</span></div>
        <div class="dns-row"><span class="dns-key">Country</span><span class="dns-val">${shodan.country || '—'}</span></div>
        <div class="dns-row"><span class="dns-key">OS</span><span class="dns-val">${shodan.os || 'Unknown'}</span></div>
        <div class="dns-row"><span class="dns-key">Last Seen</span><span class="dns-val">${(shodan.last_update || '—').slice(0, 10)}</span></div>
      </div>
      <div class="dns-card">
        <h4><i class="fa fa-network-wired" style="color:#00ffe7"></i> Exposed Services</h4>
        ${(shodan.services || []).map(s => `<div class="dns-row"><span class="dns-key">PORT</span><span class="dns-val" style="font-size:0.68rem">${s}</span></div>`).join('') || '<p style="color:var(--text-dim);font-size:0.75rem">No data</p>'}
        ${(shodan.cves || []).length ? `<div style="margin-top:10px;font-family:var(--font-mono);font-size:0.65rem;color:#ff003c">${shodan.cves.length} CVEs found by Shodan</div>` : ''}
      </div>
    </div>`;
  }
  html += '</div></div>';

  Object.values(intel).filter(i => i.enabled && i.source !== 'Shodan').forEach(i => {
    html += `<div class="panel" style="margin-bottom:12px">
      <div class="panel-header"><span class="panel-title"><i class="fa fa-shield-halved"></i> ${i.source}</span></div>
      <div style="padding:16px;font-family:var(--font-mono);font-size:0.75rem;color:var(--text-mid)">
        ${i.error ? 'Error: ' + i.error : JSON.stringify(i, null, 2).slice(0, 400)}
      </div>
    </div>`;
  });

  el.innerHTML = html;
}

// ── Report Download ───────────────────────────────────────────────────────────
function downloadReport() {
  if (!currentScan) return;
  const {
    _url: url, _scanId: scanId,
    vulnerabilities: vulns = [], ports = [], technologies: techs = [],
    score = 0, dns_security: dns = {}, ssl_info: ssl = {}, waf,
  } = currentScan;
  const now    = new Date().toISOString();
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  const sev = counts;

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VulnScan Report — ${url}</title>
<style>
  body{font-family:'Courier New',monospace;background:#05080d;color:#b8ccd8;padding:40px;max-width:1000px;margin:0 auto;line-height:1.6}
  h1{color:#00ffe7;border-bottom:2px solid #00ffe7;padding-bottom:14px;font-size:2.2rem;letter-spacing:-1px}
  h2{color:#00ffe7;margin:2rem 0 1rem;font-size:1rem;letter-spacing:3px}
  .meta{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:1.5rem 0;padding:16px;background:#0d1520;border:1px solid #162030;border-radius:8px}
  .meta-item label{display:block;font-size:0.6rem;color:#2e4a5a;letter-spacing:2px;margin-bottom:4px}
  .meta-item span{color:#00ffe7;font-size:0.85rem}
  .summary{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:1.5rem 0}
  .sc{text-align:center;padding:14px;border-radius:6px;border-top:3px solid}
  .sc-num{font-size:1.8rem;font-weight:800}
  .sc.c{border-top-color:#ff003c} .sc.c .sc-num{color:#ff003c}
  .sc.h{border-top-color:#ff6b35} .sc.h .sc-num{color:#ff6b35}
  .sc.m{border-top-color:#f0b429} .sc.m .sc-num{color:#f0b429}
  .sc.l{border-top-color:#00ffe7} .sc.l .sc-num{color:#00ffe7}
  .sc.i{border-top-color:#4a9eff} .sc.i .sc-num{color:#4a9eff}
  .sc-l{font-size:0.55rem;color:#2e4a5a;letter-spacing:2px;margin-top:4px}
  .score-bar{height:8px;background:#162030;border-radius:4px;margin:1rem 0;overflow:hidden}
  .score-fill{height:100%;background:linear-gradient(90deg,#39ff14,#f0b429,#ff003c);border-radius:4px}
  .vuln{background:#0d1520;border:1px solid #162030;border-left:4px solid;border-radius:6px;margin:10px 0;padding:16px}
  .vuln.critical{border-left-color:#ff003c} .vuln.high{border-left-color:#ff6b35}
  .vuln.medium{border-left-color:#f0b429} .vuln.low{border-left-color:#00ffe7} .vuln.info{border-left-color:#4a9eff}
  .vh{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
  .vn{font-weight:700;font-size:0.95rem;color:#fff}
  .vb{padding:2px 8px;border-radius:3px;font-size:0.6rem;letter-spacing:1px;font-weight:700}
  .vb.critical{color:#ff003c;border:1px solid rgba(255,0,60,.3);background:rgba(255,0,60,.1)}
  .vb.high{color:#ff6b35;border:1px solid rgba(255,107,53,.3);background:rgba(255,107,53,.1)}
  .vb.medium{color:#f0b429;border:1px solid rgba(240,180,41,.3);background:rgba(240,180,41,.1)}
  .vb.low{color:#00ffe7;border:1px solid rgba(0,255,231,.2);background:rgba(0,255,231,.08)}
  .vb.info{color:#4a9eff;border:1px solid rgba(74,158,255,.2);background:rgba(74,158,255,.08)}
  .vd{font-size:0.82rem;color:#6a8a9a;margin:8px 0}
  .vr{display:flex;gap:8px;margin-bottom:5px;font-size:0.78rem}
  .vrl{color:#2e4a5a;min-width:85px;font-size:0.62rem;letter-spacing:1px;padding-top:2px}
  .ve{background:rgba(240,180,41,.04);border:1px solid rgba(240,180,41,.15);padding:8px;border-radius:4px;font-size:0.7rem;color:#f0b429;margin-top:8px;word-break:break-all}
  table{width:100%;border-collapse:collapse;font-size:0.78rem;margin-top:10px}
  th{text-align:left;padding:8px 12px;border-bottom:1px solid #162030;color:#2e4a5a;font-size:0.6rem;letter-spacing:2px;background:#0d1520}
  td{padding:10px 12px;border-bottom:1px solid rgba(22,32,48,.5)}
  footer{margin-top:3rem;text-align:center;color:#2e4a5a;font-size:0.65rem;border-top:1px solid #162030;padding-top:1.5rem}
  .disclaimer{background:rgba(255,0,60,.04);border:1px solid rgba(255,0,60,.15);border-radius:6px;padding:12px 16px;font-size:0.72rem;color:#6a8a9a;margin-bottom:1.5rem}
</style></head><body>
<h1>⬡ VULNSCAN v1.0 — SECURITY REPORT</h1>
<div class="disclaimer">⚠ This report is confidential and intended for authorized security personnel only. Do not distribute without permission.</div>
<div class="meta">
  <div class="meta-item"><label>TARGET URL</label><span>${url}</span></div>
  <div class="meta-item"><label>SCAN ID</label><span>${scanId}</span></div>
  <div class="meta-item">
  <label>TIMESTAMP</label>
  <span>
    ${new Date().toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }).replace(',', '')} IST
  </span>
  </div>
  <div class="meta-item"><label>RISK SCORE</label><span style="color:${score>=80?'#ff003c':score>=60?'#ff6b35':score>=30?'#f0b429':'#39ff14'}">${score}/100</span></div>
  <div class="meta-item"><label>WAF DETECTED</label><span>${waf || 'None'}</span></div>
  <div class="meta-item"><label>TOTAL FINDINGS</label><span>${vulns.length}</span></div>
</div>
<div class="score-bar"><div class="score-fill" style="width:${score}%"></div></div>
<h2>// RISK SUMMARY</h2>
<div class="summary">
  <div class="sc c"><div class="sc-num">${sev.critical}</div><div class="sc-l">CRITICAL</div></div>
  <div class="sc h"><div class="sc-num">${sev.high}</div><div class="sc-l">HIGH</div></div>
  <div class="sc m"><div class="sc-num">${sev.medium}</div><div class="sc-l">MEDIUM</div></div>
  <div class="sc l"><div class="sc-num">${sev.low}</div><div class="sc-l">LOW</div></div>
  <div class="sc i"><div class="sc-num">${sev.info}</div><div class="sc-l">INFO</div></div>
</div>
<h2>// VULNERABILITY FINDINGS</h2>
${vulns.sort((a,b)=>({critical:0,high:1,medium:2,low:3,info:4}[a.severity]||5)-({critical:0,high:1,medium:2,low:3,info:4}[b.severity]||5)).map(v=>`
<div class="vuln ${v.severity}">
  <div class="vh">
    <span class="vn">${v.owasp_id ? v.owasp_id + ' — ' : ''}${v.name}</span>
    <span class="vb ${v.severity}">${v.severity.toUpperCase()}${v.cvss ? ' · CVSS ' + v.cvss : ''}</span>
  </div>
  <div class="vd">${v.description}</div>
  ${v.impact         ? `<div class="vr"><span class="vrl">IMPACT</span><span>${v.impact}</span></div>`        : ''}
  ${v.recommendation ? `<div class="vr"><span class="vrl">REMEDIATION</span><span>${v.recommendation}</span></div>` : ''}
  ${v.evidence       ? `<div class="ve">EVIDENCE: ${v.evidence}</div>`                                         : ''}
</div>`).join('')}
${ports.length ? `<h2>// PORT SCAN RESULTS</h2><table>
  <thead><tr><th>PORT</th><th>STATE</th><th>SERVICE</th><th>RISK</th></tr></thead>
  <tbody>${ports.map(p=>`<tr><td>${p.port}</td><td>${p.state}</td><td>${p.service||'—'}</td><td>${p.state==='open'?(p.risk||'info').toUpperCase():'—'}</td></tr>`).join('')}</tbody>
</table>` : ''}
${techs.length ? `<h2>// TECHNOLOGY STACK</h2><table>
  <thead><tr><th>NAME</th><th>CATEGORY</th><th>VERSION</th></tr></thead>
  <tbody>${techs.map(t=>`<tr><td>${t.name}</td><td>${t.category||'—'}</td><td>${t.version||'—'}</td></tr>`).join('')}</tbody>
</table>` : ''}
<footer>Generated by VulnScan v1.0 · OWASP 2025<br/>Developed by Avideepth &amp; Rhitik · ${now.slice(0,10)}</footer>
</body></html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `vulnscan_${scanId}_${Date.now()}.html`;
  a.click();

  document.getElementById('reportsContent').innerHTML = `
    <div class="panel"><div class="panel-header"><span class="panel-title"><i class="fa fa-file-shield"></i> Generated Reports</span></div>
    <div style="padding:20px">
      <div style="display:flex;align-items:center;gap:16px;padding:14px;background:var(--bg2);border-radius:6px">
        <i class="fa fa-file-code" style="font-size:1.5rem;color:var(--accent)"></i>
        <div>
          <div style="font-weight:700">${url}</div>
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-mid)">
            ${now.slice(0,19)} · Scan ID: ${scanId} · Risk: ${score}/100
          </div>
        </div>
        <button class="btn-accent" style="margin-left:auto" onclick="downloadReport()">
          <i class="fa fa-download"></i> Re-download
        </button>
      </div>
    </div></div>`;
}

// ── Backend & Settings ────────────────────────────────────────────────────────
async function checkBackend() {
  try {
    await fetch(API + '/health', { signal: AbortSignal.timeout(3000) });
    document.getElementById('sidebarDot').style.background    = '#39ff14';
    document.getElementById('sidebarStatus').textContent      = 'ONLINE';
  } catch {
    document.getElementById('sidebarDot').style.background    = '#ff0000';
    document.getElementById('sidebarStatus').textContent      = 'OFFLINE';
  }
}

function checkApiStatus() {
  const apis = [
    { id: 'cfg_vt',     name: 'VirusTotal' },
    { id: 'cfg_shodan', name: 'Shodan' },
    { id: 'cfg_urlscan',name: 'URLScan.io' },
    { id: 'cfg_gsb',    name: 'Google Safe Browsing' },
    { id: 'cfg_hibp',   name: 'HaveIBeenPwned' },
  ];
  const el = document.getElementById('apiStatusGrid');
  el.innerHTML = apis.map(a => {
    const val    = document.getElementById(a.id)?.value || '';
    const active = val && !val.startsWith('YOUR_');
    return `<div class="api-status-row">
      <span>${a.name}</span>
      <span class="${active ? 'api-ok' : 'api-off'}">${active ? '● CONFIGURED' : '○ NOT SET'}</span>
    </div>`;
  }).join('');
}

function saveSettings() {
  alert('To save API keys, edit config.py on your server with the keys you entered.\n\nBrowser cannot write to server files directly for security reasons.');
  checkApiStatus();
}

function flashInput(id = 'targetUrl') {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.borderColor = '#ff003c';
  el.focus();
  setTimeout(() => el.style.borderColor = '', 1000);
}

// ── Authenticated Scanning ──────────────────────────────────────────────────
function toggleAuthPanel() {
  const body = document.getElementById('authPanelBody');
  const chevron = document.getElementById('authChevron');
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : '';
  chevron.classList.toggle('open', !isOpen);
}

function setAuthMode(mode) {
  authMode = mode;
  document.querySelectorAll('.auth-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  document.getElementById('authModeCookie').style.display = mode === 'cookie' ? '' : 'none';
  document.getElementById('authModeCreds').style.display  = mode === 'credentials' ? '' : 'none';

  const pill = document.getElementById('authModePill');
  pill.textContent = mode === 'none' ? 'OFF' : mode === 'cookie' ? 'COOKIE' : 'CREDENTIALS';
  pill.classList.toggle('on', mode !== 'none');
}

// Reads the active auth mode's fields into a payload for the /scan request.
// Returns null (and flags the offending input) if a selected mode is incomplete.
function collectAuthOptions() {
  if (authMode === 'cookie') {
    const cookie = document.getElementById('authCookieStr').value.trim();
    if (!cookie) {
      flashInput('authCookieStr');
      tlog('warn', 'Authenticated scan selected but no session cookie was provided');
      return null;
    }
    return { mode: 'cookie', cookie };
  }

  if (authMode === 'credentials') {
    const username = document.getElementById('authUsername').value.trim();
    const password = document.getElementById('authPassword').value;
    if (!username || !password) {
      flashInput(!username ? 'authUsername' : 'authPassword');
      tlog('warn', 'Authenticated scan selected but username/password is missing');
      return null;
    }
    return {
      mode: 'credentials',
      login_url:      document.getElementById('authLoginUrl').value.trim(),
      username, password,
      username_field: document.getElementById('authUserField').value.trim(),
      password_field: document.getElementById('authPassField').value.trim(),
    };
  }

  return { mode: 'none' };
}

// ── Demo Data ─────────────────────────────────────────────────────────────────
function getDemoData(url, auth) {
  const authMode = (auth && auth.mode) || 'none';
  return {
    status: 'complete', score: 74, waf: 'Cloudflare',
    auth: authMode === 'none'
      ? { mode: 'none', status: 'not_attempted', detail: '' }
      : { mode: authMode, status: authMode === 'cookie' ? 'applied' : 'success',
          detail: 'Demo mode — session simulated, no live request made' },
    dns_security: { spf: null, dmarc: null, dnssec: false, caa: null },
    ssl_info: {
      valid: true, days_remaining: 12, expires: 'Apr 22 00:00:00 2025 GMT',
      issuer: "Let's Encrypt", cipher: 'AES_256_GCM', protocol: 'TLSv1.3',
      bits: 256, expiring_soon: true,
    },
    vulnerabilities: [
      { id:'A01-BAC',owasp_id:'A01:2025',category:'owasp',name:'Broken Access Control',severity:'critical',description:'Admin endpoint /admin returns HTTP 200 without authentication.',impact:'Unauthenticated admin access, full data breach',recommendation:'Implement deny-by-default RBAC on all routes.',evidence:'GET /admin → HTTP 200 (4.2KB response)',cvss:'9.8' },
      { id:'A02-HTTPS',owasp_id:'A02:2025',category:'owasp',name:'Cryptographic Failure — HTTP Used',severity:'critical',description:'Site served without TLS encryption.',impact:'All credentials and data visible in transit',recommendation:'Enable HTTPS with TLS 1.3. Use HSTS.',evidence:`URL scheme: http://`,cvss:'7.5' },
      { id:'A05-HEADERS',owasp_id:'A05:2025',category:'owasp',name:'Missing Security Headers',severity:'high',description:'5 of 7 security headers absent from HTTP response.',impact:'XSS, clickjacking, MIME confusion attacks',recommendation:'Set CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy.',evidence:'Missing: CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy',cvss:'6.5' },
      { id:'A06-JQUERY',owasp_id:'A06:2025',category:'owasp',name:'Outdated jQuery v3.5.0',severity:'medium',description:'jQuery 3.5.0 has known XSS vulnerabilities.',impact:'DOM-based XSS attacks',recommendation:'Upgrade to jQuery 3.7.0 or later.',evidence:'Detected jquery/3.5.0 in page source',cvss:'6.1' },
      { id:'SQL-ERROR',category:'injection',name:'SQL Injection — Error Based',severity:'critical',description:'MySQL error strings visible in HTTP response after injection payload.',impact:'Full database dump, authentication bypass, RCE via INTO OUTFILE',recommendation:'Use parameterized queries. Never expose DB errors.',evidence:"?id=1' → MySQL error: You have an error in your SQL syntax",cvss:'9.9' },
      { id:'XSS-REFLECT',category:'injection',name:'Reflected Cross-Site Scripting',severity:'high',description:'XSS payload reflected unescaped in search results.',impact:'Session hijacking, credential theft',recommendation:'Apply output encoding. Implement strict CSP.',evidence:'<script>alert(1)</script> reflected in ?q= response',cvss:'7.4' },
      { id:'CSRF-01',category:'injection',name:'CSRF — Missing Token',severity:'medium',description:'POST /account/update has no CSRF token and no SameSite cookie.',impact:'Unauthorized actions on behalf of logged-in users',recommendation:'Add CSRF synchronizer tokens. Set SameSite=Strict.',evidence:'Form POST /account/update — no csrf_token field',cvss:'6.5' },
      { id:'SSTI-01',category:'injection',name:'Server-Side Template Injection',severity:'critical',description:"Template expression {{7*7}} evaluated to 49 server-side.",impact:'Remote code execution on the server',recommendation:'Never pass user input into template strings.',evidence:"?q={{7*7}} → server returned '49'",cvss:'10.0' },
      { id:'FILE-.env',category:'exposure',name:'Environment File Exposed: .env',severity:'critical',description:'/.env is publicly accessible and contains database credentials.',impact:'Full credential leakage, database takeover',recommendation:'Move .env out of web root. Deny in nginx/Apache config.',evidence:'GET /.env → HTTP 200 (DB_PASSWORD=secret123)',cvss:'8.6' },
      { id:'DNS-SPF',category:'dns',name:'Missing SPF Record',severity:'medium',description:'No SPF TXT record. Domain can be spoofed for phishing.',impact:'Email spoofing and phishing using your domain',recommendation:"Add TXT record: v=spf1 include:_spf.google.com ~all",evidence:'No v=spf1 TXT record found',cvss:'5.3' },
      { id:'DNS-DMARC',category:'dns',name:'Missing DMARC Record',severity:'medium',description:'No DMARC policy at _dmarc domain.',impact:'No enforcement of email authentication',recommendation:'Add: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com',evidence:'No DMARC record at _dmarc.domain.com',cvss:'5.3' },
      { id:'CVE-2023-5129',owasp_id:'A06:2025',category:'cve',name:'CVE-2023-5129 — libwebp Heap Overflow',severity:'critical',description:'Critical heap buffer overflow in libwebp used by the detected framework version.',impact:'Remote code execution via malformed WebP images',recommendation:'Update framework to patched version.',evidence:'CVSS 10.0 — Published 2023-09-25',cvss:'10.0' },
    ],
    ports: [
      { port:22,  state:'open',   service:'SSH',      protocol:'TCP', risk:'medium'   },
      { port:80,  state:'open',   service:'HTTP',     protocol:'TCP', risk:'low'      },
      { port:443, state:'open',   service:'HTTPS',    protocol:'TCP', risk:'info'     },
      { port:3306,state:'open',   service:'MySQL',    protocol:'TCP', risk:'critical' },
      { port:6379,state:'open',   service:'Redis',    protocol:'TCP', risk:'critical' },
      { port:27017,state:'open',  service:'MongoDB',  protocol:'TCP', risk:'critical' },
      { port:8080,state:'open',   service:'HTTP-Alt', protocol:'TCP', risk:'medium'   },
      { port:3389,state:'closed', service:'RDP',      protocol:'TCP', risk:'info'     },
      { port:21,  state:'closed', service:'FTP',      protocol:'TCP', risk:'info'     },
    ],
    technologies: [
      { name:'Apache',           category:'Web Server',    version:'2.4.51' },
      { name:'PHP',              category:'Language',       version:'8.1.2'  },
      { name:'WordPress',        category:'CMS',            version:'6.4.1'  },
      { name:'MySQL',            category:'Database',       version:'8.0.33' },
      { name:'jQuery',           category:'JavaScript',     version:'3.5.0'  },
      { name:'Bootstrap',        category:'CSS Framework',  version:'4.6.0'  },
      { name:'Cloudflare',       category:'CDN',            version:null     },
      { name:'Google Analytics', category:'Analytics',      version:null     },
    ],
    threat_intel: {
      vt:     { enabled:true,source:'VirusTotal',malicious:3,suspicious:1,total_engines:72,flagged_by:['Avira','Kaspersky','Sophos'],reputation_score:-5,severity:'high' },
      shodan: { enabled:true,source:'Shodan',ip:'203.0.113.42',org:'AS12345 Example Corp',isp:'Cloudflare Inc.',country:'United States',open_ports:[80,443,3306,6379],cves:['CVE-2023-5129','CVE-2022-37434'],services:['80/tcp (Apache 2.4.51)','443/tcp (nginx)','3306/tcp (MySQL 8.0)'],last_update:'2025-04-01T00:00:00' },
      gsb:    { enabled:true,source:'Google Safe Browsing',threats_found:false,threats:[] },
      hibp:   { enabled:true,source:'HaveIBeenPwned',breached:true,emails_found:142,severity:'high' },
    },
  };
}
