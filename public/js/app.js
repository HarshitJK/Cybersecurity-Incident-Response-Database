/* ============================================================
   SOC Shield — Frontend App JavaScript
   Handles routing, API calls, RBAC UI, charts, etc.
   ============================================================ */

// ─── State ────────────────────────────────────────────────────────────────
let currentUser = null;
let severityChart = null;
let statusChart = null;
let currentPage = 1;

// ─── Utility: API calls ───────────────────────────────────────────────────
async function api(method, endpoint, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`/api${endpoint}`, opts);
    const data = await res.json();
    if (!res.ok) throw data;
    return data;
}

// ─── Toast notifications ──────────────────────────────────────────────────
function showToast(msg, type = 'success') {
    const toast = document.getElementById('toast');
    const icon = document.getElementById('toast-icon');
    const msgEl = document.getElementById('toast-msg');

    icon.textContent = type === 'success' ? '✅' : type === 'error' ? '❌' : '⚠️';
    msgEl.textContent = msg;
    toast.className = `toast toast-${type}`;
    toast.classList.remove('hidden');

    setTimeout(() => toast.classList.add('hidden'), 3500);
}

// ─── Time display ─────────────────────────────────────────────────────────
function updateTime() {
    const el = document.getElementById('topbar-time');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' UTC+5:30';
    }
}
setInterval(updateTime, 1000);
updateTime();

// ─── Format helpers ───────────────────────────────────────────────────────
function severityBadge(s) {
    const map = { Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low' };
    return `<span class="badge ${map[s] || 'badge-low'}">⬤ ${s}</span>`;
}
function statusBadge(s) {
    const map = { Open: 'badge-open', Investigating: 'badge-investigating', Resolved: 'badge-resolved', Closed: 'badge-closed' };
    return `<span class="badge ${map[s] || 'badge-closed'}">${s}</span>`;
}
function logStatusBadge(s) {
    const map = { Success: 'badge-success', Denied: 'badge-denied', Warning: 'badge-warning' };
    return `<span class="badge ${map[s] || 'badge-warning'}">${s}</span>`;
}
function formatDate(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}
function timeAgo(ts) {
    if (!ts) return '—';
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'Just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
}

// ─── Navigation ───────────────────────────────────────────────────────────
function navigateTo(view) {
    // Hide all views
    document.querySelectorAll('.view').forEach(v => {
        v.classList.remove('active');
        v.classList.add('hidden');
    });
    // Deactivate nav items
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    // Show target view
    const el = document.getElementById(`view-${view}`);
    if (el) {
        el.classList.remove('hidden');
        el.classList.add('active');
    }

    // Activate nav
    const navEl = document.getElementById(`nav-${view}`);
    if (navEl) navEl.classList.add('active');

    // Update title
    const titles = {
        dashboard: 'Dashboard',
        incidents: 'Incident Management',
        reports: 'Threat Reports',
        systems: 'Systems Inventory',
        users: 'User Management',
        rbac: 'RBAC Permissions',
        logs: 'Audit Logs',
    };
    document.getElementById('page-title').textContent = titles[view] || view;
    document.getElementById('breadcrumb').textContent = `SOC Shield / ${titles[view] || view}`;

    // Load data
    const loaders = {
        dashboard: loadDashboard,
        incidents: loadIncidents,
        reports: loadReports,
        systems: loadSystems,
        users: loadUsers,
        rbac: loadRBAC,
        logs: loadLogs,
    };
    if (loaders[view]) loaders[view]();
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const main = document.querySelector('.main-content');
    sidebar.classList.toggle('collapsed');
    main.classList.toggle('expanded');
}

// ─── Auth ─────────────────────────────────────────────────────────────────
async function checkAuth() {
    try {
        const data = await api('GET', '/auth/me');
        currentUser = data.user;
        showApp();
    } catch {
        showLogin();
    }
}

function showLogin() {
    document.getElementById('login-page').classList.add('active');
    document.getElementById('login-page').classList.remove('hidden');
    document.getElementById('app-page').classList.add('hidden');
    document.getElementById('app-page').classList.remove('active');
}

function showApp() {
    document.getElementById('login-page').classList.add('hidden');
    document.getElementById('login-page').classList.remove('active');
    document.getElementById('app-page').classList.remove('hidden');
    document.getElementById('app-page').classList.add('active');

    // Set user info
    const initials = currentUser.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    ['sidebar-avatar', 'topbar-avatar'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = initials;
    });
    document.getElementById('sidebar-name').textContent = currentUser.name;
    document.getElementById('topbar-name').textContent = currentUser.name;
    document.getElementById('sidebar-role').textContent = roleLabel(currentUser.role_name);

    // Adjust UI based on role
    adjustUIForRole();

    // Navigate to dashboard
    navigateTo('dashboard');
}

function roleLabel(r) {
    const map = { admin: 'Admin', soc_manager: 'SOC Manager', security_analyst: 'Analyst', auditor: 'Auditor' };
    return map[r] || r;
}

function adjustUIForRole() {
    const role = currentUser.role_name;

    // Show/hide admin nav
    const adminNav = document.getElementById('admin-nav-section');
    if (role !== 'admin') adminNav.style.display = 'none';

    // Show/hide create incident button
    const btnCreate = document.getElementById('btn-create-incident');
    if (role === 'security_analyst' || role === 'auditor') {
        if (btnCreate) btnCreate.style.display = 'none';
    }

    // Show/hide report button
    const btnReport = document.getElementById('btn-create-report');
    if (role === 'auditor') {
        if (btnReport) btnReport.style.display = 'none';
    }
}

function quickLogin(email, password) {
    document.getElementById('login-email').value = email;
    document.getElementById('login-password').value = password;
    document.getElementById('login-form').dispatchEvent(new Event('submit'));
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const btn = document.getElementById('login-btn-text');
    const errEl = document.getElementById('login-error');

    btn.textContent = '⏳ Authenticating...';
    errEl.classList.add('hidden');

    try {
        const data = await api('POST', '/auth/login', { email, password });
        currentUser = data.user;
        showApp();
    } catch (err) {
        errEl.textContent = err.error || 'Login failed. Please try again.';
        errEl.classList.remove('hidden');
    } finally {
        btn.textContent = '🔐 Secure Login';
    }
}

async function handleLogout() {
    try { await api('POST', '/auth/logout'); } catch { }
    currentUser = null;
    showLogin();
}

// ─── Dashboard ────────────────────────────────────────────────────────────
async function loadDashboard() {
    try {
        const stats = await api('GET', '/incidents/stats');

        // Stats cards
        animateCount('stat-total', stats.total);
        animateCount('stat-open', stats.open);
        animateCount('stat-critical', stats.critical);
        animateCount('stat-resolved', stats.resolved);

        // Update badge
        const badge = document.getElementById('incident-badge');
        if (badge) {
            badge.textContent = stats.open > 0 ? stats.open : '';
            badge.style.display = stats.open > 0 ? 'inline' : 'none';
        }

        // Charts
        buildSeverityChart(stats.bySeverity);
        buildStatusChart(stats.byStatus);

        // Recent incidents
        const tbody = document.getElementById('recent-incidents-body');
        if (stats.recent.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">No incidents yet.</td></tr>`;
        } else {
            tbody.innerHTML = stats.recent.map(i => `
        <tr style="cursor:pointer" onclick="viewIncidentDetail(${i.incident_id})">
          <td class="text-mono text-dim">#${i.incident_id}</td>
          <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.title}">${i.title}</td>
          <td>${severityBadge(i.severity)}</td>
          <td>${statusBadge(i.status)}</td>
          <td>${i.reporter_name || '—'}</td>
          <td class="text-dim">${timeAgo(i.created_at)}</td>
        </tr>
      `).join('');
        }
    } catch (err) {
        console.error('Dashboard error:', err);
    }
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let curr = 0;
    const step = Math.ceil(target / 20);
    const interval = setInterval(() => {
        curr = Math.min(curr + step, target);
        el.textContent = curr;
        if (curr >= target) clearInterval(interval);
    }, 40);
}

function buildSeverityChart(data) {
    if (severityChart) severityChart.destroy();
    const colors = { Critical: '#ff2d55', High: '#ff6b35', Medium: '#ffd60a', Low: '#30d158' };
    const ctx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.severity),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: data.map(d => colors[d.severity] || '#888'),
                borderColor: '#0f1a26',
                borderWidth: 3,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { size: 12 }, padding: 16, usePointStyle: true }
                }
            },
            cutout: '65%',
        }
    });
}

function buildStatusChart(data) {
    if (statusChart) statusChart.destroy();
    const colors = { Open: '#ff2d55', Investigating: '#ffd60a', Resolved: '#30d158', Closed: '#6b7280' };
    const ctx = document.getElementById('statusChart').getContext('2d');
    statusChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.status),
            datasets: [{
                label: 'Count',
                data: data.map(d => d.count),
                backgroundColor: data.map(d => (colors[d.status] || '#888') + '33'),
                borderColor: data.map(d => colors[d.status] || '#888'),
                borderWidth: 2,
                borderRadius: 6,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true }
            }
        }
    });
}

// ─── Incidents ────────────────────────────────────────────────────────────
async function loadIncidents() {
    const tbody = document.getElementById('incidents-body');
    tbody.innerHTML = `<tr><td colspan="8" class="loading-cell">⏳ Loading incidents...</td></tr>`;

    try {
        let incidents = await api('GET', '/incidents');
        const sevFilter = document.getElementById('filter-severity')?.value;
        const stFilter = document.getElementById('filter-status')?.value;

        if (sevFilter) incidents = incidents.filter(i => i.severity === sevFilter);
        if (stFilter) incidents = incidents.filter(i => i.status === stFilter);

        if (!incidents.length) {
            tbody.innerHTML = `<tr><td colspan="8" class="loading-cell">No incidents found.</td></tr>`;
            return;
        }

        tbody.innerHTML = incidents.map(i => {
            const canEdit = currentUser.role_name !== 'auditor';
            return `
        <tr>
          <td class="text-mono text-dim">#${i.incident_id}</td>
          <td style="max-width:220px">
            <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.title}">${i.title}</div>
            ${i.affected_system ? `<div class="text-dim" style="margin-top:2px">🖥️ ${i.affected_system}</div>` : ''}
          </td>
          <td>${severityBadge(i.severity)}</td>
          <td>${statusBadge(i.status)}</td>
          <td style="font-size:12px">${i.assignee_name ? `<span style="color:#00d4ff">👤 ${i.assignee_name}</span>` : '<span class="text-dim">Unassigned</span>'}</td>
          <td style="font-size:12px">${i.vector || '—'}</td>
          <td class="text-dim">${timeAgo(i.created_at)}</td>
          <td>
            <div class="action-buttons">
              <button class="btn-icon" onclick="viewIncidentDetail(${i.incident_id})" title="View">🔍</button>
              ${canEdit ? `<button class="btn-icon" onclick="openIncidentModal(${i.incident_id})" title="Edit">✏️</button>` : ''}
              ${currentUser.role_name === 'admin' ? `<button class="btn-danger" onclick="deleteIncident(${i.incident_id})" title="Delete">🗑️</button>` : ''}
            </div>
          </td>
        </tr>
      `;
        }).join('');
    } catch (err) {
        const denied = err.error || 'Failed to load incidents.';
        tbody.innerHTML = `<tr><td colspan="8" class="loading-cell" style="color:var(--critical)">🚫 ${denied}</td></tr>`;
    }
}

async function viewIncidentDetail(id) {
    const modal = document.getElementById('modal-incident-detail');
    const body = document.getElementById('incident-detail-body');
    body.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-dim)">⏳ Loading...</div>';
    modal.classList.remove('hidden');

    try {
        const i = await api('GET', `/incidents/${id}`);
        body.innerHTML = `
      <div class="detail-title">${i.title}</div>
      <div class="detail-badges">
        ${severityBadge(i.severity)}
        ${statusBadge(i.status)}
        ${i.vector ? `<span class="badge" style="background:rgba(0,212,255,0.1);color:var(--cyan);border:1px solid rgba(0,212,255,0.2)">⚡ ${i.vector}</span>` : ''}
      </div>
      <div class="detail-meta-grid">
        <div>
          <div class="detail-label">Reported By</div>
          <div class="detail-value">${i.reporter_name || '—'}</div>
        </div>
        <div>
          <div class="detail-label">Assigned To</div>
          <div class="detail-value" style="color:var(--cyan)">${i.assignee_name || 'Unassigned'}</div>
        </div>
        <div>
          <div class="detail-label">Affected System</div>
          <div class="detail-value">${i.affected_system || '—'}</div>
        </div>
        <div>
          <div class="detail-label">Created</div>
          <div class="detail-value">${formatDate(i.created_at)}</div>
        </div>
        <div>
          <div class="detail-label">Last Updated</div>
          <div class="detail-value">${formatDate(i.updated_at)}</div>
        </div>
        ${i.resolved_at ? `<div>
          <div class="detail-label">Resolved At</div>
          <div class="detail-value" style="color:var(--green)">${formatDate(i.resolved_at)}</div>
        </div>` : ''}
      </div>
      <div class="detail-section">
        <div class="detail-label">Description</div>
        <div class="detail-value" style="background:var(--bg-secondary);padding:14px;border-radius:8px;line-height:1.7">${i.description}</div>
      </div>
    `;
    } catch (err) {
        body.innerHTML = `<div style="text-align:center;padding:40px;color:var(--critical)">🚫 ${err.error || 'Failed to load.'}</div>`;
    }
}

function openIncidentModal(id = null) {
    const form = document.getElementById('incident-form');
    const title = document.getElementById('incident-modal-title');
    const btn = document.getElementById('incident-submit-btn');
    const err = document.getElementById('incident-form-error');

    form.reset();
    err.classList.add('hidden');
    document.getElementById('incident-id').value = id || '';

    // Load analysts for assignment (manager/admin)
    if (['admin', 'soc_manager'].includes(currentUser.role_name)) {
        loadAnalystsDropdown('inc-assigned');
        document.getElementById('assign-row').style.display = 'grid';
    } else {
        // Analyst: only show status field
        document.getElementById('assign-row').style.display =
            currentUser.role_name === 'security_analyst' ? 'grid' : 'none';
        document.getElementById('inc-assigned').closest('.form-group').style.display =
            currentUser.role_name === 'security_analyst' ? 'none' : 'block';
    }

    if (id) {
        title.textContent = 'Edit Incident';
        btn.textContent = 'Update Incident';
        // Pre-fill
        api('GET', `/incidents/${id}`).then(i => {
            document.getElementById('inc-title').value = i.title;
            document.getElementById('inc-severity').value = i.severity;
            document.getElementById('inc-description').value = i.description;
            document.getElementById('inc-system').value = i.affected_system || '';
            document.getElementById('inc-vector').value = i.vector || '';
            document.getElementById('inc-status').value = i.status;
            if (i.assigned_to) document.getElementById('inc-assigned').value = i.assigned_to;
        }).catch(() => { });
    } else {
        title.textContent = 'Create New Incident';
        btn.textContent = 'Create Incident';
    }

    document.getElementById('modal-incident').classList.remove('hidden');
}

async function loadAnalystsDropdown(selectId) {
    try {
        const analysts = await api('GET', '/users/analysts');
        const sel = document.getElementById(selectId);
        if (!sel) return;
        const existing = sel.value;
        sel.innerHTML = '<option value="">— Unassigned —</option>';
        analysts.forEach(a => {
            const opt = document.createElement('option');
            opt.value = a.user_id;
            opt.textContent = `${a.name} (${a.email})`;
            sel.appendChild(opt);
        });
        if (existing) sel.value = existing;
    } catch { }
}

async function submitIncident(e) {
    e.preventDefault();
    const id = document.getElementById('incident-id').value;
    const err = document.getElementById('incident-form-error');
    err.classList.add('hidden');

    const payload = {
        title: document.getElementById('inc-title').value,
        severity: document.getElementById('inc-severity').value,
        description: document.getElementById('inc-description').value,
        affected_system: document.getElementById('inc-system').value,
        vector: document.getElementById('inc-vector').value,
        status: document.getElementById('inc-status').value,
    };

    if (['admin', 'soc_manager'].includes(currentUser.role_name)) {
        payload.assigned_to = document.getElementById('inc-assigned').value || null;
    }

    try {
        if (id) {
            await api('PUT', `/incidents/${id}`, payload);
            showToast('Incident updated successfully ✓');
        } else {
            await api('POST', '/incidents', payload);
            showToast('Incident created successfully ✓');
        }
        closeModal('modal-incident');
        loadIncidents();
        loadDashboard();
    } catch (e2) {
        err.textContent = e2.error || 'Operation failed.';
        err.classList.remove('hidden');
    }
}

async function deleteIncident(id) {
    if (!confirm(`Delete incident #${id}? This action cannot be undone.`)) return;
    try {
        await api('DELETE', `/incidents/${id}`);
        showToast('Incident deleted.', 'warning');
        loadIncidents();
        loadDashboard();
    } catch (err) {
        showToast(err.error || 'Failed to delete.', 'error');
    }
}

// ─── Threat Reports ───────────────────────────────────────────────────────
async function loadReports() {
    const grid = document.getElementById('reports-grid');
    grid.innerHTML = '<div class="loading-cell">⏳ Loading reports...</div>';

    try {
        const reports = await api('GET', '/reports');
        if (!reports.length) {
            grid.innerHTML = '<div class="loading-cell">No threat reports found.</div>';
            return;
        }
        grid.innerHTML = reports.map(r => `
      <div class="report-card">
        <div class="report-header">
          <div class="report-incident">
            <div class="report-incident-title">📋 ${r.incident_title}</div>
            <div class="report-incident-meta">
              ${severityBadge(r.severity)} &nbsp;
              <span class="text-dim">by ${r.analyst_name} • ${timeAgo(r.created_at)}</span>
            </div>
          </div>
          <span class="text-mono text-dim">#${r.report_id}</span>
        </div>
        <div class="report-body">${r.report_text}</div>
        ${r.findings ? `
          <div class="report-section">
            <div class="report-section-label">🔍 Findings</div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6">${r.findings}</div>
          </div>
        ` : ''}
        ${r.recommendations ? `
          <div class="report-section">
            <div class="report-section-label">💡 Recommendations</div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6">${r.recommendations}</div>
          </div>
        ` : ''}
        ${r.ioc_data ? `<div class="report-ioc">🔺 IOC: ${r.ioc_data}</div>` : ''}
      </div>
    `).join('');
    } catch (err) {
        grid.innerHTML = `<div class="loading-cell" style="color:var(--critical)">🚫 ${err.error || 'Access denied.'}</div>`;
    }
}

async function openReportModal() {
    document.getElementById('report-form').reset();
    document.getElementById('report-form-error').classList.add('hidden');

    // Load incidents
    try {
        const incidents = await api('GET', '/incidents');
        const sel = document.getElementById('rep-incident');
        sel.innerHTML = '<option value="">Select incident...</option>';
        incidents.forEach(i => {
            const opt = document.createElement('option');
            opt.value = i.incident_id;
            opt.textContent = `#${i.incident_id} – ${i.title.slice(0, 50)}`;
            sel.appendChild(opt);
        });
    } catch { }

    document.getElementById('modal-report').classList.remove('hidden');
}

async function submitReport(e) {
    e.preventDefault();
    const err = document.getElementById('report-form-error');
    err.classList.add('hidden');

    const payload = {
        incident_id: document.getElementById('rep-incident').value,
        report_text: document.getElementById('rep-text').value,
        findings: document.getElementById('rep-findings').value,
        recommendations: document.getElementById('rep-recommendations').value,
        ioc_data: document.getElementById('rep-ioc').value,
    };

    try {
        await api('POST', '/reports', payload);
        showToast('Threat report submitted successfully ✓');
        closeModal('modal-report');
        loadReports();
    } catch (e2) {
        err.textContent = e2.error || 'Failed to submit report.';
        err.classList.remove('hidden');
    }
}

// ─── Systems ──────────────────────────────────────────────────────────────
async function loadSystems() {
    const grid = document.getElementById('systems-grid');
    grid.innerHTML = '<div class="loading-cell">⏳ Loading systems...</div>';

    // Show add button for admin
    const btn = document.getElementById('btn-create-system');
    if (btn && currentUser.role_name === 'admin') btn.style.display = 'inline-flex';

    try {
        const systems = await api('GET', '/systems');
        if (!systems.length) {
            grid.innerHTML = '<div class="loading-cell">No systems found.</div>';
            return;
        }
        const statusClass = { Online: 'sys-online', Compromised: 'sys-compromised', Offline: 'sys-offline', 'Under Maintenance': 'sys-maintenance' };
        const statusDot = { Online: '🟢', Compromised: '🔴', Offline: '⚫', 'Under Maintenance': '🟡' };

        grid.innerHTML = systems.map(s => `
      <div class="system-card ${statusClass[s.status] || ''}">
        <div class="system-header">
          <div>
            <div class="system-name">${statusDot[s.status] || '⚪'} ${s.system_name}</div>
            <div class="system-ip">${s.ip_address}</div>
          </div>
        </div>
        <div class="system-meta">
          <div class="system-meta-row"><span class="system-meta-label">Owner:</span> ${s.owner || '—'}</div>
          <div class="system-meta-row"><span class="system-meta-label">OS:</span> ${s.os_type || '—'}</div>
          <div class="system-meta-row"><span class="system-meta-label">Location:</span> ${s.location || '—'}</div>
          <div class="system-meta-row"><span class="system-meta-label">Status:</span>
            <span class="badge ${s.status === 'Online' ? 'badge-resolved' : s.status === 'Compromised' ? 'badge-critical' : 'badge-closed'}">${s.status}</span>
          </div>
        </div>
        ${currentUser.role_name === 'admin' ? `
          <div style="margin-top:12px;display:flex;gap:8px">
            <button class="btn-danger" onclick="deleteSystem(${s.system_id})" style="font-size:11px">🗑️ Remove</button>
          </div>
        ` : ''}
      </div>
    `).join('');
    } catch (err) {
        grid.innerHTML = `<div class="loading-cell" style="color:var(--critical)">🚫 ${err.error || 'Access denied.'}</div>`;
    }
}

function openSystemModal() {
    document.getElementById('system-form').reset();
    document.getElementById('modal-system').classList.remove('hidden');
}

async function submitSystem(e) {
    e.preventDefault();
    const err = document.getElementById('system-form-error');
    err.classList.add('hidden');
    const payload = {
        system_name: document.getElementById('sys-name').value,
        ip_address: document.getElementById('sys-ip').value,
        owner: document.getElementById('sys-owner').value,
        os_type: document.getElementById('sys-os').value,
        location: document.getElementById('sys-location').value,
        status: document.getElementById('sys-status').value,
    };
    try {
        await api('POST', '/systems', payload);
        showToast('System added successfully ✓');
        closeModal('modal-system');
        loadSystems();
    } catch (e2) {
        err.textContent = e2.error || 'Failed to add system.';
        err.classList.remove('hidden');
    }
}

async function deleteSystem(id) {
    if (!confirm('Remove this system?')) return;
    try {
        await api('DELETE', `/systems/${id}`);
        showToast('System removed.', 'warning');
        loadSystems();
    } catch (e) {
        showToast(e.error || 'Failed.', 'error');
    }
}

// ─── Users ────────────────────────────────────────────────────────────────
async function loadUsers() {
    const tbody = document.getElementById('users-body');
    tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">⏳ Loading users...</td></tr>`;

    try {
        const users = await api('GET', '/users');
        tbody.innerHTML = users.map(u => `
      <tr>
        <td class="text-mono text-dim">#${u.user_id}</td>
        <td><strong>${u.name}</strong></td>
        <td class="text-mono" style="font-size:12px">${u.email}</td>
        <td>
          <span class="badge" style="background:var(--cyan-dim);color:var(--cyan);border:1px solid rgba(0,212,255,0.2)">
            ${roleLabel(u.role_name)}
          </span>
        </td>
        <td>
          <span class="badge ${u.is_active ? 'badge-resolved' : 'badge-closed'}">
            ${u.is_active ? 'Active' : 'Inactive'}
          </span>
        </td>
        <td class="text-dim">${formatDate(u.last_login)}</td>
        <td>
          <div class="action-buttons">
            <button class="btn-icon" onclick="openUserModal(${u.user_id})" title="Edit">✏️</button>
            ${u.user_id !== currentUser.user_id ? `
              <button class="btn-danger" onclick="deactivateUser(${u.user_id})" title="Deactivate">🚫</button>
            ` : '<span class="text-dim" style="font-size:11px">You</span>'}
          </div>
        </td>
      </tr>
    `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading-cell" style="color:var(--critical)">🚫 ${err.error || 'Access denied.'}</td></tr>`;
    }
}

async function openUserModal(id = null) {
    const form = document.getElementById('user-form');
    const title = document.getElementById('user-modal-title');
    const btn = document.getElementById('user-submit-btn');
    const err = document.getElementById('user-form-error');

    form.reset();
    err.classList.add('hidden');
    document.getElementById('user-id').value = id || '';

    // Load roles
    try {
        const roles = await api('GET', '/users/roles');
        const sel = document.getElementById('user-role');
        sel.innerHTML = '<option value="">Select role...</option>';
        roles.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.role_id;
            opt.textContent = roleLabel(r.role_name);
            sel.appendChild(opt);
        });
    } catch { }

    if (id) {
        title.textContent = 'Edit User';
        btn.textContent = 'Update User';
        document.getElementById('user-password').placeholder = 'Leave blank to keep current';
        document.getElementById('user-password').required = false;
        // Pre-fill from users list
        try {
            const users = await api('GET', '/users');
            const u = users.find(x => x.user_id === id);
            if (u) {
                document.getElementById('user-name').value = u.name;
                document.getElementById('user-email').value = u.email;
                // find role_id by role_name
                const roles = await api('GET', '/users/roles');
                const role = roles.find(r => r.role_name === u.role_name);
                if (role) document.getElementById('user-role').value = role.role_id;
            }
        } catch { }
    } else {
        title.textContent = 'Create New User';
        btn.textContent = 'Create User';
        document.getElementById('user-password').required = true;
    }

    document.getElementById('modal-user').classList.remove('hidden');
}

async function submitUser(e) {
    e.preventDefault();
    const id = document.getElementById('user-id').value;
    const err = document.getElementById('user-form-error');
    err.classList.add('hidden');

    const payload = {
        name: document.getElementById('user-name').value,
        email: document.getElementById('user-email').value,
        role_id: document.getElementById('user-role').value,
        password: document.getElementById('user-password').value || undefined,
    };

    try {
        if (id) {
            await api('PUT', `/users/${id}`, payload);
            showToast('User updated successfully ✓');
        } else {
            await api('POST', '/users', payload);
            showToast('User created successfully ✓');
        }
        closeModal('modal-user');
        loadUsers();
    } catch (e2) {
        err.textContent = e2.error || 'Operation failed.';
        err.classList.remove('hidden');
    }
}

async function deactivateUser(id) {
    if (!confirm('Deactivate this user?')) return;
    try {
        await api('DELETE', `/users/${id}`);
        showToast('User deactivated.', 'warning');
        loadUsers();
    } catch (err) {
        showToast(err.error || 'Failed.', 'error');
    }
}

// ─── RBAC ─────────────────────────────────────────────────────────────────
async function loadRBAC() {
    const grid = document.getElementById('rbac-grid');
    grid.innerHTML = '<div class="loading-cell">⏳ Loading permissions...</div>';

    try {
        const perms = await api('GET', '/rbac/permissions');

        // Group by role
        const grouped = {};
        perms.forEach(p => {
            if (!grouped[p.role_name]) grouped[p.role_name] = [];
            grouped[p.role_name].push(p);
        });

        // Build SQL preview
        const sqlLines = [];
        const roleInfo = {
            admin: { icon: '👑', color: '#ffd60a' },
            soc_manager: { icon: '🎯', color: '#00d4ff' },
            security_analyst: { icon: '🔬', color: '#00ff88' },
            auditor: { icon: '📝', color: '#a78bfa' },
        };

        Object.entries(grouped).forEach(([role, permissions]) => {
            sqlLines.push(`-- Role: ${role.toUpperCase()}`);
            permissions.forEach(p => {
                sqlLines.push(`GRANT ${p.action} ON ${p.resource} TO ${role};`);
            });
            sqlLines.push('');
        });

        document.getElementById('rbac-sql-preview').textContent = sqlLines.join('\n');

        // Build cards
        const resources = ['incidents', 'users', 'threat_reports', 'access_logs', 'systems'];
        const allActions = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

        grid.innerHTML = Object.entries(grouped).map(([role, permissions]) => {
            const info = roleInfo[role] || { icon: '👤', color: '#888' };
            const permSet = new Set(permissions.map(p => `${p.resource}:${p.action}`));
            return `
        <div class="rbac-role-card">
          <div class="rbac-role-name" style="color:${info.color}">
            ${info.icon} ${roleLabel(role)}
          </div>
          <table class="rbac-table">
            <thead>
              <tr>
                <th>Resource</th>
                ${allActions.map(a => `<th>${a}</th>`).join('')}
              </tr>
            </thead>
            <tbody>
              ${resources.map(res => `
                <tr>
                  <td style="font-family:monospace;font-size:11px;color:var(--text-dim)">${res}</td>
                  ${allActions.map(a => {
                const has = permSet.has(`${res}:${a}`);
                return `<td>${has ? `<span class="perm-allow">✓ ${a}</span>` : `<span class="perm-deny">✕</span>`}</td>`;
            }).join('')}
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
        }).join('');
    } catch (err) {
        grid.innerHTML = `<div class="loading-cell" style="color:var(--critical)">🚫 ${err.error || 'Failed to load.'}</div>`;
    }
}

// ─── Audit Logs ───────────────────────────────────────────────────────────
async function loadLogs(page = 1) {
    currentPage = page;
    const tbody = document.getElementById('logs-body');
    const statusFilter = document.getElementById('log-filter-status')?.value || '';
    const params = `?page=${page}&limit=25${statusFilter ? `&status=${statusFilter}` : ''}`;

    tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">⏳ Loading audit logs...</td></tr>`;

    try {
        const data = await api('GET', `/logs${params}`);

        // Stats bar
        const statsData = await api('GET', '/logs/stats');
        const statsBar = document.getElementById('log-stats-bar');
        if (statsBar) {
            statsBar.innerHTML = `
        <span class="log-stat" style="background:rgba(48,209,88,0.1);color:#30d158;border:1px solid rgba(48,209,88,0.2)">${statsData.total} Total</span>
        <span class="log-stat" style="background:rgba(255,45,85,0.1);color:#ff2d55;border:1px solid rgba(255,45,85,0.2)">${statsData.denied} Denied</span>
        <span class="log-stat" style="background:rgba(255,214,10,0.1);color:#ffd60a;border:1px solid rgba(255,214,10,0.2)">${statsData.warnings} Warnings</span>
      `;
        }

        if (!data.logs.length) {
            tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">No logs found.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.logs.map(l => `
      <tr style="${l.status === 'Denied' ? 'background:rgba(255,45,85,0.03)' : ''}">
        <td class="text-mono text-dim">#${l.log_id}</td>
        <td style="font-size:12px">${l.user_email || '—'}</td>
        <td style="font-size:12px;max-width:300px">${l.action}</td>
        <td style="font-size:12px">
          <span class="badge" style="background:rgba(0,212,255,0.07);color:var(--text-secondary);border:1px solid var(--border)">${l.resource || '—'}</span>
        </td>
        <td>${logStatusBadge(l.status)}</td>
        <td class="text-mono text-dim" style="font-size:11px">${l.ip_address || '—'}</td>
        <td class="text-dim">${formatDate(l.timestamp)}</td>
      </tr>
    `).join('');

        // Pagination
        const pagination = document.getElementById('logs-pagination');
        if (data.pages > 1) {
            let pages = '';
            for (let i = 1; i <= data.pages; i++) {
                pages += `<button class="page-btn ${i === page ? 'active' : ''}" onclick="loadLogs(${i})">${i}</button>`;
            }
            pagination.innerHTML = `
        <button class="page-btn" onclick="loadLogs(${Math.max(1, page - 1)})" ${page === 1 ? 'disabled' : ''}>← Prev</button>
        ${pages}
        <button class="page-btn" onclick="loadLogs(${Math.min(data.pages, page + 1)})" ${page === data.pages ? 'disabled' : ''}>Next →</button>
      `;
        } else {
            pagination.innerHTML = '';
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading-cell" style="color:var(--critical)">🚫 ${err.error || 'Access denied.'}</td></tr>`;
    }
}

// ─── Modal utilities ──────────────────────────────────────────────────────
function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal:not(.hidden)').forEach(m => m.classList.add('hidden'));
    }
});

// ─── Init ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
});
