// @ts-check
import { apiRequest } from './api.js';

const usersTableBody = document.getElementById('users-table-body');
const logsTableBody = document.getElementById('logs-table-body');
const btnRefreshLogs = document.getElementById('btn-refresh-logs');
const btnLogout = document.getElementById('btn-logout');

// Validar que el usuario en sesión sea ADMIN
const cachedUser = JSON.parse(sessionStorage.getItem('vault_user') || 'null');
if (!cachedUser || cachedUser.role !== 'ADMIN') {
  alert('Acceso restringido: requiere privilegios de ADMINISTRADOR (RF-03)');
  window.location.href = '/index.html';
}

btnLogout?.addEventListener('click', async () => {
  try {
    await apiRequest('/auth/logout', { method: 'POST' });
  } catch {}
  sessionStorage.removeItem('vault_user');
  window.location.href = '/login.html';
});

async function loadAdminData() {
  await Promise.all([loadUsers(), loadAuditLogs()]);
}

async function loadUsers() {
  try {
    const res = await apiRequest('/admin/users');
    if (!usersTableBody) return;

    usersTableBody.innerHTML = res.users.map((u) => `
      <tr>
        <td style="font-family: monospace; font-size: 0.8rem;">${u.id}</td>
        <td>${escapeHtml(u.email)}</td>
        <td>
          <span class="${u.role === 'ADMIN' ? 'badge-admin' : 'badge-user'}">${u.role}</span>
        </td>
        <td style="color: var(--text-muted); font-size: 0.8rem;">${new Date(u.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (error) {
    if (usersTableBody) {
      usersTableBody.innerHTML = `<tr><td colspan="4" style="color: var(--accent-rose);">Error: ${error.message}</td></tr>`;
    }
  }
}

async function loadAuditLogs() {
  try {
    const res = await apiRequest('/admin/audit-logs?limit=50');
    if (!logsTableBody) return;

    logsTableBody.innerHTML = res.logs.map((l) => {
      let badgeColor = 'var(--text-muted)';
      if (l.event_type.includes('FAILURE') || l.event_type.includes('DENIED')) badgeColor = 'var(--accent-rose)';
      if (l.event_type.includes('SUCCESS')) badgeColor = 'var(--accent-emerald)';

      return `
        <tr>
          <td style="color: var(--text-muted); font-size: 0.75rem; white-space: nowrap;">${new Date(l.created_at).toLocaleString()}</td>
          <td><strong style="color: ${badgeColor}; font-size: 0.8rem;">${l.event_type}</strong></td>
          <td style="font-family: monospace; font-size: 0.8rem;">${l.ip_address}</td>
          <td style="font-family: monospace; font-size: 0.75rem;">${l.user_id || 'N/A'}</td>
          <td style="font-family: monospace; font-size: 0.75rem; max-width: 300px; word-break: break-all;">${escapeHtml(l.details)}</td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    if (logsTableBody) {
      logsTableBody.innerHTML = `<tr><td colspan="5" style="color: var(--accent-rose);">Error: ${error.message}</td></tr>`;
    }
  }
}

btnRefreshLogs?.addEventListener('click', loadAuditLogs);

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

loadAdminData();
