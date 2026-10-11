'use strict';

const root = document.documentElement;
function syncThemeButtons() {
  const dark = root.dataset.theme === 'dark';
  document.querySelectorAll('.theme-toggle').forEach(button => {
    button.setAttribute('aria-label', dark ? '切换浅色主题' : '切换深色主题');
    button.setAttribute('aria-pressed', String(dark));
    const label = button.querySelector('span');
    if (label) label.textContent = dark ? '浅色模式' : '深色模式';
  });
}
document.querySelectorAll('.theme-toggle').forEach(button => button.addEventListener('click', () => {
  root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('opennofrp-theme', root.dataset.theme); } catch (_) { /* Theme remains usable without storage. */ }
  syncThemeButtons();
}));
syncThemeButtons();

const menu = document.querySelector('.mobile-menu');
const overlay = document.querySelector('.nav-overlay');
const sidebar = document.querySelector('.sidebar');
const mobileLayout = typeof window.matchMedia === 'function' ? window.matchMedia('(max-width: 800px)') : null;
function closeMenu() {
  const wasOpen = document.body.classList.contains('nav-open');
  document.body.classList.remove('nav-open'); if (menu) menu.setAttribute('aria-expanded', 'false'); if (overlay) overlay.hidden = true;
  if (sidebar) sidebar.inert = Boolean(mobileLayout && mobileLayout.matches);
  if (wasOpen && menu) menu.focus();
}
if (menu) menu.addEventListener('click', () => {
  const open = !document.body.classList.contains('nav-open');
  document.body.classList.toggle('nav-open', open); menu.setAttribute('aria-expanded', String(open)); overlay.hidden = !open;
  if (sidebar) { sidebar.inert = false; if (open) sidebar.querySelector('a').focus(); }
});
if (overlay) overlay.addEventListener('click', closeMenu);
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeMenu();
  if (event.key === 'Tab' && sidebar && document.body.classList.contains('nav-open')) {
    const links = sidebar.querySelectorAll('a'); const first = links[0]; const last = links[links.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
if (mobileLayout) { mobileLayout.addEventListener('change', closeMenu); closeMenu(); }
document.querySelectorAll('.sidebar nav a').forEach(link => link.addEventListener('click', closeMenu));
function syncNavigation() {
  const detail = location.pathname.startsWith('/clients/');
  const key = detail ? 'clients' : (location.hash.slice(1) || 'overview');
  document.querySelectorAll('[data-nav]').forEach(link => {
    const active = link.dataset.nav === key;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
  const locationLabel = document.getElementById('page-location');
  if (locationLabel) locationLabel.textContent = detail ? '机器详情' : '概览';
}
window.addEventListener('hashchange', syncNavigation); syncNavigation();

document.querySelectorAll('[data-table-search]').forEach(input => {
  const table = document.querySelector(input.dataset.tableSearch);
  const state = document.querySelector(input.dataset.stateFilter || '#nonexistent');
  if (!table) return;
  const rows = Array.from(table.querySelectorAll('tbody tr')).filter(row => !row.querySelector('.empty'));
  const output = document.querySelector(input.dataset.searchCount);
  const empty = document.createElement('tr');
  const cell = document.createElement('td'); cell.colSpan = table.querySelectorAll('thead th').length; cell.className = 'empty'; cell.textContent = '没有匹配的结果，试试其他关键词或状态。'; empty.append(cell); empty.hidden = true; table.querySelector('tbody').append(empty);
  function filter() {
    const query = input.value.trim().toLocaleLowerCase(); let count = 0;
    rows.forEach(row => {
      const show = row.textContent.toLocaleLowerCase().includes(query) && (!state || !state.value || row.dataset.state === state.value);
      row.hidden = !show; if (show) count++;
    });
    empty.hidden = !rows.length || count > 0;
    if (output) output.textContent = count + ' / ' + rows.length;
  }
  input.addEventListener('input', filter); if (state) state.addEventListener('change', filter); filter();
});

// Organize advanced fields without altering their names or submitted values.
const editor = document.getElementById('rule-editor');
if (editor) {
  const grid = editor.querySelector('#rule-step2 > .form-grid');
  const groups = [
    ['网站与证书', '域名、路径与 HTTPS', ['domains', 'path_prefix', 'tls_mode', 'redirect_https', 'tls_cert', 'tls_key']],
    ['真实 IP 与代理', '来源识别与可信代理', ['ip_sources', 'trusted_proxies']],
    ['HTTP 高级设置', '请求头、认证与自定义页面', ['offline_page', 'strip_prefix', 'host_rewrite', 'req_headers', 'resp_headers', 'basic_auth', 'ip_allow', 'not_found_page']],
    ['转发策略', '负载均衡与 PROXY 协议', ['backends', 'lb_strategy', 'proxy_protocol']],
    ['访问防护', '访问控制、并发与带宽限制', ['guard_allow', 'guard_deny', 'max_conns_per_ip', 'conn_rate_per_min', 'bandwidth_kbps']]
  ];
  const toggles = grid && grid.querySelector('[name="enabled"]')?.closest('.check-stack');
  if (grid) groups.forEach(([title, hint, names]) => {
    const fields = Array.from(grid.children).filter(field => names.some(name => field.querySelector('[name="' + name + '"]')));
    if (!fields.length) return;
    const details = document.createElement('details'); details.className = 'advanced-group span-all';
    const summary = document.createElement('summary'); const text = document.createElement('strong'); text.textContent = title; const help = document.createElement('span'); help.textContent = hint; summary.append(text, help);
    const inner = document.createElement('div'); inner.className = 'form-grid'; fields.forEach(field => inner.append(field)); details.append(summary, inner);
    grid.insertBefore(details, toggles || null);
    const isEdit = editor.action.includes('/edit');
    details.open = title === '网站与证书' || (isEdit && fields.some(field => Array.from(field.querySelectorAll('input,textarea,select')).some(control => control.type === 'checkbox' ? control.checked : control.value && control.value !== 'round_robin')));
  });
  function syncGroups() {
    editor.querySelectorAll('.advanced-group').forEach(group => { group.hidden = Array.from(group.querySelector('.form-grid').children).every(field => field.hidden); });
  }
  editor.addEventListener('change', syncGroups); syncGroups();
  editor.addEventListener('invalid', event => { const group = event.target.closest('details'); if (group) group.open = true; }, true);
  // Keep unselected protocol fields from blocking native browser validation.
  function syncProtocol() {
    const selected = editor.querySelector('[name="protocol"]:checked');
    editor.querySelectorAll('#rule-step2 input, #rule-step2 select, #rule-step2 textarea').forEach(control => {
      control.disabled = !selected || Boolean(control.closest('[hidden]'));
    });
    syncGroups();
  }
  editor.addEventListener('change', syncProtocol); syncProtocol();
  const preview = document.createElement('div'); preview.className = 'connection-preview'; preview.setAttribute('aria-live', 'polite');
  editor.querySelector('#rule-step2').prepend(preview);
  function updatePreview() {
    const ip = editor.querySelector('[name="local_ip"]').value || '127.0.0.1';
    const local = editor.querySelector('[name="local_port"]').value || '—';
    const remote = editor.querySelector('[name="remote_port"]').value || '—';
    preview.textContent = '访问者 → 公网端口 ' + remote + ' → 内网服务 ' + ip + ':' + local;
  }
  editor.addEventListener('input', updatePreview); editor.addEventListener('change', updatePreview); updatePreview();
}

const confirmation = document.getElementById('confirm-dialog');
if (confirmation) {
  const approved = new WeakSet(); let pendingForm = null; let pendingButton = null;
  document.querySelectorAll('form[data-confirm]').forEach(form => form.addEventListener('submit', event => {
    if (approved.has(form)) { approved.delete(form); return; }
    if (typeof confirmation.showModal !== 'function') { if (!window.confirm(form.dataset.confirm)) event.preventDefault(); return; }
    event.preventDefault(); pendingForm = form; pendingButton = event.submitter;
    document.getElementById('confirm-description').textContent = form.dataset.confirm;
    confirmation.showModal(); document.getElementById('confirm-cancel').focus();
  }));
  document.getElementById('confirm-cancel').addEventListener('click', () => confirmation.close());
  document.getElementById('confirm-accept').addEventListener('click', () => {
    const form = pendingForm; const button = pendingButton;
    confirmation.close(); if (!form) return;
    approved.add(form); form.requestSubmit(button || undefined);
  });
  confirmation.addEventListener('close', () => { pendingForm = null; pendingButton = null; });
}

document.querySelectorAll('form').forEach(form => form.addEventListener('submit', event => {
  if (event.defaultPrevented) return;
  const button = event.submitter;
  if (!button || button.tagName !== 'BUTTON') return;
  // Delaying preserves submitter values and existing confirmation handlers.
  const original = button.textContent;
  setTimeout(() => { if (event.defaultPrevented) return; button.dataset.originalText = original; button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = '处理中…'; }, 0);
}));
window.addEventListener('pageshow', event => { if (event.persisted) document.querySelectorAll('[aria-busy="true"]').forEach(button => { button.disabled = false; button.removeAttribute('aria-busy'); button.textContent = button.dataset.originalText || '提交'; }); });

document.querySelectorAll('.alert').forEach(alert => { alert.setAttribute('role', alert.classList.contains('alert-err') ? 'alert' : 'status'); });
