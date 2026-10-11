'use strict';

(function () {
  const form = document.getElementById('rule-editor');
  if (!form || form.action.includes('/edit')) return;
  const secondPart = document.getElementById('rule-step2');
  const grid = secondPart.querySelector(':scope > .form-grid');
  const picker = form.querySelector('.proto-picker');
  if (!grid || !picker) return;

  const labels = ['选择协议', '内网服务', '公网入口', '访问与选项', '确认创建'];
  const descriptions = [
    '先选择服务使用的协议。不同协议需要填写的内容会有所不同。',
    '填写服务在这台内网机器上的地址。Docker 服务填写宿主机发布端口。',
    '设置访问者使用的公网端口。网站和 TLS 服务还可以按域名区分。',
    '确认是否保留访问者 IP，其他设置按需展开。',
    '检查访问路径与关键设置。创建后，启用的隧道会立即同步到内网机器。'
  ];
  const machine = form.dataset.clientName || '当前机器';
  const draftKey = 'opennofrp-tunnel-draft:' + new URL(form.action, location.href).pathname;
  const draftFields = ['protocol', 'name', 'local_ip', 'local_port', 'remote_port', 'remote_port_end', 'domains', 'path_prefix', 'tls_mode', 'redirect_https', 'preserve_source_ip', 'enabled'];
  let restored = null;
  try { restored = JSON.parse(sessionStorage.getItem(draftKey) || 'null'); } catch (_) { /* Storage is optional. */ }
  if (restored && restored.values && typeof restored.values === 'object') {
    draftFields.forEach(name => {
      const controls = form.querySelectorAll('[name="' + name + '"]');
      if (!(name in restored.values)) return;
      controls.forEach(control => {
        if (control.type === 'radio') control.checked = control.value === restored.values[name];
        else if (control.type === 'checkbox') control.checked = Boolean(restored.values[name]);
        else control.value = String(restored.values[name]);
      });
    });
    form.querySelector('[name="remote_port"]').dataset.touched = '1';
    const radio = form.querySelector('[name="protocol"]:checked');
    if (radio) radio.dispatchEvent(new Event('change', { bubbles: true }));
  }

  const layout = document.createElement('div'); layout.className = 'wizard-layout';
  const aside = document.createElement('aside'); aside.className = 'wizard-aside'; aside.setAttribute('aria-label', '创建进度');
  const progress = document.createElement('ol'); progress.className = 'wizard-progress';
  const progressButtons = labels.map((label, index) => {
    const item = document.createElement('li');
    const button = document.createElement('button'); button.type = 'button';
    const number = document.createElement('span'); number.className = 'wizard-number'; number.textContent = index + 1;
    const title = document.createElement('strong'); title.textContent = label;
    button.append(number, title); item.append(button); progress.append(item); return button;
  });
  const asideNote = document.createElement('p'); asideNote.className = 'wizard-aside-note'; asideNote.textContent = '配置过程中不会开放端口。确认并创建后才会生效。';
  aside.append(progress, asideNote);
  const content = document.createElement('div'); content.className = 'wizard-content';
  const heading = document.createElement('h2'); heading.id = 'wizard-step-heading'; heading.tabIndex = -1;
  const guidance = document.createElement('p'); guidance.className = 'wizard-guidance';
  const position = document.createElement('div'); position.className = 'wizard-position'; position.setAttribute('aria-live', 'polite');
  content.append(position, heading, guidance);
  layout.append(aside, content); form.prepend(layout);
  form.querySelectorAll(':scope > .step-title, #rule-step2 > .step-title').forEach(title => title.remove());
  const card = form.closest('.card');
  Array.from(card.children).filter(child => child.tagName === 'H2' || child.classList.contains('desc')).forEach(child => child.hidden = true);

  const steps = labels.map((_, index) => {
    const step = document.createElement('section'); step.className = 'wizard-step'; step.dataset.wizardStep = index;
    step.setAttribute('aria-labelledby', heading.id);
    const fields = document.createElement('div'); fields.className = 'form-grid'; step.append(fields);
    return { step, fields };
  });
  steps[0].step.prepend(picker); content.append(steps[0].step, secondPart);
  steps.slice(1).forEach(({step}) => secondPart.append(step));
  function moveFields(names, target) {
    Array.from(grid.children).filter(field => names.some(name => field.querySelector('[name="' + name + '"]'))).forEach(field => target.append(field));
  }
  moveFields(['name', 'local_ip', 'local_port'], steps[1].fields);
  moveFields(['remote_port', 'remote_port_end', 'domains', 'tls_mode'], steps[2].fields);
  Array.from(grid.children).forEach(field => { if (field.classList.contains('step-title')) field.remove(); else steps[3].fields.append(field); });
  grid.remove();
  const accessTip = document.createElement('p'); accessTip.className = 'wizard-tip'; accessTip.textContent = '保留来源 IP 需要内网机器具备相应权限。普通转发可关闭；负载均衡和访问限制按需设置即可。'; steps[3].step.prepend(accessTip);
  const preview = secondPart.querySelector('.connection-preview'); if (preview) steps[4].step.prepend(preview);
  const review = document.createElement('dl'); review.className = 'wizard-review'; steps[4].fields.append(review);
  const actions = form.querySelector('.form-actions');
  const submit = actions.querySelector('button[type="submit"]'); submit.textContent = '确认并创建隧道';
  const previous = document.createElement('button'); previous.type = 'button'; previous.className = 'btn'; previous.textContent = '← 上一步';
  const next = document.createElement('button'); next.type = 'button'; next.className = 'btn btn-primary'; next.textContent = '下一步 →';
  const cancel = document.createElement('a'); cancel.className = 'wizard-cancel'; cancel.href = form.getAttribute('action').replace(/\/rules$/, ''); cancel.textContent = '取消创建';
  actions.prepend(cancel, previous); actions.append(next); content.append(actions);
  let current = 0; let furthest = 0;

  function selectedProtocol() { return form.querySelector('[name="protocol"]:checked')?.value || ''; }
  function value(name) { return form.querySelector('[name="' + name + '"]')?.value || ''; }
  function checked(name) { return Boolean(form.querySelector('[name="' + name + '"]')?.checked); }
  function saveDraft() {
    const values = {};
    draftFields.forEach(name => {
      const control = form.querySelector('[name="' + name + '"]');
      if (control) values[name] = control.type === 'radio' ? selectedProtocol() : control.type === 'checkbox' ? control.checked : control.value;
    });
    // Certificates, passwords, authentication headers and tokens are never saved.
    try { sessionStorage.setItem(draftKey, JSON.stringify({values, step: current})); } catch (_) { /* Continue without a draft. */ }
  }
  function renderReview() {
    const proto = selectedProtocol();
    const rows = [
      ['隧道名称', value('name') || '尚未填写'], ['目标机器', machine], ['协议', proto.toUpperCase()],
      ['内网服务', (value('local_ip') || '127.0.0.1') + ':' + value('local_port')],
      ['公网入口', '端口 ' + value('remote_port') + (value('remote_port_end') && ['tcp','udp','tcp+udp'].includes(proto) ? ' – ' + value('remote_port_end') : '')],
      ['保留来源 IP', checked('preserve_source_ip') ? '开启（需要内网机器支持）' : '关闭'],
      ['创建后状态', checked('enabled') ? '立即启用' : '保持停用']
    ];
    if (['http','tls'].includes(proto)) rows.push(['域名', value('domains') || '所有未被认领的域名']);
    if (proto === 'http') rows.push(['访问路径', value('path_prefix') || '/'], ['HTTPS', {acme:'自动证书',custom:'自定义证书'}[value('tls_mode')] || '关闭']);
    review.replaceChildren(); rows.forEach(([label,text]) => { const dt = document.createElement('dt'); dt.textContent = label; const dd = document.createElement('dd'); dd.textContent = text; review.append(dt,dd); });
  }
  function showStep(index, focus = true) {
    current = index; furthest = Math.max(furthest, index);
    steps.forEach(({step}, i) => step.hidden = i !== index);
    progressButtons.forEach((button,i) => {
      button.disabled = i > furthest;
      button.parentElement.classList.toggle('active', i === index); button.parentElement.classList.toggle('complete', i < index);
      if (i === index) button.setAttribute('aria-current','step'); else button.removeAttribute('aria-current');
    });
    heading.textContent = labels[index]; guidance.textContent = descriptions[index]; position.textContent = '步骤 ' + (index+1) + ' / ' + labels.length;
    previous.hidden = index === 0; next.hidden = index === labels.length-1; submit.hidden = index !== labels.length-1;
    if (index === labels.length-1) renderReview();
    if (focus) heading.focus(); saveDraft();
  }
  function validateStep(index) {
    if (index === 0 && !selectedProtocol()) { guidance.textContent = '请选择一种协议，再继续下一步。'; picker.querySelector('input').focus(); return false; }
    if (index === 1) {
      const field = form.querySelector('[name="local_ip"]'); const ip = field.value.trim();
      let valid = !ip;
      if (ip.includes(':')) { try { valid = new URL('http://[' + ip + ']/').hostname.startsWith('['); } catch (_) { valid = false; } }
      else if (ip) { const parts = ip.split('.'); valid = parts.length === 4 && parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255); }
      if (typeof field.setCustomValidity === 'function') field.setCustomValidity(valid ? '' : '请输入有效的 IPv4 或 IPv6 地址，例如 127.0.0.1。');
    }
    if (index === 2) {
      const end = form.querySelector('[name="remote_port_end"]');
      if (end && !end.disabled && typeof end.setCustomValidity === 'function') {
        const count = Number(end.value) - Number(value('remote_port')) + 1;
        end.setCustomValidity(end.value && (count < 1 || count > 1000 || Number(value('local_port')) + count - 1 > 65535) ? '结束端口不得小于起始端口，端口段最多 1000 个，且本地端口不得超出 65535。' : '');
      }
    }
    for (const control of steps[index].step.querySelectorAll('input,select,textarea')) {
      if (control.disabled || typeof control.checkValidity !== 'function') continue;
      if (!control.checkValidity()) { const details = control.closest('details'); if (details) details.open = true; control.reportValidity(); return false; }
    }
    return true;
  }
  next.addEventListener('click', () => { if (validateStep(current)) showStep(current+1); });
  previous.addEventListener('click', () => showStep(Math.max(0,current-1)));
  progressButtons.forEach((button,index) => button.addEventListener('click', () => {
    if (index > current) { for (let step=current;step<index;step++) if (!validateStep(step)) { showStep(step); return; } }
    showStep(index);
  }));
  form.addEventListener('invalid', event => {
    const step = event.target.closest('[data-wizard-step]'); if (step) showStep(Number(step.dataset.wizardStep), false);
  }, true);
  form.addEventListener('input', () => {
    const end = form.querySelector('[name="remote_port_end"]'); if (end && typeof end.setCustomValidity === 'function') end.setCustomValidity('');
    saveDraft(); if (current === 4) renderReview();
  });
  form.addEventListener('change', () => { saveDraft(); if (current === 4) renderReview(); });
  form.addEventListener('keydown', event => {
    if (event.key === 'Enter' && current !== 4 && event.target.tagName === 'INPUT' && !['radio','checkbox'].includes(event.target.type)) { event.preventDefault(); next.click(); }
  });
  form.addEventListener('submit', event => {
    if (current !== 4) { event.preventDefault(); next.click(); return; }
    for (let step=0;step<4;step++) { if (!validateStep(step)) { event.preventDefault(); showStep(step); return; } }
  });
  const savedStep = restored && Number.isInteger(restored.step) ? Math.min(4, Math.max(0,restored.step)) : 0;
  showStep(selectedProtocol() ? savedStep : 0, false);
})();
