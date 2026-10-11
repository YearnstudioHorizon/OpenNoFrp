'use strict';

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return; } catch (_) { /* Try selection fallback. */ }
  }
  const active = document.activeElement;
  const field = document.createElement('textarea');
  field.value = text;
  field.style.cssText = 'position:fixed;left:-9999px;top:0';
  document.body.append(field);
  field.select();
  let copied = false;
  try { copied = document.execCommand('copy'); }
  finally { field.remove(); if (active && active.focus) active.focus(); }
  if (!copied) throw new Error('请选中内容后手动复制');
}

document.addEventListener('click', async function (event) {
  const button = event.target.closest('[data-copy-target]');
  if (!button || button.disabled) return;
  const target = document.querySelector(button.dataset.copyTarget);
  if (!target) return;
  const original = button.textContent;
  button.disabled = true;
  try { await copyText(target.textContent); button.textContent = '已复制'; }
  catch (error) { button.textContent = '请手动复制'; target.focus(); }
  finally { setTimeout(() => { button.disabled = false; button.textContent = original; }, 1800); }
});

const updateButton = document.getElementById('btn-check-update');
if (updateButton) updateButton.addEventListener('click', async function () {
  const box = document.getElementById('update-alert');
  updateButton.disabled = true;
  updateButton.textContent = '检查中…';
  box.style.display = 'none';
  try {
    const response = await fetch('/api/check-update', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('请求失败（HTTP ' + response.status + '），请确认登录状态');
    const data = await response.json();
    if (!data.ok || !data.info) throw new Error(data.error || '版本信息不可用');
    const info = data.info;
    box.className = 'alert alert-ok';
    box.replaceChildren();
    box.append(document.createTextNode(info.has_update ? '发现新版本 ' + info.latest_version + '，当前版本 ' + info.current_version + '。 ' : '当前已是最新版本（' + info.current_version + '）'));
    if (info.has_update) {
      const url = new URL(info.release_url);
      if (url.protocol === 'https:' && url.hostname === 'github.com') {
        const link = document.createElement('a');
        link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = '查看更新说明';
        box.append(link);
      }
      const command = document.createElement('code');
      command.textContent = 'sudo opennofrp-server update';
      box.append(document.createTextNode(' · 更新命令：'), command);
    }
  } catch (error) { box.className = 'alert alert-err'; box.textContent = '检查更新失败：' + error.message; }
  finally { box.style.display = 'block'; updateButton.disabled = false; updateButton.textContent = '检查更新'; }
});
