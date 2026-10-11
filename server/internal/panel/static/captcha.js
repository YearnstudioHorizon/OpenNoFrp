'use strict';
(function () {
  const settings = document.getElementById('captcha-settings');
  if (settings) {
    const select = settings.querySelector('[name="provider"]');
    const sync = () => settings.querySelectorAll('[data-captcha-settings]').forEach(group => { group.hidden = group.dataset.captchaSettings !== select.value; group.querySelectorAll('input').forEach(control => { control.disabled = group.hidden; }); });
    select.addEventListener('change', sync); sync();
  }
  const form = document.getElementById('login-form');
  if (!form) return;
  const image = document.getElementById('captcha-image');
  const status = document.getElementById('captcha-status');
  if (image) {
    const refresh = document.getElementById('captcha-refresh');
    refresh.addEventListener('click', () => {
      form.querySelector('[name="captcha_answer"]').value = '';
      image.src = '/captcha/image?t=' + Date.now(); status.textContent = '正在刷新…';
    });
    image.addEventListener('load', () => { status.textContent = '请输入图片中的五位数字，三分钟内有效。'; });
    image.addEventListener('error', () => { status.textContent = '验证码加载失败，请点击“换一张”重试。'; });
    return;
  }
  const config = document.getElementById('captcha-config');
  if (!config) return;
  let verified = false;
  const fields = ['captcha_token', 'lot_number', 'captcha_output', 'pass_token', 'gen_time'];
  function reset(message) {
    verified = false; fields.forEach(name => { form.querySelector('[name="'+name+'"]').value = ''; });
    status.textContent = message;
  }
  form.addEventListener('submit', event => { if (!verified) { event.preventDefault(); status.textContent = '请先完成人机验证。加载失败时可刷新页面重试。'; } });
  function loadScript(src, ready) {
    const script = document.createElement('script'); script.src = src; script.async = true;
    const timer = setTimeout(() => reset('验证服务加载超时，请刷新页面重试。'), 15000);
    script.onload = () => { clearTimeout(timer); try { ready(); } catch (_) { reset('验证服务初始化失败，请检查配置或刷新页面。'); } };
    script.onerror = () => { clearTimeout(timer); reset('验证服务加载失败，请检查网络或刷新页面。'); };
    document.head.append(script);
  }
  if (config.dataset.provider === 'fcaptcha') {
    loadScript(config.dataset.instance + '/fcaptcha.js', () => {
      FCaptcha.configure({serverUrl: config.dataset.instance, lang: 'zh-CN'});
      FCaptcha.render('captcha-widget', {
        siteKey: config.dataset.siteKey,
        callback: token => { if (!token) return reset('请重新完成人机验证。'); form.querySelector('[name="captcha_token"]').value = token; verified = true; status.textContent = '验证完成，可以登录。'; },
        expiredCallback: () => reset('验证已过期，请重新验证。'),
        errorCallback: () => reset('验证失败，请重新验证。')
      });
      status.textContent = '请完成人机验证。';
    });
  } else if (config.dataset.provider === 'geetest') {
    loadScript('https://static.geetest.com/v4/gt4.js', () => {
      initGeetest4({captchaId: config.dataset.geetestId, product: 'float', language: 'zho', protocol: 'https://', timeout: 10000, onError: () => reset('验证服务不可用，请刷新重试。'), offlineCb: () => reset('验证服务不可用，请稍后重试。')}, captcha => {
        captcha.appendTo('#captcha-widget');
        captcha.onSuccess(() => {
          const result = captcha.getValidate();
          if (!result) return reset('请重新完成人机验证。');
          for (const name of fields.slice(1)) form.querySelector('[name="'+name+'"]').value = result[name] || '';
          verified = fields.slice(1).every(name => Boolean(result[name]));
          status.textContent = verified ? '验证完成，可以登录。' : '验证结果不完整，请重新验证。';
        });
        captcha.onError(() => reset('验证出错，请刷新页面重试。'));
        captcha.onFail(() => reset('验证未通过，请重新验证。'));
        captcha.onReady(() => { status.textContent = '请完成人机验证。'; });
      });
    });
  }
})();
