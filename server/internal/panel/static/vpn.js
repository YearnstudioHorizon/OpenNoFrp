(() => {
  const button = document.getElementById('vpn-download-config');
  const config = document.getElementById('vpn-config');
  if (!button || !config) return;
  button.addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([config.value + '\n'], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'opennofrp-vpn.json';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
