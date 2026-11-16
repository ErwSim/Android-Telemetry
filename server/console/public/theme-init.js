// Applied before the first render to avoid a theme flash (external script: CSP-compatible).
try {
  var t = localStorage.getItem('watchpost.theme');
  if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
} catch {
  /* storage unavailable: system theme */
}
