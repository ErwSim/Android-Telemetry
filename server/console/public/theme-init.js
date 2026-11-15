// Appliqué avant le premier rendu pour éviter un flash de thème (script externe : compatible CSP).
try {
  var t = localStorage.getItem('vigie.theme');
  if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
} catch (e) {
  /* stockage indisponible : thème système */
}
