/* Administration console: password mode toggle and copy-to-clipboard. */
(function () {
  'use strict';
  document.querySelectorAll('[data-pw-group]').forEach(function (group) {
    var scope = group.closest('form') || document;
    var sync = function () {
      var chosen = group.querySelector('input[type=radio]:checked');
      var show = chosen && chosen.value === 'set';
      scope.querySelectorAll('[data-pw-set]').forEach(function (el) {
        el.hidden = !show;
        el.querySelectorAll('input').forEach(function (i) { i.disabled = !show; });
      });
    };
    group.addEventListener('change', sync);
    sync();
  });

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.dataset.copy);
    if (!el) return;
    var text = el.textContent.trim();
    var done = function () { var old = b.innerHTML; b.textContent = 'Copied'; setTimeout(function () { b.innerHTML = old; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { window.getSelection().selectAllChildren(el); });
    } else {
      window.getSelection().selectAllChildren(el);
      try { document.execCommand('copy'); done(); } catch (err) { /* text stays selected for manual copy */ }
    }
  });
})();
