/* BOD / EOD pages: busy state for synchronous runs/uploads and a cancellable auto refresh. */
(function () {
  'use strict';
  var hold = false;
  document.addEventListener('submit', function (e) {
    var f = e.target.closest('[data-busy-form]');
    if (!f || e.defaultPrevented) return;
    hold = true; // never reload while a run is being submitted
    var b = f.querySelector('button[type=submit][data-busy]');
    if (b) setTimeout(function () { b.disabled = true; b.textContent = b.dataset.busy; }, 0);
  });
  // pause the refresh while someone types a note or changes an option
  document.addEventListener('input', function (e) { if (e.target.closest('form')) hold = true; });
  var host = document.querySelector('[data-bod-refresh]');
  if (host) {
    var secs = Math.max(10, +host.dataset.bodRefresh || 60);
    setInterval(function () { if (!hold && !document.hidden) location.reload(); }, secs * 1000);
  }
})();
