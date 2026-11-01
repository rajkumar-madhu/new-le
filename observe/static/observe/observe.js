/* Exporters, Logs & Events: real-time log panel, live tail and row selection. */
(function () {
  'use strict';
  var POLL_MS = 5000;

  function store(key, value) {
    try { if (value === undefined) return window.localStorage.getItem(key); window.localStorage.setItem(key, value); } catch (e) { return null; }
    return null;
  }
  function cell(tr, text, cls, title) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    td.textContent = text;
    if (title) td.title = title;
    tr.appendChild(td);
    return td;
  }
  function levelChip(td, row) {
    var s = document.createElement('span');
    s.className = 'ex-level ' + row.tone;
    s.textContent = row.level;
    td.appendChild(s);
  }

  // ------------------------------------------------ Logs (Real-time) panel on the exporters page
  document.querySelectorAll('[data-tail]').forEach(function (panel) {
    var body = panel.querySelector('[data-tail-body]'), empty = panel.querySelector('[data-tail-empty]');
    var auto = panel.querySelector('[data-tail-auto]'), pause = panel.querySelector('[data-tail-pause]');
    var source = panel.querySelector('[data-tail-source]'), range = panel.querySelector('[data-tail-range]');
    var status = panel.querySelector('[data-tail-status]');
    var paused = false, timer = null, busy = false;
    if (store('ob-tail-auto') === '0') auto.checked = false;

    function render(rows) {
      body.replaceChildren();
      rows.forEach(function (r) {
        var tr = document.createElement('tr');
        cell(tr, r.time, '', r.date);
        cell(tr, r.source, '', r.source);
        levelChip(cell(tr, ''), r);
        cell(tr, r.message, 'ex-msg', r.message);
        body.appendChild(tr);
      });
      empty.hidden = rows.length > 0;
    }
    function load() {
      if (busy) return;
      busy = true;
      var u = new URL(panel.dataset.feed, location.href);
      u.searchParams.set('limit', '12');
      u.searchParams.set('range', range.value);
      if (source.value) u.searchParams.set('source', source.value);
      fetch(u, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
        .then(function (d) { render(d.rows); status.textContent = 'Updated ' + new Date().toLocaleTimeString(); })
        .catch(function () { status.textContent = 'Could not refresh – retrying'; })
        .finally(function () { busy = false; });
    }
    function schedule() {
      clearInterval(timer);
      timer = null;
      var on = auto.checked && !paused;
      if (on) timer = setInterval(function () { if (!document.hidden) load(); }, POLL_MS);
      status.textContent = paused ? 'Paused' : (auto.checked ? 'Updates every 5 s' : 'Auto refresh off');
    }
    pause.addEventListener('click', function () {
      paused = !paused;
      pause.setAttribute('aria-pressed', paused ? 'true' : 'false');
      pause.title = paused ? 'Resume stream' : 'Pause stream';
      pause.setAttribute('aria-label', pause.title);
      pause.querySelector('[data-ic-pause]').hidden = paused;
      pause.querySelector('[data-ic-play]').hidden = !paused;
      if (!paused) load();
      schedule();
    });
    auto.addEventListener('change', function () { store('ob-tail-auto', auto.checked ? '1' : '0'); if (auto.checked && !paused) load(); schedule(); });
    source.addEventListener('change', load);
    range.addEventListener('change', load);
    schedule();
  });

  // ------------------------------------------------ live tail on the Logs & Events page
  document.querySelectorAll('[data-live]').forEach(function (wrap) {
    var toggle = document.querySelector('[data-live-toggle]');
    var body = wrap.querySelector('tbody'), status = document.querySelector('[data-live-status]');
    var lastId = +wrap.dataset.lastId || 0, timer = null, busy = false, MAX_ROWS = 300;
    if (!toggle) return;
    if (store('ob-live') === '1' && !toggle.disabled) toggle.checked = true;

    function row(r) {
      var tr = document.createElement('tr');
      tr.className = 'ob-new';
      cell(tr, r.date + ' ' + r.time, 'ob-ts', r.ts);
      levelChip(cell(tr, ''), r);
      var src = cell(tr, '');
      var a = document.createElement('a');
      a.href = '?source=' + encodeURIComponent(r.source); a.textContent = r.source; src.appendChild(a);
      cell(tr, r.host || '–', 'ob-host', r.host);
      cell(tr, r.site || '–', 'ob-site', r.site);
      cell(tr, r.message, 'ob-msg', r.message);
      return tr;
    }
    function poll() {
      if (busy || document.hidden) return;
      busy = true;
      var u = new URL(wrap.dataset.feed, location.href);
      new URLSearchParams(wrap.dataset.params || '').forEach(function (v, k) { u.searchParams.set(k, v); });
      u.searchParams.set('after', lastId);
      u.searchParams.set('limit', '100');
      fetch(u, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
        .then(function (d) {
          lastId = Math.max(lastId, d.last_id || 0);
          if (d.rows.length) {
            var placeholder = body.querySelector('tr.ob-empty-row');
            if (placeholder) placeholder.remove();
            for (var i = d.rows.length - 1; i >= 0; i--) body.insertBefore(row(d.rows[i]), body.firstChild);
            while (body.rows.length > MAX_ROWS) body.deleteRow(body.rows.length - 1);
          }
          status.textContent = 'Live · ' + d.rows.length + ' new · ' + new Date().toLocaleTimeString();
        })
        .catch(function () { status.textContent = 'Live tail: could not refresh – retrying'; })
        .finally(function () { busy = false; });
    }
    function apply() {
      clearInterval(timer);
      timer = null;
      if (toggle.checked) { poll(); timer = setInterval(poll, POLL_MS); status.textContent = 'Live tail on'; }
      else status.textContent = '';
    }
    toggle.addEventListener('change', function () { store('ob-live', toggle.checked ? '1' : '0'); apply(); });
    apply();
  });

  // ------------------------------------------------ time range select: "Custom…" reveals from/to inputs
  document.querySelectorAll('[data-range-select]').forEach(function (sel) {
    var custom = sel.form.querySelector('[data-custom]');
    sel.addEventListener('change', function () {
      if (sel.value === 'custom') { if (custom) { custom.hidden = false; var f = custom.querySelector('input'); if (f) f.focus(); } }
      else { if (custom) custom.querySelectorAll('input').forEach(function (i) { i.disabled = true; }); sel.form.submit(); }
    });
  });

  // ------------------------------------------------ select-all checkboxes
  document.querySelectorAll('[data-check-all]').forEach(function (all) {
    var boxes = function () { return document.querySelectorAll('input[name="' + all.dataset.checkAll + '"]'); };
    all.addEventListener('change', function () { boxes().forEach(function (b) { b.checked = all.checked; }); });
    document.addEventListener('change', function (e) {
      if (e.target.name !== all.dataset.checkAll) return;
      var list = Array.prototype.slice.call(boxes());
      all.checked = list.length > 0 && list.every(function (b) { return b.checked; });
      all.indeterminate = !all.checked && list.some(function (b) { return b.checked; });
    });
  });
})();
