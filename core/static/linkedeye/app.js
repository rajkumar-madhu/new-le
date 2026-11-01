/* LinkedEye console behaviour: async "run now" buttons, confirm dialogs, auto-refresh. */
(function () {
  'use strict';
  const csrf = () => (document.cookie.match(/csrftoken=([^;]+)/) || [])[1] || (document.querySelector('[name=csrfmiddlewaretoken]') || {}).value;

  // <button data-post="/url" data-reload> : POST via fetch, then reload (or show JSON result in data-target)
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-post]');
    if (!b) return;
    e.preventDefault();
    if (b.dataset.confirm && !window.confirm(b.dataset.confirm)) return;
    const label = b.innerHTML;
    b.disabled = true;
    if (b.dataset.busy) b.textContent = b.dataset.busy;
    try {
      const r = await fetch(b.dataset.post, { method: 'POST', headers: { 'X-CSRFToken': csrf(), 'Accept': 'application/json' }, credentials: 'same-origin' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || r.statusText);
      const out = b.dataset.target && document.getElementById(b.dataset.target);
      if (out) { out.hidden = false; out.textContent = d.summary || JSON.stringify(d, null, 2); b.disabled = false; b.innerHTML = label; }
      else location.reload();
    } catch (err) {
      b.disabled = false; b.innerHTML = label;
      const out = b.dataset.target && document.getElementById(b.dataset.target);
      if (out) { out.hidden = false; out.textContent = 'Failed: ' + err.message; } else window.alert('Failed: ' + err.message);
    }
  });

  // <form data-confirm="..."> asks before submitting
  document.addEventListener('submit', e => {
    const f = e.target;
    if (f.dataset.confirm && !window.confirm(f.dataset.confirm)) e.preventDefault();
  });

  // filters that submit on change
  document.querySelectorAll('[data-autosubmit]').forEach(s => s.addEventListener('change', () => s.form.submit()));

  // hamburger: collapse the sidebar on desktop, slide it in on phones
  document.addEventListener('click', e => {
    if (!e.target.closest('[data-toggle-menu]')) return;
    if (window.innerWidth > 860) document.getElementById('shell').classList.toggle('collapsed');
    else document.getElementById('side').classList.toggle('open');
  });

  // per-page selector in pagers keeps the other query parameters
  document.querySelectorAll('[data-per-page]').forEach(s => s.addEventListener('change', () => {
    const u = new URL(location.href); u.searchParams.set('per', s.value); u.searchParams.delete('page'); location.href = u;
  }));

  // optional auto refresh: <body data-refresh="60">
  const page = document.querySelector('[data-refresh]');
  if (page) setTimeout(() => { if (!document.hidden) location.reload(); }, +page.dataset.refresh * 1000);
})();
