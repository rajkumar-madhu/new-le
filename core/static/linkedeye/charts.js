/* LinkedEye charts: dependency-free SVG charts.
 * Markup: <div class="chart" data-chart="line|bars|donut|spark" data-src="json-script-id" style="height:200px"></div>
 * Data comes from a {{ value|json_script:"id" }} block. null values are gaps (never drawn as zero).
 * Options: labels, series[{name,color,values,area,areaOpacity,width,dash,endDot}], unit, yMin, yMax, yTicks,
 *   tipLabels, xLabelEvery, stacked (bars), thickness/center (donut).
 */
(function () {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const AXIS = '#b3ab9c', GRID = '#ebe5d9', TEXT = '#6f6a61';

  function el(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function fmt(v, unit) {
    if (v === null || v === undefined || isNaN(v)) return '–';
    const a = Math.abs(v);
    let s = a >= 1e6 ? (v / 1e6).toFixed(1) + 'M' : a >= 1e4 ? (v / 1e3).toFixed(0) + 'K' : a >= 100 ? Math.round(v).toLocaleString() : a >= 10 ? v.toFixed(1) : v.toFixed(2);
    s = s.replace(/\.0+(?=[A-Z]|$)/, '');
    return unit ? s + (unit === '%' ? '%' : ' ' + unit) : s;
  }
  function niceMax(v) {
    if (v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }
  function tipFor(host) {
    let t = host.querySelector('.tip');
    if (!t) { t = document.createElement('div'); t.className = 'tip'; t.hidden = true; host.appendChild(t); }
    return t;
  }

  // ------------------------------------------------------------ axes chart (line / bars)
  function axesChart(host, d, kind) {
    const W = host.clientWidth, H = host.clientHeight || 200;
    const m = { l: 52, r: 10, t: 10, b: 26 };
    const pw = W - m.l - m.r, ph = H - m.t - m.b;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img', 'aria-label': d.title || 'chart' });
    const n = d.labels.length;
    let lo = d.yMin !== undefined ? d.yMin : 0, hi;
    if (kind === 'bars' && d.stacked !== false) {
      hi = Math.max(0, ...d.labels.map((_, i) => d.series.reduce((s, x) => s + (x.values[i] || 0), 0)));
    } else {
      hi = Math.max(...d.series.flatMap(s => s.values.filter(v => v !== null)), lo + 1e-9);
    }
    hi = d.yMax !== undefined ? d.yMax : niceMax(hi);
    if (d.yMin === undefined && lo === 0 && hi === 0) hi = 1;
    const Y = v => m.t + ph - ((v - lo) / (hi - lo)) * ph;
    const step = pw / Math.max(1, kind === 'bars' ? n : n - 1);
    const X = i => kind === 'bars' ? m.l + step * i + step / 2 : m.l + step * i;

    const ticks = d.yTicks || 4;
    for (let i = 0; i <= ticks; i++) {
      const v = lo + ((hi - lo) * i) / ticks, y = Y(v);
      el('line', { x1: m.l, x2: W - m.r, y1: y, y2: y, stroke: GRID }, svg);
      el('text', { x: m.l - 8, y: y + 4, 'text-anchor': 'end', 'font-size': 11, fill: TEXT }, svg).textContent = fmt(v, d.unit);
    }
    const every = d.xLabelEvery || Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 70))));
    d.labels.forEach((lab, i) => {
      if (i % every) return;
      el('text', { x: X(i), y: H - 8, 'text-anchor': 'middle', 'font-size': 11, fill: TEXT }, svg).textContent = lab;
    });

    if (kind === 'line') {
      d.series.forEach(s => {
        let path = '', area = '', open = false, first = null, lastX = null;
        s.values.forEach((v, i) => {
          if (v === null || v === undefined) {
            if (open && s.area) area += `L${lastX},${Y(lo)}L${first},${Y(lo)}Z`;
            open = false; return;
          }
          const x = X(i), y = Y(v);
          if (!open) { path += `M${x},${y}`; area += `M${x},${y}`; first = x; open = true; } else { path += `L${x},${y}`; area += `L${x},${y}`; }
          lastX = x;
        });
        if (open && s.area) area += `L${lastX},${Y(lo)}L${first},${Y(lo)}Z`;
        if (s.area) el('path', { d: area, fill: s.color, 'fill-opacity': s.areaOpacity || 0.14, stroke: 'none' }, svg);
        // a point with no neighbours would be invisible as a path: draw it as a dot
        s.values.forEach((v, i) => {
          const prev = s.values[i - 1], next = s.values[i + 1];
          if (v !== null && v !== undefined && (prev === null || prev === undefined) && (next === null || next === undefined))
            el('circle', { cx: X(i), cy: Y(v), r: 3, fill: s.color }, svg);
        });
        el('path', { d: path, fill: 'none', stroke: s.color, 'stroke-width': s.width || 1.8, 'stroke-linejoin': 'round', 'stroke-dasharray': s.dash || 'none' }, svg);
        if (s.endDot) { let li = s.values.length - 1; while (li >= 0 && (s.values[li] === null || s.values[li] === undefined)) li--; if (li >= 0) el('circle', { cx: X(li), cy: Y(s.values[li]), r: 3.5, fill: s.color, stroke: '#fff', 'stroke-width': 1.5 }, svg); }
      });
    } else {
      const bw = Math.max(3, Math.min(46, step * 0.7));
      d.labels.forEach((_, i) => {
        let base = lo;
        d.series.forEach((s, si) => {
          const v = s.values[i];
          if (!v) return;
          if (d.stacked === false) {
            const w = bw / d.series.length;
            el('rect', { x: X(i) - bw / 2 + w * si, y: Y(v), width: w - 1, height: Y(lo) - Y(v), fill: s.color, rx: 1.5 }, svg);
          } else {
            el('rect', { x: X(i) - bw / 2, y: Y(base + v), width: bw, height: Math.max(0, Y(base) - Y(base + v)), fill: s.color }, svg);
            base += v;
          }
        });
      });
    }
    const cross = el('line', { y1: m.t, y2: m.t + ph, stroke: AXIS, 'stroke-dasharray': '3 3', visibility: 'hidden' }, svg);
    host.replaceChildren(svg);
    const tip = tipFor(host);
    svg.addEventListener('mousemove', e => {
      const r = svg.getBoundingClientRect();
      const x = (e.clientX - r.left) * (W / r.width);
      const i = Math.max(0, Math.min(n - 1, Math.round(kind === 'bars' ? (x - m.l - step / 2) / step : (x - m.l) / step)));
      cross.setAttribute('x1', X(i)); cross.setAttribute('x2', X(i)); cross.setAttribute('visibility', 'visible');
      tip.innerHTML = `<b>${(d.tipLabels || d.labels)[i]}</b><br>` + d.series.map(s => `<span style="color:${s.color}">●</span> ${s.name}: ${fmt(s.values[i], d.unit)}`).join('<br>');
      tip.style.left = (X(i) / W) * r.width + 'px'; tip.style.top = '24px'; tip.hidden = false;
    });
    svg.addEventListener('mouseleave', () => { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); });
  }

  // ------------------------------------------------------------ donut
  function donut(host, d) {
    const S = host.clientWidth || 170, r = S / 2, w = d.thickness || S * 0.13, R = r - w / 2 - 1;
    const svg = el('svg', { viewBox: `0 0 ${S} ${S}`, height: S, role: 'img', 'aria-label': d.title || 'donut chart' });
    const total = d.segments.reduce((s, x) => s + x.value, 0);
    el('circle', { cx: r, cy: r, r: R, fill: 'none', stroke: '#ebe5d9', 'stroke-width': w }, svg);
    let a0 = -Math.PI / 2;
    if (total > 0) d.segments.forEach(seg => {
      if (!seg.value) return;
      const frac = seg.value / total;
      if (frac >= 0.9999) { el('circle', { cx: r, cy: r, r: R, fill: 'none', stroke: seg.color, 'stroke-width': w }, svg); return; }
      const a1 = a0 + frac * Math.PI * 2;
      const p = (a) => `${r + R * Math.cos(a)},${r + R * Math.sin(a)}`;
      el('path', { d: `M${p(a0)}A${R},${R} 0 ${frac > 0.5 ? 1 : 0} 1 ${p(a1)}`, fill: 'none', stroke: seg.color, 'stroke-width': w }, svg)
        .appendChild(el('title', {})).textContent = `${seg.label}: ${seg.value}`;
      a0 = a1;
    });
    if (d.center) {
      el('text', { x: r, y: r + (d.center.label ? 2 : 8), 'text-anchor': 'middle', 'font-size': S * 0.17, 'font-weight': 600, 'font-family': 'Fraunces, Georgia, serif', fill: '#0e1116' }, svg).textContent = d.center.value;
      if (d.center.label) el('text', { x: r, y: r + S * 0.13, 'text-anchor': 'middle', 'font-size': S * 0.075, 'font-weight': 600, fill: '#3d3a35' }, svg).textContent = d.center.label;
    }
    host.replaceChildren(svg);
  }

  // ------------------------------------------------------------ sparkline
  function spark(host, d) {
    const W = host.clientWidth, H = host.clientHeight || 32;
    const vals = d.values.filter(v => v !== null);
    const lo = Math.min(...vals), hi = Math.max(...vals) || 1;
    const X = i => (i / (d.values.length - 1)) * (W - 2) + 1, Y = v => H - 2 - ((v - lo) / (hi - lo || 1)) * (H - 4);
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, height: H, 'aria-hidden': 'true' });
    el('path', { d: d.values.map((v, i) => (i ? 'L' : 'M') + X(i) + ',' + Y(v)).join(''), fill: 'none', stroke: d.color || '#0f7a55', 'stroke-width': 1.6 }, svg);
    host.replaceChildren(svg);
  }

  const KINDS = { line: (h, d) => axesChart(h, d, 'line'), bars: (h, d) => axesChart(h, d, 'bars'), donut, spark };

  function render(host) {
    const src = document.getElementById(host.dataset.src);
    if (!src) return;
    const kind = KINDS[host.dataset.chart];
    if (kind) kind(host, JSON.parse(src.textContent));
  }
  function init() {
    const hosts = document.querySelectorAll('.chart[data-chart]');
    hosts.forEach(render);
    if ('ResizeObserver' in window) {
      const ro = new ResizeObserver(entries => entries.forEach(e => render(e.target)));
      hosts.forEach(h => ro.observe(h));
    }
  }
  window.LinkedEyeCharts = { render, init, fmt };
  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();
})();
