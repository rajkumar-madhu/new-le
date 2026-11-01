/* Service desk chart polish (same look as the design): smooth line curves with gradient areas and point
 * markers, thin separators between donut segments. Works on the SVG that charts.js renders. */
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  function mk(tag, attrs, parent, before) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.insertBefore(e, before || null);
    return e;
  }
  function pts(d) { return (d.match(/-?[\d.]+,-?[\d.]+/g) || []).map(function (p) { return p.split(',').map(Number); }); }
  function curve(p) {
    var s = 'M' + p[0][0] + ',' + p[0][1];
    for (var i = 0; i < p.length - 1; i++) {
      var p0 = p[i - 1] || p[i], p1 = p[i], p2 = p[i + 1], p3 = p[i + 2] || p2, t = 0.18;
      var c1y = p1[1] + (p2[1] - p0[1]) * t, c2y = p2[1] - (p3[1] - p1[1]) * t;
      var lo = Math.max(p1[1], p2[1]);   // never overshoot below the lower point (no dips under zero)
      s += 'C' + (p1[0] + (p2[0] - p0[0]) * t) + ',' + Math.min(c1y, lo) + ' ' +
           (p2[0] - (p3[0] - p1[0]) * t) + ',' + Math.min(c2y, lo) + ' ' + p2[0] + ',' + p2[1];
    }
    return s;
  }
  function polishLine(svg) {
    var defs = mk('defs', {}, svg, svg.firstChild), n = 0;
    svg.querySelectorAll('path').forEach(function (path) {
      var d = path.getAttribute('d') || '';
      if (/Z/.test(d) && path.getAttribute('fill') !== 'none') {
        var p = pts(d); if (p.length < 4) return;
        var top = p.slice(0, -2), base = p.slice(-2), color = path.getAttribute('fill'), id = 'sdg' + Math.random().toString(36).slice(2, 7) + (n++);
        var g = mk('linearGradient', { id: id, x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
        mk('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': 0.32 }, g);
        mk('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0.03 }, g);
        path.setAttribute('d', curve(top) + 'L' + base[0] + 'L' + base[1] + 'Z');
        path.setAttribute('fill', 'url(#' + id + ')'); path.removeAttribute('fill-opacity');
      } else if (path.getAttribute('fill') === 'none' && path.getAttribute('stroke')) {
        var q = pts(d); if (q.length < 2) return;
        path.setAttribute('d', curve(q));
        if (q.length <= 31) q.forEach(function (c) { mk('circle', { cx: c[0], cy: c[1], r: 3.2, fill: path.getAttribute('stroke'), stroke: '#fff', 'stroke-width': 1.4 }, svg, path.nextSibling); });
      }
    });
  }
  function polishDonut(svg) {
    var vb = svg.viewBox.baseVal, c = vb.width / 2;
    var segs = svg.querySelectorAll('path');
    if (segs.length < 2) return;
    segs.forEach(function (path) {
      var p = pts(path.getAttribute('d') || ''); if (!p.length) return;
      var w = +path.getAttribute('stroke-width'), dx = p[0][0] - c, dy = p[0][1] - c, R = Math.hypot(dx, dy), ux = dx / R, uy = dy / R;
      var r0 = R - w / 2 - 1, r1 = R + w / 2 + 1;
      mk('line', { x1: c + ux * r0, y1: c + uy * r0, x2: c + ux * r1, y2: c + uy * r1, stroke: '#fff', 'stroke-width': 2.5 }, svg);
    });
  }
  function polish(host) {
    var svg = host.querySelector(':scope > svg');
    if (!svg || svg.dataset.polished) return;
    svg.dataset.polished = '1';
    if (host.dataset.smooth) polishLine(svg);
    if (host.dataset.gap) polishDonut(svg);
  }
  document.querySelectorAll('.pg-sd .chart[data-smooth], .pg-sd .chart[data-gap]').forEach(function (host) {
    polish(host);
    new MutationObserver(function () { polish(host); }).observe(host, { childList: true });
  });
})();
