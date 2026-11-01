"""Server-side layered layout of the CMDB graph, rendered as SVG by the topology template.

Nodes are placed in horizontal layers by CI type (business domains on top, physical kit at the bottom),
ordered inside each layer with a few barycenter sweeps to reduce edge crossings. Wide layers wrap into
several rows so the drawing stays readable.
"""
from collections import defaultdict, deque

from core.templatetags.le import ICONS

from . import services
from .models import IMPACT_FORWARD, IMPACT_REVERSE, CIType, RelType

LAYER_OF = {
    CIType.BUSINESS_DOMAIN: 0,
    CIType.SERVICE: 1,
    CIType.APPLICATION: 2,
    CIType.MIDDLEWARE: 3, CIType.DATABASE: 3, CIType.OTHER: 3,
    CIType.KUBERNETES_CLUSTER: 4,
    CIType.VIRTUAL_MACHINE: 5,
    CIType.SERVER: 6, CIType.STORAGE: 6,
    CIType.NETWORK_DEVICE: 7,
}
LAYER_LABELS = ["Business domains", "Services", "Applications", "Middleware & databases", "Platforms",
                "Virtual machines", "Servers & storage", "Network"]

NODE_W, NODE_H = 168, 46
GAP_X, GAP_Y, ROW_GAP = 22, 84, 26
PAD_X, PAD_TOP, PAD_BOTTOM = 150, 24, 24
MAX_PER_ROW = 9
MAX_NODES = 250


def _label(text, limit=21):
    return text if len(text) <= limit else text[: limit - 1] + "…"


def neighbourhood(root, edges, max_nodes=MAX_NODES):
    """Root plus everything it depends on and everything that depends on it (all relationship types)."""
    up, down = services.impact_adjacency(edges), services.dependency_adjacency(edges)
    other = defaultdict(set)
    for _pk, s, t, rt in edges:
        if rt not in IMPACT_REVERSE and rt not in IMPACT_FORWARD:   # connects_to: one hop either side
            other[s].add(t)
            other[t].add(s)
    keep = {root}
    for adj in (lambda n: [x for x, _r, _d in up.get(n, ())], lambda n: [x for x, _r in down.get(n, ())]):
        q = deque([root])
        seen = {root}
        while q and len(keep) < max_nodes:
            cur = q.popleft()
            for nxt in adj(cur):
                if nxt not in seen:
                    seen.add(nxt)
                    keep.add(nxt)
                    q.append(nxt)
    keep |= other.get(root, set())
    return keep


def domain_scope(name, cis, edges):
    """A business domain, its member CIs and everything those members rely on."""
    dom_ci, members = services.domain_members(name, cis=cis, edges=edges)
    keep = {m.pk for m in members}
    if dom_ci is not None:
        keep.add(dom_ci.pk)
    down = services.dependency_adjacency(edges)
    q = deque(keep)
    while q and len(keep) < MAX_NODES:
        cur = q.popleft()
        for nxt, _rt in down.get(cur, ()):
            if nxt not in keep:
                keep.add(nxt)
                q.append(nxt)
    return keep


def layout(cis, edges, health=None, root_id=None):
    """Positions for `cis` (list of ConfigurationItem) and the `edges` between them."""
    health = health or {}
    ids = {c.pk for c in cis}
    edges = [e for e in edges if e[1] in ids and e[2] in ids and e[1] != e[2]]
    by_layer = defaultdict(list)
    for c in cis:
        by_layer[LAYER_OF.get(c.ci_type, 3)].append(c)
    layer_keys = sorted(by_layer)

    nbrs = defaultdict(set)
    for _pk, s, t, _rt in edges:
        nbrs[s].add(t)
        nbrs[t].add(s)

    # initial order: name; then barycenter sweeps down and up
    order = {k: sorted(by_layer[k], key=lambda c: c.name.lower()) for k in layer_keys}
    pos = {}

    def index_positions():
        for k in layer_keys:
            for i, c in enumerate(order[k]):
                pos[c.pk] = i / max(1, len(order[k]) - 1) if len(order[k]) > 1 else 0.5

    index_positions()
    for sweep in range(6):
        keys = layer_keys if sweep % 2 == 0 else list(reversed(layer_keys))
        for k in keys:
            same = {x.pk for x in order[k]}

            def bary(c, same=same):
                ns = [pos[n] for n in nbrs.get(c.pk, ()) if n in pos and n not in same]
                return sum(ns) / len(ns) if ns else pos[c.pk]
            order[k] = sorted(order[k], key=lambda c: (bary(c), c.name.lower()))
            index_positions()

    # rows (wrap wide layers)
    rows = []
    for k in layer_keys:
        items = order[k]
        for start in range(0, len(items), MAX_PER_ROW):
            rows.append((k, start == 0, items[start:start + MAX_PER_ROW]))
    widest = max((len(r[2]) for r in rows), default=1)
    inner_w = widest * NODE_W + (widest - 1) * GAP_X
    width = PAD_X + inner_w + 24
    nodes, coords, layers = [], {}, []
    y = PAD_TOP
    prev_layer = None
    for k, first, items in rows:
        if prev_layer is not None:
            y += (GAP_Y if k != prev_layer else ROW_GAP)
        row_w = len(items) * NODE_W + (len(items) - 1) * GAP_X
        x0 = PAD_X + (inner_w - row_w) / 2
        if first:
            layers.append({"label": LAYER_LABELS[k], "y": y + NODE_H / 2 + 4})
        for i, c in enumerate(items):
            x = x0 + i * (NODE_W + GAP_X)
            coords[c.pk] = (x, y)
            state = health.get(c.pk, "unknown")
            nodes.append({
                "ci": c, "x": round(x, 1), "y": round(y, 1), "w": NODE_W, "h": NODE_H,
                "label": _label(c.name), "sub": c.get_ci_type_display() + ("" if c.status == "active" else f" · {c.get_status_display()}"),
                "state": state, "cls": services.STATE_CLASS.get(state, "unk"), "icon": ICONS.get(c.icon, ICONS["box"]),
                "root": c.pk == root_id, "retired": c.status == "retired",
            })
        y += NODE_H
        prev_layer = k
    height = y + PAD_BOTTOM

    labels = dict(RelType.choices)
    names = {c.pk: c.name for c in cis}
    out_edges = []
    for pk, s, t, rt in edges:
        (sx, sy), (tx, ty) = coords[s], coords[t]
        if abs(sy - ty) < 1:   # same row: arc above
            x1, x2 = sx + NODE_W / 2, tx + NODE_W / 2
            y1 = sy
            lift = 28 + min(60, abs(x2 - x1) / 6)
            path = f"M{x1:.1f},{y1:.1f} C{x1:.1f},{y1 - lift:.1f} {x2:.1f},{y1 - lift:.1f} {x2:.1f},{y1:.1f}"
            lx, ly = (x1 + x2) / 2, y1 - lift * 0.75
        else:
            x1 = sx + NODE_W / 2
            x2 = tx + NODE_W / 2
            if sy < ty:
                y1, y2 = sy + NODE_H, ty
            else:
                y1, y2 = sy, ty + NODE_H
            dy = (y2 - y1) / 2
            path = f"M{x1:.1f},{y1:.1f} C{x1:.1f},{y1 + dy:.1f} {x2:.1f},{y2 - dy:.1f} {x2:.1f},{y2:.1f}"
            lx, ly = (x1 + x2) / 2, (y1 + y2) / 2
        out_edges.append({"pk": pk, "path": path, "rel": rt, "label": labels.get(rt, rt), "lx": round(lx, 1), "ly": round(ly, 1),
                          "title": f"{names[s]} {labels.get(rt, rt).lower()} {names[t]}",
                          "hot": root_id in (s, t)})
    return {"nodes": nodes, "edges": out_edges, "layers": layers, "width": round(width), "height": round(height)}

