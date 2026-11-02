"""Chart colours for telemetry pages, matching the LinkedEye "paper" theme tokens in core app.css.

Chart.js and the donut/sparkline renderers need literal colours (not CSS variables), so they live here.
Status colours keep their meaning everywhere: OK green, WARN amber, CRIT red; UNKNOWN/NODATA are stone.
"""

CORAL = "#ff5b2e"   # --brand
BLUE = "#2b4cff"    # --accent-blue / --info
GREEN = "#0f7a55"   # --ok
AMBER = "#e08a00"   # --warn
RED = "#d92d20"     # --crit
PURPLE = "#7a4fd6"  # --purple
TEAL = "#0e8a7a"
STONE = "#a8a398"   # neutral / unknown
STONE_LIGHT = "#d6cfc1"  # pending / no data
BROWN = "#9a4a06"   # --warn-ink
DOWN = "#7a1f16"    # host down: darker than critical so the two stay distinguishable

OK, WARN, CRIT = GREEN, AMBER, RED

# Multi-series charts (Metrics Explorer). Red comes late so a single series never reads as "critical";
# teal is kept away from green because the two are close.
SERIES = [CORAL, BLUE, GREEN, AMBER, PURPLE, STONE, RED, TEAL, BROWN, "#3d3a35"]
