"""Sidebar navigation (order follows the LinkedEye design). `url` is a URL name;
an item whose URL name does not resolve yet opens the "not built yet" page."""

NAV = [
    {"label": "Dashboard", "icon": "home", "url": "dashboard"},
    {"label": "Service Desk", "icon": "headset", "children": [
        {"label": "Tickets", "url": "servicedesk:tickets"},
        {"label": "Incidents", "url": "servicedesk:incidents"},
        {"label": "Problems", "url": "servicedesk:problems"},
        {"label": "Changes", "url": "servicedesk:changes"},
        {"label": "Service Catalog", "url": "servicedesk:catalog"},
        {"label": "SLA Policies", "url": "servicedesk:sla"},
    ]},
    {"label": "Assets", "icon": "box", "children": [
        {"label": "IT Assets", "url": "cmdb:assets"}, {"label": "Software", "url": "cmdb:software"},
        {"label": "Licenses", "url": "cmdb:licenses"}, {"label": "Lifecycle", "url": "cmdb:lifecycle"},
    ]},
    {"label": "CMDB", "icon": "database", "children": [
        {"label": "Topology", "url": "cmdb:topology"}, {"label": "Configuration Items", "url": "cmdb:items"},
        {"label": "Relationships", "url": "cmdb:relationships"},
    ]},
    {"label": "Monitoring", "icon": "gauge", "children": [
        {"label": "Heatmap", "url": "cmdb:heatmap"},
        {"label": "Infrastructure", "url": "telemetry:infrastructure"},
        {"label": "Nagios Status", "url": "telemetry:nagios"},
        {"label": "Prometheus Metrics", "url": "telemetry:prometheus"},
        {"label": "Alert Manager", "url": "telemetry:alertmanager"},
        {"label": "Telnet Monitoring", "url": "tcpcheck:index"},
        {"label": "Uptime Checks", "url": "tcpcheck:uptime"},
        {"label": "Metrics Explorer", "url": "telemetry:explorer"},
    ]},
    {"label": "Network Devices", "icon": "network", "children": [
        {"label": "Switches", "url": "network:switches"}, {"label": "Routers", "url": "network:routers"},
        {"label": "Firewalls", "url": "network:firewalls"}, {"label": "Load Balancers", "url": "network:load_balancers"},
        {"label": "Wireless", "url": "network:wireless"}, {"label": "Physical Servers", "url": "network:physical_servers"},
        {"label": "Virtual Machines", "url": "network:virtual_machines"}, {"label": "All Devices", "url": "network:all"},
        {"label": "Discovery", "url": "network:discovery"},
    ]},
    {"label": "Domains", "icon": "browser", "children": [
        {"label": "Overview", "url": "domains:overview"},
        {"label": "Domain List", "url": "domains:list"},
        {"label": "DNS Records", "url": "domains:dns"},
        {"label": "SSL Certificates", "url": "domains:ssl"},
        {"label": "Uptime Monitoring", "url": "domains:uptime"},
        {"label": "Performance", "url": "domains:performance"},
        {"label": "Security", "url": "domains:security"},
        {"label": "Export Reports", "url": "domains:export_reports"},
    ]},
    {"label": "URL Checker", "icon": "link", "url": "urlchecker:index", "chev": True},
    {"label": "Templates", "icon": "template", "url": "automation:templates", "chev": True},
    {"label": "All Exporters", "icon": "exporters", "url": "observe:exporters", "chev": True},
    {"label": "Logs & Events", "icon": "logs", "url": "observe:logs", "chev": True},
    {"label": "BOD / EOD", "icon": "calendar", "children": [
        {"label": "Status Dashboard", "url": "bodeod:status"}, {"label": "Key Validation", "url": "bodeod:keys"},
        {"label": "Execution History", "url": "bodeod:history"},
        {"label": "Checklist", "url": "bodeod:checklist"}, {"label": "Holidays", "url": "bodeod:holidays"},
    ]},
    {"label": "Automation", "icon": "bot", "children": [
        {"label": "Runbooks", "url": "automation:runbooks"}, {"label": "StackStorm", "url": "automation:stackstorm"},
        {"label": "Workflows", "url": "automation:workflows"},
    ]},
    {"label": "Analytics", "icon": "analytics", "url": "reports:analytics", "chev": True},
    {"label": "Reports", "icon": "clipboard", "url": "reports:index", "chev": True},
    {"label": "Administration", "icon": "settings", "url": "administration:index", "chev": True},
]
