"""Create clearly-marked example devices for demos (`manage.py seed_network`).

Addresses come from the documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so the examples never point at a real host; the reachability probe refuses
them unless those ranges are allowed, and they stay "Unknown". Idempotent: re-running updates
the same records. `--remove` deletes them again. No metrics or check history is invented."""
from django.conf import settings
from django.core.management.base import BaseCommand

from network.models import Device

NOTE = "Example record created by manage.py seed_network – documentation IP range, not a real device."

EXAMPLES = [
    dict(name="FG-01", device_type="firewall", vendor="Fortinet", model="FortiGate 100F", serial="EXAMPLE-FG100F-0001",
         firmware="FortiOS 7.4.3", mgmt_ip="192.0.2.254", check_port=443, site="Mumbai (NSE)", role="Perimeter Firewall",
         environment="prod", contact="network@example.com", prometheus_instance="192.0.2.254",
         tags="example, perimeter"),
    dict(name="FG-02", device_type="firewall", vendor="Fortinet", model="FortiGate 60F", serial="EXAMPLE-FG60F-0002",
         firmware="FortiOS 7.2.8", mgmt_ip="192.0.2.253", check_port=443, site="DR Site", role="DR Firewall",
         environment="dr", contact="network@example.com", tags="example"),
    dict(name="core-sw-01", device_type="switch", vendor="Cisco", model="Catalyst 9500-48Y4C", serial="EXAMPLE-C9500-0001",
         firmware="IOS-XE 17.9.4", mgmt_ip="192.0.2.10", site="Mumbai (NSE)", role="Core Switch", environment="prod",
         contact="network@example.com", prometheus_instance="192.0.2.10", tags="example, core"),
    dict(name="acc-sw-12", device_type="switch", vendor="Aruba", model="CX 6300M", serial="EXAMPLE-CX6300-0012",
         firmware="ArubaOS-CX 10.13", mgmt_ip="192.0.2.12", site="Mumbai (NSE)", role="Access Switch", environment="prod",
         tags="example, access"),
    dict(name="edge-rtr-01", device_type="router", vendor="Juniper", model="MX204", serial="EXAMPLE-MX204-0001",
         firmware="Junos 22.4R3", mgmt_ip="198.51.100.1", site="Mumbai (NSE)", role="Internet Edge Router", environment="prod",
         contact="network@example.com", tags="example, edge"),
    dict(name="wan-rtr-dr", device_type="router", vendor="Cisco", model="ISR 4451", serial="EXAMPLE-ISR4451-0001",
         firmware="IOS-XE 17.6.5", mgmt_ip="198.51.100.2", site="DR Site", role="WAN Router", environment="dr", tags="example"),
    dict(name="lb-01", device_type="load_balancer", vendor="F5", model="BIG-IP i5800", serial="EXAMPLE-F5-0001",
         firmware="TMOS 17.1.1", mgmt_ip="198.51.100.20", check_port=443, site="Mumbai (NSE)", role="Application Delivery",
         environment="prod", tags="example"),
    dict(name="wlc-01", device_type="wireless", vendor="Cisco", model="Catalyst 9800-40", serial="EXAMPLE-C9800-0001",
         firmware="IOS-XE 17.9.4", mgmt_ip="198.51.100.30", check_port=443, site="Mumbai (NSE)", role="Wireless Controller",
         environment="prod", tags="example, wifi"),
    dict(name="esx-host-01", device_type="physical_server", vendor="Dell", model="PowerEdge R750", serial="EXAMPLE-R750-0001",
         firmware="ESXi 8.0 U2", mgmt_ip="203.0.113.11", check_port=443, site="Mumbai (NSE)", role="Hypervisor Host",
         environment="prod", tags="example, vmware"),
    dict(name="oms-app-vm-01", device_type="virtual_machine", vendor="VMware", model="Virtual Machine", serial="",
         firmware="RHEL 9.3", mgmt_ip="203.0.113.21", site="Mumbai (NSE)", role="OMS application server", environment="prod",
         tags="example"),
]


class Command(BaseCommand):
    help = "Create (or remove with --remove) clearly-marked example network devices on documentation IP ranges."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true", help="Delete the example devices instead.")

    def handle(self, *args, remove=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        names = [e["name"] for e in EXAMPLES]
        if remove:
            qs = Device.objects.filter(tenant_key=tenant, name__in=names, tags__icontains="example")
            n = qs.count()
            qs.delete()
            self.stdout.write(self.style.SUCCESS(f"Removed {n} example device(s)."))
            return
        created = updated = 0
        for e in EXAMPLES:
            fields = dict(e, description=NOTE)
            existing = Device.objects.filter(tenant_key=tenant, name=e["name"]).first()
            if existing is not None and "example" not in existing.tags.lower():
                self.stdout.write(self.style.WARNING(f"Skipped {e['name']}: a real device with that name exists."))
                continue
            _obj, was_created = Device.objects.update_or_create(tenant_key=tenant, name=e["name"], defaults=fields)
            created += was_created
            updated += not was_created
        self.stdout.write(self.style.SUCCESS(f"Example devices: {created} created, {updated} updated (tagged 'example')."))
