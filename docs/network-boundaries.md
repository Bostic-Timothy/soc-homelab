# Planned Network Boundaries

## Zones

| Zone | Trust level | Permitted purpose |
| --- | --- | --- |
| Management | Highest | Proxmox, firewall, recovery, and configuration |
| Operator | Controlled | Authorized assessment traffic toward scoped targets |
| Enterprise | Untrusted target | Fictional internal organization |
| DMZ | Untrusted target | Internet-style services and web applications |
| Telemetry | Restricted | Collection, detection, investigation, and reporting |
| Egress | Restricted | Updates and scenario-approved outbound traffic |

## Baseline Policy

1. Deny traffic by default between zones.
2. Permit the administration VM to reach only approved management services through the VPN.
3. Permit the operator zone to reach only targets listed in the active scenario scope.
4. Prevent Enterprise and DMZ targets from initiating traffic toward household or management networks.
5. Permit telemetry flows from targets to named collectors.
6. Log firewall decisions relevant to an exercise.
7. Disable temporary scenario rules during cleanup.

Actual VLAN identifiers, addresses, firewall objects, and device names are private deployment data. Public examples belong in `infrastructure/public-examples/` and must use fictional values.
