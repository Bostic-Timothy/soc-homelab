# Enterprise Security Range

An evolving, isolated purple-team homelab for practicing enterprise penetration testing, detection engineering, and remediation.

> **Status:** Architecture redesign is planned. Existing SOC middleware and diagrams are retained as prior work while the new range is built and validated.

## Goals

1. Demonstrate an end-to-end penetration testing process in a synthetic, authorized environment.
2. Administer the Proxmox-based homelab from a dedicated VM on the operator's current computer without a direct cable to the tower.
3. Practice original exercises aligned to public GPEN objectives while retaining defensive telemetry and remediation evidence.

## Planned Architecture

The tower remains the Proxmox compute host. A firewall controls traffic among six logical zones:

| Zone | Purpose | Planned systems |
| --- | --- | --- |
| Management | Infrastructure administration only | Proxmox, firewall administration, management services |
| Operator | Authorized offensive operations | Dedicated testing workstation |
| Enterprise | Internal assessment targets | Domain controller, Windows workstation, member server |
| DMZ | Internet-style target services | Vulnerable Linux and web applications |
| Telemetry | Detection and investigation | Wazuh and optional supporting sensors |
| Controlled egress | Updates and explicitly permitted outbound access | Firewall and NAT controls |

The administration VM reaches the management plane through WireGuard. The Proxmox interface is not intended to be exposed directly to the Internet. See [Architecture](docs/architecture.md), [Network Boundaries](docs/network-boundaries.md), and [Remote Access](docs/remote-access.md).

## Repository Structure

```text
.
├── docs/
│   ├── architecture.md
│   ├── network-boundaries.md
│   ├── remote-access.md
│   └── safety-model.md
├── infrastructure/
│   ├── provisioning/
│   ├── configuration/
│   └── public-examples/
├── scenarios/
│   ├── 01-mini-engagement/
│   ├── 02-recon-and-scanning/
│   ├── 03-password-assessment/
│   ├── 04-active-directory/
│   └── 05-pivot-and-detect/
├── detections/
├── automation/
├── evidence/
├── diagrams/
├── middleware/
└── weekly-reports/
```

Every planned directory contains a README explaining its purpose and publication boundary.

## Scenario Standard

Each completed scenario should document:

- objective and authorization
- scope and rules of engagement
- environment and starting state
- methodology and timestamped evidence
- validated findings and impact
- detection observations
- remediation and retest results
- cleanup and lessons learned

## Safety and Publication

All testing is limited to systems owned by and isolated for the operator. Fictional identities, synthetic data, and lab-only services make evidence publishable by design. Secrets, reusable credentials, management endpoints, VPN configuration, proprietary course content, challenge flags, and answer keys remain private.

## Existing Work

The repository retains the original SOC-focused material:

- Proxmox and network-segmentation diagrams
- Wazuh-oriented alert-processing design
- Python middleware for sanitizing and enriching alerts
- historical weekly-report structure

These components will be incorporated into the telemetry and automation portions of the redesigned range as they are validated.
