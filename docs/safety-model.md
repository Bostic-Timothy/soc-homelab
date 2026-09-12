# Safety and Publication Model

## Authorization

All activity is restricted to systems owned by the operator and explicitly included in a written scenario scope. No production, third-party, or public target is implicitly authorized.

## Isolation Controls

- Dedicated target zones separated from household and management networks
- Default-deny firewall policy
- Controlled egress
- Disposable targets and known-good snapshots
- Separate administration and operator workstations
- Exercise-specific access rules with a defined cleanup step

## Publishable by Design

Use:

- fictional organizations and identities
- synthetic credentials and documents
- lab-only services
- generated network traffic
- public example configurations with non-deployable values

Never publish:

- secrets, API keys, tokens, or reusable passwords
- VPN keys or operational peer configurations
- externally reachable management endpoints
- real household or organizational data
- proprietary course material
- challenge flags, answer keys, or copied lab instructions

“No sanitization needed” means evidence contains no real client or production data. It does not remove the requirement for a final secret and privacy review.
