# Planned Remote Access

## Objective

Administer the Proxmox-based range from a dedicated VM on the current computer without directly cabling that computer to the tower.

## Design

- Create a dedicated administration VM on the current computer.
- Connect that VM through its ordinary NAT or supported virtual network.
- Establish a WireGuard tunnel from the administration VM to a range firewall or dedicated management gateway.
- Route only approved management and lab networks through the tunnel.
- Restrict Proxmox, firewall administration, and SSH to the management path.
- Keep the Proxmox web interface off the public Internet.
- Use a separate operator VM for offensive activity.

## Validation Checklist

- [ ] Administration VM reaches approved management services through WireGuard.
- [ ] Host computer does not require a direct tower connection.
- [ ] Operator VM cannot administer Proxmox.
- [ ] Vulnerable targets cannot reach the household network.
- [ ] VPN revocation and recovery procedures are tested.
- [ ] Firewall logs show the expected management path.

Private keys, peer configuration, public endpoints, and actual management addresses must never be committed.
