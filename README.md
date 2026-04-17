# kvmd-auth-ip

IP-based auto-login for [PiKVM](https://pikvm.org/) — automatically detects users by their IP address and skips the login form.

![PiKVM Extension](https://img.shields.io/badge/PiKVM-Extension-blue)

## What it does

When a user opens a PiKVM, this extension checks their IP address:

- **Tailscale IPs (100.x.x.x)** — automatically detected via `tailscale whois`. No configuration needed.
- **LAN IPs (192.168.x.x)** — matched against a static map in `/etc/kvmd/ip-users.conf`.

If a match is found, the user is logged in automatically — they never see the login form. If no match, the normal login form appears.

## Compatibility

| kvmd version | Status |
|---|---|
| 4.140 – 4.165 | Tested and working |
| < 4.140 | Untested — may work |
| > 4.165 | Should work unless upstream refactors auth API |

## Requirements

- PiKVM with kvmd 4.140+
- Authentication enabled (`kvmd.auth.enabled: true`)
- Tailscale running on the PiKVM (for auto-detection of Tailscale users)
- All user passwords set to `1` (shared password for auto-login)

## Installation

```bash
rw
curl -LO https://github.com/nullstacked/kvmd-auth-ip/releases/latest/download/kvmd-auth-ip-1.0.0-1-any.pkg.tar.zst
pacman -U kvmd-auth-ip-1.0.0-1-any.pkg.tar.zst
```

Set all user passwords to `1`:

```bash
echo "1" | kvmd-htpasswd set -i david
echo "1" | kvmd-htpasswd set -i zohaib
echo "1" | kvmd-htpasswd set -i jesse
# repeat for each user
ro
```

## Configuration

### Tailscale users (automatic)

No configuration needed. Any user connecting from a Tailscale IP is automatically identified via `tailscale whois`. The username is extracted from their Tailscale login (the part before `@`).

### LAN users (static map)

Edit `/etc/kvmd/ip-users.conf`:

```
192.168.100.55=david
192.168.100.60=jesse
```

This file persists across kvmd and kvmd-auth-ip updates.

### External users via gateway

Users connecting through a NAT gateway all appear as the gateway's IP. To distinguish them, you would need to switch the gateway from L4 DNAT to an L7 nginx reverse proxy that passes `X-Forwarded-For`. Without that, external users see the normal login form (still works — they just type their username and the shared password `1`).

## How it works

1. User opens PiKVM URL → browser loads login page
2. Login page JS calls `/api/auth/ip-detect`
3. Endpoint checks source IP: Tailscale API first, then static map
4. If match found → returns `{"user": "zohaib"}`
5. JS auto-fills username + shared password, auto-submits the form
6. User goes straight to KVM — login page flashes briefly then redirects

If IP not recognized → normal login form, no change to existing behavior.

## What gets patched

| File | Change |
|---|---|
| `kvmd/apps/kvmd/api/auth.py` | New `/api/auth/ip-detect` endpoint |
| `web/share/js/login/main.js` | Auto-login JS on page load |
| `/etc/kvmd/ip-users.conf` | NEW — static IP-to-user map (not overwritten on updates) |

## Survives kvmd updates

ALPM hook automatically re-applies patches after any `kvmd` package upgrade.

## Uninstall

```bash
rw
pacman -R kvmd-auth-ip
pacman -S kvmd  # restore original files
ro
```

`/etc/kvmd/ip-users.conf` is not removed — delete manually if no longer needed.

## Works with kvmd-presence

This plugin pairs well with [kvmd-presence](https://github.com/nullstacked/kvmd-presence). Auto-login provides the user identity that the presence overlay displays. Install both for the full experience.

## License

GPL-3.0 — same as kvmd.
