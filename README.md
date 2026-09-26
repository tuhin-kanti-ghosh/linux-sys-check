# sys-check

A single bash script that runs a quick manual security/health check on a Linux
system and prints a readable, sectioned report — network connections, running
processes, persistence mechanisms (cron, systemd), SSH keys, login history,
and file permissions. Flags anything that looks off along the way.

This is a **triage tool**, not a signature-based scanner. Pair it with
`rkhunter`, `chkrootkit`, `clamscan`, or `lynis` for deeper checks.

## What it checks

- **Network** — active connections (`ss -tupn`) and listening ports, flags
  established connections on non-standard ports
- **Processes** — top CPU/memory consumers, flags root processes running
  from `/tmp`, `/dev/shm`, or `/var/tmp`
- **Persistence** — user and root crontabs, system cron directories,
  running/enabled systemd services, recently modified unit files
- **SSH** — authorized_keys contents (truncated), `sshd_config`
  root-login/password-auth settings
- **Login history** — recent logins (`last`), recent failed SSH attempts
- **Accounts** — UID 0 and UID 1000+ users, accounts with login shells
- **Filesystem** — world-writable files in `/etc`, `/bin`, `/sbin`,
  `/usr/bin`, `/usr/sbin`

Each run is saved to a timestamped log file (`sys-check_YYYYMMDD_HHMMSS.log`)
unless run with `--no-log`.

## Requirements

- bash
- Standard Linux userland: `ss`, `ps`, `awk`, `find`, `last`
- `sudo` (optional, for root crontab check)
- `systemctl` (optional, for systemd checks — skipped if absent)
- `journalctl` (optional, falls back to `/var/log/auth.log` if absent)

Tested on Arch-based systems (CachyOS/Arch/Manjaro). Should run on most
systemd-based distros.

## Usage

```bash
chmod +x sys-check.sh
./sys-check.sh
```

Skip writing a log file:

```bash
./sys-check.sh --no-log
```

## Output

The script prints color-coded lines inline with each section:

- `[OK]` — nothing unusual found
- `[CHECK]` — needs a human look (not necessarily bad)
- `[SUSPICIOUS]` — flagged automatically, worth investigating first

A summary line at the end totals how many items were auto-flagged.

## Recommended companion tools

For deeper, signature-based scanning beyond what this script does:

```bash
sudo rkhunter --check
sudo chkrootkit
sudo clamscan -r /
sudo lynis audit system
```

## Disclaimer

This script surfaces information for manual review — it does not
definitively diagnose infection or compromise on its own. Treat
`[SUSPICIOUS]` flags as a starting point for investigation, not a
confirmed verdict.

## License

MIT
