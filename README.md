# pfnetbird

Install, update and uninstall [NetBird](https://netbird.io) on a pfSense firewall, over SSH, from your own computer.

## Why

It started with a simple question: how easy is it to keep NetBird maintained on pfSense? That led to automating it. pfnetbird is built on [NetBird](https://github.com/netbirdio/netbird) and pfSense, follows NetBird's own [pfSense guide](https://docs.netbird.io/get-started/install/pfsense), and adds the automation. The author forgets to update, so the tool can do it on a schedule.

## Features

- Simple menu: check, back up, install or update, uninstall
- Backup before every change, your choice: Local, ACB (AutoConfigBackup, confirmed at Netgate), Both or Skip. The change runs only if the chosen backup succeeded; with Skip it runs without a backup and the result says `No backup was taken.`
- Dry run: shows the plan, changes nothing
- Login works like plain `ssh`, including SSH agents such as 1Password
- Optional auto-update that runs on the firewall itself (pfSense cron), so your computer can be off. Requires ACB (Services > AutoConfigBackup) with an encryption password, because the firewall has no PC to save a local backup to.

## Requirements

- `pfnetbird.sh`: bash 4.2+, `sha256sum` (GNU coreutils), the OpenSSH client (`ssh`) and `curl`, plus `grep`, `sed` and `awk` and the usual coreutils. Tested on Linux.
- `pfnetbird.ps1`: PowerShell 7.1+ and the OpenSSH client (`ssh`). Tested on Windows.
- Firewall: pfSense Plus 25.11+ (tested) or CE 2.8+ (expected to work, not tested on a real box); FreeBSD ABI 15+

## Usage

### Windows

Needs PowerShell 7 or newer (`pwsh`). It does not run in Windows PowerShell 5.1.

```powershell
Invoke-WebRequest https://github.com/uboesen/pfnetbird/releases/latest/download/pfnetbird.ps1 -OutFile pfnetbird.ps1
pwsh ./pfnetbird.ps1
```

### Linux

```bash
curl -LO https://github.com/uboesen/pfnetbird/releases/latest/download/pfnetbird.sh
chmod +x pfnetbird.sh
./pfnetbird.sh
```

### What happens

1. A start screen opens. Choose **1) Connect to firewall**.
2. Enter the firewall address (for example `192.0.2.1`) and the user, `root` or `admin`.
3. Login works like plain `ssh`: your SSH key (from an agent such as 1Password) or your password.
4. The menu appears: **Check**, **Backup only**, **Install/Update**, **Uninstall**, **Auto-update**, **Logging**.

Anything that changes the firewall first offers **Run**, **Dry run** or **Back**, one item per line. After **Run** it asks `[y/N]`, and only then asks for the backup (Local, ACB, Both, Skip or Back):

```
Update NetBird 0.79.2 → 0.80.0
 1) Run
 2) Dry run (plan only)
 3) Older release
 4) Back
```

### Options

| Linux | Windows | What it does |
|-------|---------|--------------|
| `--host [user@]host` | `-Host [user@]host` | Skip the start screen and connect at once; the script ends after Disconnect |
| `--key <file>` | `-Key <file>` | Pin one SSH key: a private key file, or its `.pub` file to pick one agent key. No password fallback |
| `--no-log` | `-NoLog` | No session log (it can be switched on from the menu) |
| `--version` | `-Version` | Print the version and exit |
| `--help`, `-h` | | Show help (PowerShell: `Get-Help ./pfnetbird.ps1 -Full`) |
| `--ascii` | | Plain ASCII instead of Unicode glyphs (bash only; `PFNETBIRD_ASCII=1` does the same in both) |

Environment: `NO_COLOR` turns colour off, `PFNETBIRD_ASCII=1` forces ASCII, and an optional `GITHUB_TOKEN` raises the GitHub rate limit. More in `./pfnetbird.sh --help`.

## Tested on

- Firewalls:
  - Netgate SG-4860 · pfSense Plus 25.11 (FreeBSD 16)
  - Netgate 4100 · pfSense Plus 26.03.1 (FreeBSD 16)
- Clients:
  - Windows 11 25H2 · PowerShell 7.6.6 · Windows Terminal
  - Debian 13 · bash 5.2.37
- Not tested: macOS and the Windows console host (conhost). macOS should work with Homebrew bash and coreutils (`brew install bash coreutils`). Feedback is very welcome: https://github.com/uboesen/pfnetbird/issues.

Written for Linux first (bash), then PowerShell.

## Feedback

Feature requests and bugs: please [open an issue](https://github.com/uboesen/pfnetbird/issues).

## Disclaimer

Independent community tool, not affiliated with NetBird or Netgate. NetBird, pfSense and Netgate are trademarks of their respective owners. Use at your own risk and keep your own backups.

## License

[MIT](LICENSE)

## Credits

- [netbirdio/pfsense-netbird](https://github.com/netbirdio/pfsense-netbird): the official NetBird package for pfSense. pfnetbird installs and updates exactly these release packages and does not replace them. What pfnetbird adds: an easier rollout and update from a PC, with a backup before every change and an optional auto-update.
- [Miralthor/netbird-pfsense-helper](https://github.com/Miralthor/netbird-pfsense-helper) (MIT): a helper that runs on the firewall. pfnetbird took the idea of SHA-256 verification of the downloaded packages from it.
