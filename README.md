# pf-netbird

Install, update and uninstall [NetBird](https://netbird.io) on a pfSense firewall, over SSH, from your own computer.

**Status:** not released yet. The script will be published here as a tagged release, so the downloads below work once the first release is out.

## Why

It started with a simple question: how easy is it to keep NetBird maintained on pfSense? That led to automating it. pf-netbird is built on [NetBird](https://github.com/netbirdio/netbird) and pfSense, follows NetBird's own [pfSense guide](https://docs.netbird.io/get-started/install/pfsense), and adds the automation. The author forgets to update, so the tool can do it on a schedule.

## Features

- Simple menu: check, back up, install or update, uninstall
- Backup before every change, your choice: Local, ACB (AutoConfigBackup, confirmed at Netgate) or Both. No backup, no change
- Dry run: shows the plan, changes nothing
- Login works like plain `ssh`, including SSH agents such as 1Password
- Optional auto-update that runs on the firewall itself (pfSense cron), so your computer can be off

## Requirements

- **Client:** PowerShell 7+ and the OpenSSH client (Windows), or bash 4.1+, OpenSSH client and curl (Linux)
- **Firewall:** stock pfSense CE 2.8+ or Plus 25.07+ (FreeBSD ABI 15+)

## Usage

### Windows

Needs PowerShell 7 or newer (`pwsh`). It does not run in Windows PowerShell 5.1.

```powershell
Invoke-WebRequest https://github.com/uboesen/pf-netbird/releases/latest/download/pfnetbird.ps1 -OutFile pfnetbird.ps1
pwsh ./pfnetbird.ps1
```

### Linux

```bash
curl -LO https://github.com/uboesen/pf-netbird/releases/latest/download/pfnetbird.sh
chmod +x pfnetbird.sh
./pfnetbird.sh
```

### What happens

1. A start screen opens. Choose **1) Connect to firewall**.
2. Enter the firewall address (for example `192.0.2.1`) and the user, `root` or `admin`.
3. Login works like plain `ssh`: your SSH key (from an agent such as 1Password) or your password.
4. The menu appears: **Check**, **Backup only**, **Install/Update**, **Uninstall**, **Auto-update**, **Logging**.

Anything that changes the firewall asks for a backup first, then offers **Run**, **Dry run** or **Back**.

### Options

| Linux | Windows | What it does |
|-------|---------|--------------|
| `--check` | `-Check` | Read-only status |
| `--dry-run` | `-DryRun` | Show the plan, change nothing |
| `--no-log` | `-NoLog` | No session log |
| `--key <file>.pub` | | Pin one SSH key (Linux only) |

More in `./pfnetbird.sh --help`.

## Tested on

- Firewalls: Netgate 4200 and Netgate 4100, pfSense Plus 25.11 (a VM test target is planned)
- Clients: Windows 11 25H2+ and Debian 13

Written for Linux first (bash), then PowerShell.

## Feedback

Feature requests and bugs: please [open an issue](https://github.com/uboesen/pf-netbird/issues).

## Disclaimer

Independent community tool, not affiliated with NetBird or Netgate. NetBird, pfSense and Netgate are trademarks of their respective owners. Use at your own risk and keep your own backups.

## License

[MIT](LICENSE)
