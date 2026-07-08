# Keeping `hugind` resident

`src/index.ts` is the foreground daemon entry. Keep it alive in one of two ways:

1. `hugind start/stop/status/restart` lifecycle CLI: lightweight and useful for local development. It detaches the foreground daemon so it survives shell exit, but it does not auto-restart after a crash unless another service manager supervises it.
2. launchd/systemd service: preferred for daily use. The OS service manager runs the foreground daemon and restarts it after crashes, logout/login, or clean exits.

As long as the daemon process is alive, it auto-reconnects within ~10 s of a C2 restart (backoff 0.5s→10s cap); the only failure mode was the process not staying resident. In `src/daemon.ts`, `Daemon.start()` loops while `this.running`, calls `backoffDelay(attempt, 500, 10_000)`, resets `attempt = 0` after an established session, and logs `reconnecting`.

Both service templates run as your user, not root. The daemon spawns local Claude/Codex tooling and needs your normal user login state.

## Environment

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `HUGIND_SERVER_URL` | yes | paired config | `wss://...` for real relays; `ws://` only for loopback/dev |
| `HUGIND_AGENT_ID` | yes | paired config | Per-device agent id |
| `HUGIND_TENANT_ID` | no | paired config, then `dev-tenant` | Tenant binding |
| `HUGIND_KEY_ID` | no | paired config, then `dev-key` | OS-keychain device key id |
| `HUGIND_AGENT_VERSION` | no | `0.0.0` | Reported in hello |
| `HUGIND_PROTOCOL_VERSION` | no | `2.0.0` | Set `1.0.0` only for a v1-only relay |
| `HUGIND_PROJECT_ROOTS` | no | empty allowlist | Comma-separated absolute repo roots |
| `HUGIND_STATE_DIR` | no | daemon config default `.hugind`; lifecycle CLI uses an OS state dir | SQLite event log, worktrees, and lifecycle pid/log override |
| `HUGIND_ENGINE_CMD` | no | `claude` | Engine command override |
| `HUGIN_SIMPLE_PAIRING` | no | off | Dev-only. Set to `1` only when using a raw-IP `ws://` relay such as `ws://127.0.0.1:...` |

## Lifecycle CLI

Install dependencies once from the repo:

```bash
npm install
```

Start, inspect, stop, and restart:

```bash
HUGIND_SERVER_URL=wss://relay.example.com \
HUGIND_AGENT_ID=REPLACE_ME \
HUGIND_TENANT_ID=REPLACE_ME \
HUGIND_PROJECT_ROOTS="$HOME/code" \
npm run hugind:start

npm run hugind:status
npm run hugind:stop
npm run hugind:restart
```

The CLI writes `hugind.pid` and `hugind.log` under `HUGIND_STATE_DIR` when set. Otherwise it uses:

| OS | Default lifecycle state dir |
|----|-----------------------------|
| macOS | `~/Library/Application Support/hugin-agent` |
| Linux | `${XDG_STATE_HOME:-~/.local/state}/hugin-agent` |
| Windows | `%LOCALAPPDATA%\hugin-agent` or `~/AppData/Local/hugin-agent` |

Uninstall/cleanup for the lifecycle CLI:

```bash
npm run hugind:stop
# Optional: remove the lifecycle state dir if you no longer need hugind.pid or hugind.log.
```

## macOS launchd

Edit `service/com.contextualai.hugind.plist` before installing:

- Replace `/usr/local/bin/node` with the absolute path from `which node`.
- Replace `/opt/hugin-agent` and `/opt/hugin-agent/src/index.ts` with this repo's absolute path.
- Fill `REPLACE_ME` values and user-specific paths.
- Add `HUGIN_SIMPLE_PAIRING=1` only for a raw-IP `ws://` dev relay.

Install/start:

```bash
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
cp service/com.contextualai.hugind.plist ~/Library/LaunchAgents/
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.contextualai.hugind.plist
launchctl kickstart -k "gui/$(id -u)/com.contextualai.hugind"
launchctl print "gui/$(id -u)/com.contextualai.hugind"
```

Logs:

```bash
tail -f ~/Library/Logs/hugind.out.log ~/Library/Logs/hugind.err.log
```

Uninstall/stop:

```bash
launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/com.contextualai.hugind.plist
rm -f ~/Library/LaunchAgents/com.contextualai.hugind.plist
```

## Linux systemd user service

Edit `service/hugind.service` before installing:

- Replace `/opt/hugin-agent` and `/opt/hugin-agent/src/index.ts` with this repo's absolute path.
- Ensure `node` is available to `/usr/bin/env` in the user service environment, or replace `/usr/bin/env node` with an absolute node path.
- Fill `REPLACE_ME` values and user-specific paths.
- Add `Environment=HUGIN_SIMPLE_PAIRING=1` only for a raw-IP `ws://` dev relay.

Install/start:

```bash
mkdir -p ~/.config/systemd/user
cp service/hugind.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hugind
systemctl --user status hugind
```

Logs:

```bash
journalctl --user -u hugind -f
```

Uninstall/stop:

```bash
systemctl --user disable --now hugind
rm -f ~/.config/systemd/user/hugind.service
systemctl --user daemon-reload
```

## Windows

Planned / not yet shipped: a first-class Windows Service template.

The `hugind start/stop/status/restart` lifecycle CLI already works on Windows and uses `%LOCALAPPDATA%\hugin-agent` for its default pid/log state. For boot/crash auto-start on Windows, wrap the foreground daemon command with a Windows service manager:

```powershell
node --import tsx C:\absolute\path\to\hugin-agent\src\index.ts
```

Candidate wrappers for the planned service follow-up are `node-windows`, NSSM, or Task Scheduler. Until that template ships, use the lifecycle CLI for detached local runs and a wrapper only when boot/crash restart is required.
