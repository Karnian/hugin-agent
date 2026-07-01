# Running `hugind` as a service

Templates for supervising the daemon. Both run it **as your user** (not root):
the daemon spawns the local Claude/Codex CLI, which uses **your** login
(macOS keychain / `~/.claude`), so it must share your session.

> **Skeleton, not an installer.** Fill the `REPLACE_ME` values + paths first.
> Production would ship a bundled JS entry instead of `npx tsx src/index.ts`.

## Config (env — see [`src/config.ts`](../src/config.ts))

| Var | Required | Default |
|-----|----------|---------|
| `HUGIND_SERVER_URL` | ✅ | — (`wss://…`; `ws://` only for loopback) |
| `HUGIND_AGENT_ID` | ✅ | — (per-device, minted at pairing) |
| `HUGIND_TENANT_ID` | | `dev-tenant` |
| `HUGIND_KEY_ID` | | `dev-key` |
| `HUGIND_AGENT_VERSION` | | `0.0.0` (reported in `hello.agent_version`; set a real release value) |
| `HUGIND_PROJECT_ROOTS` | | `[]` (comma-separated allowlist of repo roots) |
| `HUGIND_STATE_DIR` | | `.hugind` (SQLite event log + worktrees) |

## macOS (launchd)

```bash
cp service/com.contextualai.hugind.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.contextualai.hugind.plist
launchctl list | grep hugind          # status
launchctl unload ~/Library/LaunchAgents/com.contextualai.hugind.plist  # stop
```

## Linux (systemd --user)

```bash
mkdir -p ~/.config/systemd/user
cp service/hugind.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hugind
journalctl --user -u hugind -f        # logs
systemctl --user stop hugind          # stop (daemon sends agent.draining first)
```

## Notes

- **Auth is deferred**: the MVP handshake uses a dev stub signer. The production
  path (OS-keychain Ed25519 + device-code pairing) lands before real deployment —
  see [`docs/auth-pairing-spec.md`](../docs/auth-pairing-spec.md).
- **Approval gate / write jobs**: until the real MCP permission bridge is wired,
  the daemon **fails closed** on write/exec jobs (only `read_only` + `never` runs).
  See [`docs/hugind-mvp-plan.md`](../docs/hugind-mvp-plan.md) §5.6.
