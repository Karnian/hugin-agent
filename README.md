# Hugin Agent

> Outbound-only local bridge daemon that runs your headless **Claude Code / Codex CLI**
> on behalf of a cloud orchestrator — without opening any inbound ports.

Your laptop sits behind NAT and a firewall. Hugin Agent dials **out** to the
orchestrator over WSS, receives commands, runs the local coding CLI headlessly,
and streams normalized results back. Same outbound-only pattern as a GitHub
Actions self-hosted runner or Claude Code Remote Control. **No inbound port is
ever opened.**

---

## Status: pre-MVP (design spikes)

This repo currently contains the two pieces that must be de-risked **before**
writing the daemon:

| Path | What |
|------|------|
| [`protocol/`](protocol/README.md) | **Wire protocol v1.0.0 (FROZEN)** — the WSS JSON contract shared with the cloud relay. zod SSOT + spec + F4 cross-language test vectors. Cloud diff-review: FREEZE-OK. `protocol:check` green. |
| [`spikes/approval-prompt-tool/`](spikes/approval-prompt-tool/README.md) | **Approval spike** — empirically probes headless Claude's `--permission-prompt-tool` request/response behavior. |
| [`docs/PROPOSAL.md`](docs/PROPOSAL.md) | **Review request** for the cloud team — what to confirm before the contract is frozen. |

The daemon (`hugind`), pairing, WSS dial-out, and engine adapters land **after**
the protocol is agreed with the cloud team and the approval mechanism is proven.

## Quick checks

```bash
npm install
npm run typecheck        # type-check protocol + spikes
npm run protocol:check   # validate one sample of every protocol message
npm run spike:approval   # run the approval spike (needs claude logged in)
```

## License

Apache-2.0 (proposed).
