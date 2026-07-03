# Hugin Agent

[English](README.md) | **한국어**

> 인바운드 포트를 전혀 열지 않고, 클라우드 오케스트레이터를 대신해 로컬의
> 헤드리스 **Claude Code / Codex CLI**를 실행하는 **아웃바운드 전용** 로컬 브리지
> 데몬입니다.

당신의 노트북은 NAT과 방화벽 뒤에 있습니다. `hugind`는 WSS로 오케스트레이터에
**바깥으로(dial out)** 접속해 명령을 받고, 로컬 코딩 CLI를 헤드리스로 실행한 뒤
정규화된 결과를 스트리밍해 돌려보냅니다. GitHub Actions self-hosted runner나
Claude Code Remote Control과 동일한 아웃바운드 전용 패턴입니다. **인바운드 포트는
절대 열리지 않습니다.**

---

## 상태(Status)

- **와이어 프로토콜 `v1.0.0` — FROZEN(동결)** ([`protocol/`](protocol/README.md)).
  zod SSOT + 스펙 + F4 크로스언어 테스트 벡터. 클라우드 diff 리뷰: **FREEZE-OK**.
- **`hugind` MVP — mock relay 상대로 구축** (P0–P5 단계, 참고:
  [`docs/hugind-mvp-plan.md`](docs/hugind-mvp-plan.md)). 전송 계층, 비인증
  핸드셰이크, 재접속, 전체 잡 라이프사이클, git-worktree 격리, 재접속 resume +
  리스 회전이 구현·테스트되었습니다 (`npm run e2e`). **실제 Claude 어댑터**는 실제
  CLI에서 잡을 끝까지 스트리밍합니다 (`npm run e2e:claude`, allow / read-only 경로).
  **승인 라운드트립 + fail-closed 정책**은 fake 엔진으로 manager/protocol 레벨에서
  구현·테스트되었고, **라이브 Claude 권한 브리지도 구축**되었습니다 (아래 Track B).
  격리된 게이트가 로그인에 도달할 수 없는(env-auth 없음) 호스트에서는 데몬이
  write/exec 잡에 대해 **fail-closed**됩니다.
- **프로덕션 인증(Track A) — 구축·테스트 완료.** OS 키체인의 실제 Ed25519 기기 키
  (`@napi-rs/keyring`)가 동결된 핸드셰이크 transcript에 서명합니다
  (`keychainSigner`, 개발용 stub의 드롭인 교체). `hugin-agent connect`는 이제 rev2
  브라우저-개시 `hpk1` 페이스트 토큰 + Ed25519 PoP + 필수 지문 활성화 흐름을
  실행하여 `agent_id`/`key_id`/`tenant_id`를 발급하고 **공개** 키를 등록합니다 —
  개인 키는 호스트를 절대 벗어나지 않습니다. mock 페어링 서버가 소유 증명을
  검증합니다 (`npm run e2e` AE1–AE9). 보안 표면:
  [`docs/auth-pairing-spec.md`](docs/auth-pairing-spec.md).
  > **페어링 세리머니 rev2 — 데몬 쪽 구축 완료(LOCKED, off-wire).** 데몬 `connect`
  > 구현은 브라우저-개시 `hpk1` 페이스트 토큰 + Ed25519 소유 증명(PoP) + 필수 지문
  > 활성화를 사용합니다 (auth-spec §3/§5c; e2e AE1–AE9). 이 페어링 경로는
  > off-wire이며 와이어 `v1.0.0` / `PROTOCOL_VERSION`을 변경하지 않습니다. 실제
  > Python C2 통합은 Track C로 남아 있습니다.
- **승인 브리지(Track B) — 구축·테스트 완료.** 실제 Claude
  `--permission-prompt-tool`이 인프로세스 `ApprovalBridge`(실행당 UNIX 소켓 —
  인바운드 TCP 포트 없음) + stdio MCP 서브프로세스를 통해 `onApprovalRequest`에
  연결됩니다 ([`src/engine/permission.ts`](src/engine/permission.ts)). 도구 프롬프트는
  원격 결정을 기다리며 블로킹됩니다 (fail-closed: 채널이 끊기면 거부). 시작 시
  `selfCheckGate`가 `gateAvailable`을 결정하고(강제 도구가 실제로 프롬프트를 거쳐야
  함), env-auth가 격리된 자식 프로세스에 주입됩니다. 브리지 + 배선 + 게이트 체크는
  CI 테스트됩니다 (`npm run e2e` AH–AK, 실제 claude 불필요). 라이브 deny→blocked
  게이트는 `npm run e2e:claude`에서 가드됩니다 (env-auth 또는 깨끗한 로그인 필요 —
  [`src/engine/isolate.ts`](src/engine/isolate.ts)의 격리 finding 참고).
- **연기됨(Deferred)** (각각 명시적으로 범위 지정): 실제 relay 상대의 클라우드 통합
  (Track C); P5 서비스 패키징은 [`service/`](service/README.md) 아래 스켈레톤 상태.

## 아키텍처(Architecture)

```
protocol/v1/   동결된 와이어 SSOT (messages, transcript, digest, origin) — relay와 공유
src/
  conn/        WSS 클라이언트, 단일 choke-point 프레이밍, 핸드셰이크, 하트비트, 재접속
  jobs/        registry(멱등), lease, manager(오케스트레이션, 승인, resume)
  engine/      Engine 인터페이스; ClaudeEngine(stream-json spawn), isolate, normalize; fake 엔진
  workspace/   git-worktree 격리 (allowlist + realpath + 경로 주입 안전)
  store/       SQLite 이벤트 로그 (seq persist-before-send, ack GC, digest-ack, backpressure)
  daemon.ts    라이프사이클: dial → 핸드셰이크 → 잡 펌프 → 재접속 (데몬 레벨 registry)
mock-relay/    e2e용 스크립트 가능 relay (클라우드 불필요)
```

원칙: 아웃바운드 전용 · at-least-once + 멱등(`seq`/`event_id` 중복 제거) · 모든
attempt 범위 메시지에 리스 펜싱 · digest-ack 완료 · persist-before-send 내구성 ·
게이트 없는 write/exec에 대해 fail-closed.

## 실행(Run)

```bash
npm install
npm run typecheck        # 프로토콜 + 데몬 타입 체크
npm run protocol:check   # 모든 프로토콜 메시지 + F4 벡터 검증
npm run e2e              # 데몬 ⇄ mock relay, fake 엔진 (CI 안전, 클라우드/claude 불필요)
npm run e2e:claude       # 실제 CLI 어댑터 체크 (`claude` 설치 + 로그인 필요)
npm run connect                     # 이 기기 페어링 (숨겨진 stdin으로 hpk1 토큰 붙여넣기); 최초 1회
npm run hugind           # 데몬 실행 (페어링된 config, 또는 env 오버라이드 — 아래 참고)
npm run mock-relay       # 독립 실행형 mock relay
```

## 설정(Configure — env, [`src/config.ts`](src/config.ts))

페어링 후(`npm run connect` 실행 후 브라우저의 hpk1 토큰 붙여넣기), 데몬은 자신의
신원을 영속화된 config에서 읽습니다 (`~/.config/hugin-agent/config.json` — 비밀 아님:
`agent_id`/`key_id`/`tenant_id`/serverUrl; 기기 개인 키는 OS 키체인에 유지). env
변수는 필요 없습니다. 페어링된 키가 없고 env 오버라이드도 없으면 **fail-closed**되어
접속하지 않습니다. `HUGIND_*` env 변수는 개별 영속 필드를 오버라이드하며,
`HUGIND_SERVER_URL` + `HUGIND_AGENT_ID`가 페어링 없이 실행하기 위한 최소값입니다.
supervised(launchd / systemd)로 실행하려면 [`service/`](service/README.md)를 참고하세요.

```bash
HUGIND_SERVER_URL=wss://relay.example.com \
HUGIND_AGENT_ID=my-laptop \
HUGIND_PROJECT_ROOTS=/Users/you/code \
npm run hugind
```

## 그 외 문서(Also here)

| 경로 | 내용 |
|------|------|
| [`docs/hugind-mvp-plan.md`](docs/hugind-mvp-plan.md) | 구축 계획(P0–P5) + 설계 결정 |
| [`docs/auth-pairing-spec.md`](docs/auth-pairing-spec.md) | 보안 표면: canonical 서명 바이트, 페어링, 키 |
| [`docs/PROPOSAL.md`](docs/PROPOSAL.md) | 클라우드 동결 기록 (v1.6 → v1.0.0) |
| [`spikes/approval-prompt-tool/`](spikes/approval-prompt-tool/README.md) | 승인 메커니즘 스파이크 (permission-prompt-tool findings) |

## 라이선스(License)

Apache-2.0 (제안).
