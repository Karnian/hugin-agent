# C2 수정 요청 — WSS 프레임을 frozen v1.0.0 평면 포맷으로

**대상**: Hugin C2 (Python) WSS 엔드포인트 담당
**보낸 쪽**: hugin-agent 데몬(`hugind`)
**날짜**: 2026-07-03
**우선순위**: 블로킹 — 이 수정 전까지 어떤 에이전트도 핸드셰이크를 완료할 수 없음

---

## 1. TL;DR

에이전트가 페어링(HTTP)까지는 성공하지만, WSS 핸드셰이크를 **완료하지 못합니다.** 원인은
C2가 **frozen 프로토콜 v1.0.0과 다른 "provisional" 와이어 포맷**으로 프레임을 주고받기
때문입니다. C2가 보내는 프레임은 `{ v, type, payload }` 봉투로 감싸여 있고, frozen이
요구하는 최상위 `id`/`ts`와 `auth.challenge`의 `server_time`이 빠져 있습니다. 그리고
에이전트가 보낸 평면 `hello`(모든 변형)에 대해 C2가 **응답 프레임 없이 소켓을 끊었습니다**
— 수신부 동작을 프레임만으로는 진단할 수 없으나, 최소한 C2가 평면 `hello`를 정상 처리하지
못하고 있음을 뜻합니다.

**요청**: C2의 WSS 송·수신 프레임을 **frozen v1.0.0 평면 포맷**으로 맞춰 주세요.
와이어 계약은 동결(frozen)되어 있으며, 에이전트와 mock relay가 그 평면 포맷을 구현합니다
(Python 참조 모듈은 crypto/검증 primitive만 다루고 JSON 프레이밍은 규정하지 않음 — §4 참고).
변경은 전적으로 C2 쪽 JSON 직렬화/역직렬화에 국한됩니다.

참고: **WS 경로 자체는 문제 없습니다.** C2가 `/api/v1/hugin-agents/connect`에서 서빙하는
것이 맞고, 에이전트가 그 경로로 다이얼하도록 이미 수정했습니다(이전엔 베어 오리진으로 다이얼해
`403`이 났었음). 이 문서는 오직 **프레임 포맷**에 관한 것입니다.

---

## 2. 관측된 증상 (라이브 C2 실측)

`ws://<relay>/api/v1/hugin-agents/connect`로 붙어 실제 프레임을 떠서 확인했습니다.

**C2가 보낸 첫 프레임 (auth.challenge):**
```json
{
  "v": "1.0.0-provisional",
  "type": "auth.challenge",
  "payload": {
    "challenge_id": "469524a8-b41c-4b49-a045-82da9b8ca857",
    "nonce": "vSkccQM13Syfo7CY77Qw1cUhhiw7t_H6wSiqamiry_E",
    "challenge_ttl_ms": 60000
  }
}
```

**핸드셰이크 시도 결과** (페어링된 키체인 키로 실제 Ed25519 서명한 `hello` 전송):

| 에이전트가 보낸 것 | C2 반응 |
|---|---|
| 평면 `hello` (frozen 포맷) | 소켓 즉시 `1006` 종료, `hello.rejected` 프레임 없음 |
| 봉투 `hello` (`protocol_version: "1.0.0"`) | `1006` 종료, 응답 프레임 없음 |
| 봉투 `hello` (`protocol_version: "1.0.0-provisional"`) | `1006` 종료, 응답 프레임 없음 |

관찰로 확정된 것: C2는 (a) challenge를 **봉투로 감싸 보내고**, (b) 시도한 모든 `hello`
변형에 대해 **응답 프레임 없이 소켓을 닫았습니다.** 후자는 "받는 쪽이 봉투를 요구한다"까지
증명하는 건 아니며(에러 프레임이 없어 수신부 원인은 프레임만으로 진단 불가), 다만 **정상
경로면 파싱된 hello의 서명 실패 시 `hello.rejected`를 보내고 닫아야 하는데 그 프레임이
전혀 없다**는 점이 문제입니다. (데몬 로그 상 challenge 프레임은 `invalid_message ...
Unrecognized keys: "v", "payload"`로 거부됩니다 — frozen 스키마는 strict object라 미지
키를 받지 않음.)

---

## 3. 정확히 무엇이 다른가

frozen v1.0.0의 모든 메시지는 **평면 strict object**이며 `{ id, ts, type, … }`를
공유합니다 (`protocol/v1/messages.ts:255-258`). 봉투(`v`/`payload`) 개념은 계약에
존재하지 않습니다. `auth.challenge` 기준 세 가지 차이:

| # | 항목 | C2 현재 (provisional) | frozen v1.0.0 (요구) |
|---|---|---|---|
| 1 | 구조 | `{ v, type, payload:{…} }` 봉투 | 평면 `{ id, ts, type, …필드 }` |
| 2 | `id`, `ts` | 없음 | **필수** (모든 메시지 최상위) |
| 3 | `server_time` | 없음 | **필수** (`auth.challenge`) |

`payload` 안의 `challenge_id`/`nonce`/`challenge_ttl_ms`는 그대로 최상위로 올리면 됩니다.

---

## 4. 요구 수정

C2의 WSS **송신·수신** 프레임을 아래 평면 포맷으로 맞춰 주세요. 즉:

- 송신: `{ v, type, payload }`로 감싸지 말고, `payload` 필드를 최상위로 평면화 + `id`/`ts`
  (+ `auth.challenge`엔 `server_time`) 추가.
- 수신: 에이전트가 보내는 평면 `hello`를 파싱 (봉투를 기대하지 말 것).

### 권위 있는 참조 (모두 이 레포에 존재)
- **`protocol/v1/messages.ts`** — 전 메시지의 frozen zod 스키마 (진실의 원천).
- **`mock-relay/server.ts`** — 참조 relay 구현. `handleConnection()`이 평면 프레임을
  보내는 방식, `verifyHello()`가 `auth-pairing-spec` §5(검증 절차)대로 transcript를
  재구성/검증하는 방식이 그대로 예시.
- **`protocol/v1/py/hugin_protocol_v1.py`** — 이미 벤더링한 Python 검증 primitive
  (`build_transcript`, `verify_transcript`, `canonicalize_server_origin`,
  `validate_auth_id`, `decode_nonce` …). **주의**: 이 모듈은 crypto/검증만 제공하고
  JSON 프레이밍은 규정하지 않습니다 — 그래서 봉투 divergence가 생긴 것으로 보입니다.
  프레이밍은 위 `messages.ts`/`mock-relay` 형태를 따라 C2가 직접 맞춰야 합니다.

---

## 5. 프레임 예시 (frozen 평면)

> 아래 예시에서 `<…>`로 감싸거나 `…`로 줄인 문자열은 **형식만 나타내는 placeholder**이며
> 리터럴 값이 아닙니다 (예: `signature`는 실제로는 86자 base64url). 각 필드의 실제 제약은
> 예시 아래 목록과 `protocol/v1/messages.ts`를 따르세요.

### 5.1 `auth.challenge` (C2 → 에이전트)
```json
{
  "id": "ch-msg-7f3a9c12",
  "ts": "2026-07-03T13:11:36.307Z",
  "type": "auth.challenge",
  "challenge_id": "469524a8-b41c-4b49-a045-82da9b8ca857",
  "nonce": "vSkccQM13Syfo7CY77Qw1cUhhiw7t_H6wSiqamiry_E",
  "server_time": "2026-07-03T13:11:36.307Z",
  "challenge_ttl_ms": 60000
}
```
필드 제약:
- `id`: 비어있지 않은 문자열(1..256자). 스키마가 고유성을 강제하지는 않지만 메시지마다
  고유하게 두는 것을 권장.
- `ts`, `server_time`: RFC3339 datetime with offset (예: `…Z` 또는 `+09:00`).
- `challenge_id`: AuthId `^[A-Za-z0-9._-]{1,128}$` (예시의 UUID는 하이픈만 쓰므로 유효).
- `nonce`: 32바이트를 **canonical base64url**로 인코딩 → 정확히 43자, 무패딩,
  재인코딩 시 동일해야 함(trailing pad bit 0). 단일 사용.
- `challenge_ttl_ms`: 양의 정수 (≤ 2^53−1, `Number.MAX_SAFE_INTEGER`).

### 5.2 `hello` (에이전트 → C2) — C2가 이 평면 형태를 받아야 함
```json
{
  "id": "msg-…",
  "ts": "2026-07-03T13:11:36.400Z",
  "type": "hello",
  "protocol_version": "1.0.0",
  "agent_id": "agent-a8f357fd42c4487f",
  "agent_version": "0.0.0",
  "auth": {
    "challenge_id": "469524a8-b41c-4b49-a045-82da9b8ca857",
    "key_id": "key-5ec0e917f38c4381",
    "signature": "<86자 base64url Ed25519 서명 — placeholder>",
    "alg": "ed25519"
  },
  "os": { "platform": "darwin", "arch": "arm64" },
  "capabilities": {
    "engines": { "claude": { "installed": true }, "codex": { "installed": false } },
    "project_roots": []
  },
  "active_jobs": [],
  "pending_results": []
}
```

### 5.3 `hello.accepted` (C2 → 에이전트, 검증 성공 시)
```json
{
  "id": "msg-…",
  "ts": "2026-07-03T13:11:36.500Z",
  "type": "hello.accepted",
  "negotiated_version": "1.0.0",
  "connection_epoch": 1,
  "heartbeat_interval_ms": 30000,
  "resume": []
}
```

### 5.4 `hello.rejected` (C2 → 에이전트, 검증 실패 시) — **끊지 말고 이 프레임을 보내 주세요**
```json
{
  "id": "msg-9f0e1d2c",
  "ts": "2026-07-03T13:11:36.600Z",
  "type": "hello.rejected",
  "code": "bad_signature",
  "message": "Ed25519 signature does not verify over the transcript"
}
```
`code` 허용값: `unsupported_version` | `unauthorized` | `agent_unknown` |
`bad_signature` | `expired_challenge`. 현재는 실패 시 소켓만 끊어서(`1006`) 원인 파악이
불가능합니다 — 반드시 `hello.rejected`를 보낸 뒤 닫아 주세요.

---

## 6. 서명 / transcript 주의 (와이어와 별개, 바뀌지 않음)

- **`protocol_version` 검증**: C2는 `hello.protocol_version == "1.0.0"`를 요구해야
  합니다(frozen). 그리고 transcript에는 `hello`가 실제로 보낸 값을 그대로 바인딩하세요 —
  치환된 버전(예: 봉투용 `"1.0.0-provisional"`)으로 검증하면 서명이 맞지 않습니다.
  (참고: 스키마의 `SemVer`는 prerelease 문자열도 형식상 허용하므로, "1.0.0" 강제는
   포맷 검사가 아니라 **명시적 동등 비교**로 하세요.)
- transcript는 `(challenge_id, nonce_raw, agent_id, key_id, protocol_version,
  tenant_id, server_origin)`로 재구성 (`build_transcript`). `tenant_id`와
  `server_origin`은 **off-wire** — 페어링 레코드/엔드포인트에서 재구성하고 절대 `hello`에서
  읽지 않습니다. (주의: `docs/c2-auth-integration-brief.md`의 "hello가 tenant_id를
  담는다"는 서술은 **오기**입니다 — 따르지 마세요.)
- `server_origin`은 **경로 없는** canonical 오리진
  (`canonicalize_server_origin(<이 엔드포인트가 서빙되는 URL>)`). **프로덕션 형태는
  `wss://` + 소문자 DNS 이름, 기본 포트·경로 없음** (예: `wss://relay.example.com`).
  frozen canonicalizer는 non-loopback 원시 IP(`ws://100.120.25.112:8004` 등)를
  거부합니다 — 그건 dev 전용 완화(`allowDevOrigin`)에서만 허용됩니다. WS **경로**
  (`/api/v1/hugin-agents/connect`)는 다이얼에만 쓰고 transcript 오리진에는 넣지 마세요.
- 프레이밍(봉투 유무)은 transcript 바이트에 영향을 주지 않으므로, 프레임만 평면으로
  바꾸면 기존 서명 검증 로직은 그대로 동작합니다.

---

## 7. 검수 기준 (Acceptance criteria)

1. C2가 보내는 `auth.challenge`가 `protocol/v1/messages.ts`의 `AuthChallenge` 스키마를
   통과 (평면, `id`/`ts`/`server_time` 포함, 봉투 없음).
2. C2가 에이전트의 평면 `hello`를 파싱하고, 서명 검증 후 `hello.accepted`(성공) 또는
   `hello.rejected`(실패)를 **평면 프레임으로** 응답 — 어떤 경우에도 응답 없이 소켓만
   끊지 않음.
3. 실제 `hugind`가 페어링 후 `npm run hugind`로 붙었을 때 로그에 `handshake ok`가 찍히고
   heartbeat가 흐름.
4. (권장) C2 유닛테스트: `mock-relay/server.ts`의 `verifyHello()` 시퀀스와 동일하게,
   레포의 F4 테스트 벡터(`protocol/v1/test-vectors.json`) 또는 Python
   `selftest.py`로 왕복 검증.

---

## 8. 부록 — 이후 프레임들도 동일 규칙

핸드셰이크 이후 전 메시지(`heartbeat`, `job.assign`, `stream.event`, `stream.ack`,
`job.result`, `job.result.ack`, `approval.request/response`, `lease.*`,
`agent.draining` 등)도 **모두 같은 평면 규칙**을 따릅니다: 최상위 `{ id, ts, type, … }`,
봉투 없음. 스키마는 `protocol/v1/messages.ts`, 예시는 `mock-relay/server.ts`.
