# Commit Message Format Guide

TC8 / SOME/IP 컨포먼스 하네스 프로젝트의 커밋 메시지 규칙.

## Structure

```
<type>(<scope>): <subject>

- <detail 1>
- <detail 2>
- <detail 3>
```

## Rules

### 1. Subject Line
- Format: `<type>(<scope>): <subject>` — scope 는 선택
- Types: `feat`, `refactor`, `fix`, `docs`, `test`, `chore`, `build`, `perf`
- Subject: 변경을 명확하고 간결하게 기술
- 마침표 없음
- 최대 72자

### 2. Body
- Subject 아래 빈 줄 1개
- 불릿 (`- ` prefix) 만 사용 — 산문 리드 문단 금지
- **불릿 1개 = 1줄, `- ` 포함 최대 72 bytes** — 연속/wrap 줄 금지.
  안 들어가면 더 짧게 쓰거나 별도 불릿으로 분리
- 불릿은 **연속** — 불릿 사이 빈 줄 금지
- **1-3개** — 핵심 변경에 집중 (4번째 불릿은 거부; 적을수록 좋음)
- commit-msg 훅이 위 규칙을 전부 강제 (위반 시 커밋 거부)
- 확인: `git log -1 --format=%B | awk '{print length, $0}'`
- 구체적이고 기술적으로
- 해당되는 경우 스펙 섹션 참조:
  - TC8 v3.0: `TC8 §4.8`, `TC8 SOMEIP_ETS_42`, `TC8 ARP_01`
  - SOME/IP: `SOME/IP Server FORMAT`, `SOME/IP-SD OPTIONS`
  - W3C SCXML (SCE 통합 코드): `W3C SCXML 3.12.1`
  - RFC 인용: `RFC 826 (ARP)`, `RFC 793 (TCP)`

### 3. Style
- **이모지 금지**
- **"Generated with Claude Code" 금지**
- **"Co-Authored-By" 태그 금지**
- 전문적이고 기술적인 톤
- "what" 과 "why" 에 집중, "how" 는 코드가 말하게

## Type Guidelines

| Type | 사용 시점 | 예시 |
|------|----------|------|
| `feat` | 새 기능 / 케이퍼빌리티 | Add BPF filter builder, Implement SOME/IP-SD Subscribe verdict |
| `refactor` | 동작 변경 없는 구조 개선 | Extract pcap thread manager, Unify dissect error paths |
| `fix` | 버그 수정 | Fix TLV alignment on 32-bit, Correct SD entry length parse |
| `docs` | 문서 변경 | Update tc8-harness-plan.md, Revise README scope |
| `test` | 테스트 추가 / 수정 | Add ETS_42 happy path SCXML, Cover TCP FLAGS_INVALID |
| `chore` | 빌드/툴링/의존성 | Update vsomeip submodule, Bump CommonAPI-SomeIP to 3.2.x |
| `build` | CMake / 링크 / 패키징 | Wire find_package(PCAP), Fix libtins include path |
| `perf` | 성능 개선 | Reduce dissect allocation, In-kernel BPF prefilter |

## Scope Guidelines (선택)

프로젝트 구조에 맞춘 scope — `src/` 하위 디렉터리 또는 논리 계층:

| Scope | 대상 |
|-------|------|
| `capture` | libpcap 래퍼, BPF 필터, 캡처 스레드 |
| `dissect` | Ethernet/IP/UDP, SOME/IP 헤더, CommonAPI InputStream 브리지 |
| `stimulus` | vsomeip 클라이언트, 스티뮬러스 송출 |
| `sce` | SCE 통합, event injector, result collector |
| `tests` | SCXML 테스트 케이스, FIDL/FDEPL 정의 |
| `deploy` | harness_config.yaml, fdepl, fidl |
| `report` | JUnit XML / 리포트 템플릿 |
| `cmake` | 빌드 시스템 |

## Examples

### Good: Capture 계층 기능 추가
```
feat(capture): Add BPF filter for SOME/IP port range

- Compile portrange 30490-30500 BPF (udp + tcp) in-kernel
- Expose port range via harness_config.yaml (TC8 §4.6/§4.8)
- Drop non-SOME/IP frames before user-space to cut CPU by ~60%
```

### Good: Dissect 계층 리팩터
```
refactor(dissect): Unify SOME/IP header parse with CommonAPI bridge

- Extract SomeIpHeader decoder reused by capture and stimulus paths
- Route payload to CommonAPI InputStream via single dispatch table
- Eliminate 80+ LOC duplication across service entries
```

### Good: SCE 통합 기능
```
feat(sce): Wire captured SOME/IP events into raiseExternalEvent

- Serialize CommonAPI struct to JSON for `_event.data.field_x` access
- Map service_id/method_id/session_id to SCXML event name convention
- First end-to-end happy path, Service A (TC8 SOMEIP_ETS_1)
```

### Good: 테스트 케이스 추가
```
test(tests): Add ETS_42 timeout + malformed failure cases

- Cover deadline_exceeded via a `<send>` timer race (plan §9)
- Add malformed TLV fixture for SOME/IP Server FORMAT assertion
- All 3 verdicts (pass/fail_timeout/fail_field) emit donedata
```

### Good: 버그 수정
```
fix(dissect): Correct SOME/IP-SD entry length on 32-bit align

- Mask lower 2 bits per SOME/IP-SD OPTIONS spec before offset calc
- Guard against truncated SD entries that crashed capture thread
- Regression test replays captured pcap from DUT vendor lab
```

### Good: 빌드 시스템
```
build(cmake): Link libpcap + CommonAPI-SomeIP + SCE

- Add find_package entries for PCAP, CommonAPI-SomeIP, SCE
- Freeze vsomeip to tag specified in contract (plan §11 risk)
- tc8-harness binary + cap_net_raw setcap hint at install
```

### Good: 간결 (1-2 항목으로 충분할 때)
```
refactor(sce): Extract ResultCollector from harness_main

- Move DoneData JSON aggregation into dedicated collector class
- Unblock JUnit XML reporter reuse across parallel capture threads
```

### Bad: 항목 과다
```
feat(dissect): Add SOME/IP support

- Add header parser
- Add SD parser
- Add TLV decoder
- Add CommonAPI bridge
- Update tests
- Update docs
- Update CMake
```
**문제**: 7개 항목 — 핵심 3개로 응축해야 함

### Bad: 불릿이 길어 줄바꿈 (wrap)
```
feat(sce): Wire captured events into raiseExternalEvent

- Serialize the CommonAPI struct to JSON so SCXML can read
  `_event.data.field_x` from the captured payload
```
**문제**: 불릿 1개가 72 bytes를 넘겨 2줄로 이어짐 (들여쓰기 연속줄).
규칙은 불릿 1개 = 1줄 ≤72 bytes. 더 짧게:
```
- Serialize CommonAPI struct → JSON for `_event.data.x`
```

### Bad: 너무 모호
```
refactor: Improve code

- Update files
- Fix issues
- Add features
```
**문제**: 무엇을 왜 개선했는지 불명확

## Common Mistakes to Avoid

### Bad: 이모지 + 귀속 태그
```
refactor(capture): Add pcap thread manager

- Add PcapCapture class
- Handle BPF compile errors
...

Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>
```
**문제**:
1. "Generated with Claude Code" 푸터
2. "Co-Authored-By" 태그
3. 일반 이모지 사용

### Good: 깔끔하고 전문적
```
refactor(capture): Introduce PcapCapture with BPF lifecycle

- RAII-wrap pcap_open_live/compile/setfilter in one class
- Surface BPF compile errors with the filter expr for ops
- Replace ad-hoc harness_main loop with a worker thread
```
**개선점**:
1. 이모지 / 귀속 태그 없음
2. 3개 핵심 변경으로 응축
3. 각 불릿이 구체적이고 기술적
4. 전문적 톤 유지

## Quick Reference

- `feat(<scope>)` / `refactor(<scope>)` / `fix(<scope>)` / `test(<scope>)` / `docs` / `chore` / `build` / `perf`
- Scope: `capture` | `dissect` | `stimulus` | `sce` | `tests` | `deploy` | `report` | `cmake`
- Body: 1-3 bullets, 각 1줄 ≤72 bytes, 연속 (wrap/빈 줄 금지), 구체적
- 참조: `TC8 §X`, `TC8 SOMEIP_ETS_N`, `SOME/IP-SD ...`, `W3C SCXML X.Y`, `RFC NNNN`
- 금지: 이모지, `Generated with Claude Code`, `Co-Authored-By`
