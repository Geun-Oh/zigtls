# zigtls Production Completion Task Specification (Strict)

## 1. 목표
이 문서는 zigtls를 **실제 프로덕션 환경에서 운영 가능한 수준**으로 끌어올리기 위한 최종 구현 작업 정의서다.

최종 목표:
- TLS 1.3 기준의 명확한 프로덕션 타깃 프로파일에서 기능/보안/운영 검증이 모두 닫힌 상태
- BoGo/interop/fuzz/성능/운영 문서가 릴리즈 게이트로 일관되게 연결된 상태
- `allow-unimplemented`에 의존하지 않는 엄격한 검증 경로 확보

---

## 2. 프로덕션 타깃 프로파일 (v1-prod)

### 2.1 범위 (MUST)
- TLS 1.3 only
- TCP 기반 client/server
- Sans-I/O 코어
- 필수 cipher suite:
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
- HRR, KeyUpdate, PSK resumption, 0-RTT(기본 off + 정책 강제)
- X.509 경로 검증 핵심 체크 + OCSP 정책

### 2.2 비범위 (v1-prod에서 명시적 제외)
- TLS 1.2
- DTLS
- QUIC glue
- PAKE

### 2.3 핵심 원칙
- 비범위 항목은 문서/게이트에서 명시적으로 분리한다.
- 범위 내 항목은 `unimplemented/skip` 없이 엄격 검증을 통과해야 한다.

---

## 3. 현재 갭 정의 (BoGo/Interop 중심)

현재 BoGo 실행은 `-allow-unimplemented` 모드에서만 실질 통과한다.
이는 다음을 의미한다:
- 전체 runner 관점에서 미구현 케이스가 대량 존재
- 현재 수준은 "검증 인프라 확보" 단계이며, "엄격 프로덕션 closure" 단계는 아님

따라서 해야 할 일:
1. **프로파일 기반 테스트 분리**: v1-prod 범위 외 케이스를 정책적으로 제외
2. **프로파일 내 strict pass**: 범위 내 케이스는 `PASS` 또는 명시적 기대치와 일치
3. `allow-unimplemented=0` 경로에서 gate를 통과하도록 BoGo harness 고도화

---

## 4. 구현 워크스트림

## WS-A. BoGo Strict Profile 정립

### A1. BoGo 테스트 분류 체계 도입 (MUST)
- 각 BoGo 테스트를 다음으로 분류:
  - `in_scope_required`
  - `in_scope_optional`
  - `out_of_scope`
- 분류 산출물:
  - `docs/bogo-profile-v1-prod.md`
  - `scripts/interop/bogo_profile_v1_prod.json` (또는 TOML)

완료 기준:
- 분류 기준이 문서화되어 리뷰 가능
- 임의 샘플 테스트명 100개 이상에 대해 분류 재현 가능

### A2. Runner 필터링/평가 로직 구현 (MUST)
- `bogo_run.sh`에 profile 입력 옵션 추가:
  - `BOGO_PROFILE=<file>`
  - `BOGO_STRICT=1`
- `out_of_scope`는 실행 제외 또는 별도 집계
- `in_scope_required`는 `PASS` 외 실패 금지

완료 기준:
- profile 기반 결과 요약이 자동 출력
- `in_scope_required` 실패 시 non-zero exit

### A3. Summary 스키마 표준화 (MUST)
- `bogo_summary.py` 출력 스키마 고정:
  - total/pass/fail/skip
  - in_scope_required pass/fail
  - critical_failure_count
  - out_of_scope_count
- 구버전/신버전 JSON 포맷 모두 지원 유지

완료 기준:
- self-test + golden fixture 테스트 통과

---

## WS-B. BoGo In-Scope 기능 결손 해소

### B1. TLS 1.3 핵심 핸드셰이크 결손 해소 (MUST)
- 현재 shim 수준이 아닌 실제 엔진 경로로 BoGo in-scope 케이스 흡수
- 최소 대상군:
  - basic TLS1.3 handshake variants
  - HRR variants
  - KeyUpdate variants
  - Resumption(PSK) 핵심 variants
  - Alert/close_notify 핵심 variants

완료 기준:
- `in_scope_required` 항목에서 `unimplemented/unsupported` 0건

### B2. 인증서/검증 관련 in-scope 결손 해소 (MUST)
- 서버 인증서 체인/usage/hostname/OCSP 정책 관련 in-scope 케이스 처리
- certificate selection/issuer 매칭은 v1 범위에 맞게 명확히 제한하거나 구현

완료 기준:
- in-scope certificate 계열 테스트 실패 0건

### B3. 0-RTT/Resumption 정책 완성도 강화 (MUST)
- anti-replay 정책/윈도우/idempotency 관련 음수 케이스 확장
- 재현 가능한 replay corpus 추가

완료 기준:
- 관련 regression test 추가 + gate 통과

---

## WS-C. Interop Strict Closure

### C1. 로컬 matrix 확장 (MUST)
- OpenSSL/rustls/NSS matrix를 strict 모드로 운영
- 환경별 버전과 실행 옵션 고정 문서화

완료 기준:
- `scripts/interop/matrix_local.sh --strict` 성공
- 아티팩트 저장 경로 표준화

### C2. 외부 환경 재현성 (MUST)
- CI 또는 재현 가능한 컨테이너 스크립트 제공
- 설치/빌드/실행 전 과정을 한 번에 수행

완료 기준:
- 신규 환경에서 단일 명령으로 interop evidence 생성

---

## WS-D. 보안 보증 심화

### D1. Timing harness 추가 (MUST)
- 비밀 의존 경로(verify/compare/key schedule) 측정 하네스 작성
- 통계 기반 임계치(분포 차이) 정의

완료 기준:
- `docs/side-channel-review.md`가 정성 리뷰 + 정량 결과 포함으로 갱신

### D2. 정책 동등성 갭 축소 (SHOULD)
- 플랫폼 trust policy와 차이점 테스트셋 작성
- 차이점별 처리 정책(구현/명시적 제한) 결정

완료 기준:
- RA-001 재평가 자료 완비

---

## WS-E. 성능/운영 준비

### E1. 성능 게이트 고도화 (MUST)
- 현재 perf probe를 지표화:
  - handshake latency P50/P95/P99
  - suite별 throughput
  - connection memory ceiling
- 릴리즈 기준선 대비 회귀 임계치 정의

완료 기준:
- `scripts/benchmark/run_local_perf.sh --assert` 지원
- 회귀 시 non-zero exit

### E2. 운영 런북 완성 (MUST)
- 장애 탐지/완화/롤백/사후분석 체크리스트 강화
- 실제 rehearsal 결과 정기 반영

완료 기준:
- 릴리즈 전 rehearsal evidence 필수

---

## 5. 테스트/검증 게이트 정의

## 5.1 필수 게이트 명령 (MUST)
```bash
zig build test
zig test tools/bogo_shim.zig
python3 scripts/interop/bogo_summary.py --self-test
bash scripts/interop/matrix_local.sh --self-test
bash scripts/fuzz/replay_corpus.sh --self-test
bash scripts/benchmark/run_local_perf.sh
```

## 5.2 프로덕션 릴리즈 전 필수 게이트 (MUST)
```bash
# strict interop
bash scripts/interop/matrix_local.sh --strict

# strict BoGo (allow-unimplemented 금지)
BOGO_PROFILE=scripts/interop/bogo_profile_v1_prod.json \
BOGO_STRICT=1 \
BOGO_ALLOW_UNIMPLEMENTED=0 \
BORINGSSL_DIR=<path> \
bash scripts/interop/bogo_run.sh

# fuzz regression replay
bash scripts/fuzz/replay_corpus.sh --skip-baseline
```

---

## 6. 산출물 (Deliverables)
- `docs/bogo-profile-v1-prod.md`
- `scripts/interop/bogo_profile_v1_prod.json` (or toml)
- strict BoGo/interop 실행 결과 리포트 문서
- timing harness 코드 + 결과 문서
- 성능 회귀 임계치 문서/스크립트
- 갱신된 risk acceptance 및 release signoff 문서

---

## 7. DoD (완료 정의)
아래 조건을 모두 만족해야 "프로덕션 가능"으로 판정한다.

1. v1-prod 범위가 문서/스크립트/게이트에 동일하게 반영됨
2. BoGo v1-prod in-scope required 케이스에서 fail/unimplemented 0건
3. interop strict matrix 통과
4. fuzz/regression gate 안정 통과
5. 보안 문서(특히 timing evidence) 최신화
6. 성능 회귀 임계치 기반 gate 통과
7. RA 문서의 open 항목이 릴리즈 승인 가능한 수준으로 축소/정당화됨

