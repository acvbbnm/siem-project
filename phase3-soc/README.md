# Phase 3. 관제 운영 (SOC 시뮬레이션)

> mng-mint에서 실시간 모니터링 → 경보 대응 → 차단 검증 → 보고

---

## 모니터링 체계 구축

### Splunk 대시보드

Settings > Searches, reports and alerts > New Dashboard

**패널 구성:**

| 패널 | 쿼리 | 시각화 |
|------|------|--------|
| 실시간 이벤트 수 | `index=pfsense \| timechart span=1m count` | 라인 차트 |
| 공격자 IP Top 5 | `index=pfsense \| top 5 src` | 바 차트 |
| 공격 유형 분포 | `index=pfsense \| top 10 signature` | 파이 차트 |
| 최근 경보 목록 | `index=pfsense "ALERT" \| table _time src dest signature` | 테이블 |

**대시보드 캡처:**
> (실습 후 캡처)

### Splunk Alert 설정

Settings > Searches, reports and alerts > New Alert

| 알림 이름 | 조건 | 액션 |
|----------|------|------|
| 포트 스캔 탐지 | 1분 내 동일 src에서 50회 이상 이벤트 | 로그 기록 |
| 반복 공격 탐지 | 5분 내 동일 src에서 "ALERT" 10회 이상 | 로그 기록 |
| SQLi 탐지 | "SQL Injection" 키워드 포함 이벤트 발생 | 로그 기록 |

```spl
# 포트 스캔 탐지 쿼리
index=pfsense | stats count by src | where count > 50

# 반복 공격 탐지 쿼리
index=pfsense "ALERT" | stats count by src | where count > 10
```

---

## 관제 대응 프로세스

### 전체 흐름

```
경보 발생 (Splunk Alert / Snort Alert)
    │
    ▼
[1단계] 경보 분류 (Triage)
    │  Q1. 오탐(False Positive)인가?
    │  Q2. 이미 알려진/처리된 건인가?
    │  Q3. 위험도는? (상/중/하)
    │
    ▼
[2단계] 상세 분석 (Analysis)
    │  - 공격자 IP / 대상 / 공격 유형 확인
    │  - 공격 페이로드 내용 확인
    │  - HTTP 응답코드로 공격 성공 여부 판단
    │  - 동일 공격자의 과거 이력 조회
    │
    ▼
[3단계] 대응 조치 (Response)
    │  - 위험도 상: 즉시 IP 차단 (pfSense)
    │  - 위험도 중: Snort 차단 모드로 자동 대응
    │  - 위험도 하: 모니터링 지속, 일지 기록
    │
    ▼
[4단계] 차단 검증 (Verification)
    │  - att-mint에서 동일 공격 재시도
    │  - 접속 불가 / Snort 차단 로그 확인
    │  - Splunk에서 차단 이벤트 확인
    │
    ▼
[5단계] 보고 (Reporting)
    - 관제 일지에 기록 (incident-log.md)
    - 관제 보고서 작성
```

### 오탐 판별 기준

| 판별 항목 | 오탐 가능성 높음 | 실제 공격 가능성 높음 |
|----------|----------------|-------------------|
| 출발지 IP | 내부 관리 대역 (10.0.50.x) | 외부/공격자 대역 (10.50.50.x) |
| 패턴 | 단발성, 정상 요청과 유사 | 반복적, 알려진 공격 페이로드 포함 |
| 시간대 | 업무 시간, 단건 | 새벽/비정상 시간, 대량 |
| 페이로드 | 정상 파라미터 | SQL 구문, script 태그, 시스템 명령어 |

---

## 차단 검증 시나리오

### 검증 1: IP 차단 확인

**사전 조건:** Phase 2에서 10.50.50.17 차단 규칙 적용 완료

```bash
# att-mint에서 실행
curl -v http://10.0.0.254          # 기대: Connection refused / timeout
nmap -sS -p 80 10.0.0.254         # 기대: filtered
ping 10.0.0.254                    # 기대: 응답 없음
```

**결과:**
> (실습 후 기록)

### 검증 2: Snort 자동차단 확인

**사전 조건:** Phase 2에서 Snort Block Offenders 활성화 + 10.50.50.17 차단 해제

```bash
# att-mint에서 SQLi 공격 재시도
curl "http://10.0.0.254/bWAPP/sqli_1.php?title=%27%20OR%201%3D1--&action=search"
# 1회 요청 후 Snort가 자동 차단

# 차단 확인
curl -v http://10.0.0.254          # 기대: 접속 불가
```

pfSense에서 확인: Services > Snort > Blocked

**결과:**
> (실습 후 기록)

### 검증 3: 차단 해제 → 재공격 → 재차단

```
1. pfSense에서 10.50.50.17 차단 해제
2. att-mint에서 재공격 수행
3. Snort 자동차단 재동작 확인
4. Splunk에서 차단/허용 로그 비교
```

**결과:**
> (실습 후 기록)

---

## 관제 일지

> 상세 관제 일지는 [incident-log.md](incident-log.md)에 기록

### 기록 양식

```
## [INC-001] 포트 스캔 탐지

| 항목 | 내용 |
|------|------|
| 탐지 일시 | YYYY-MM-DD HH:MM |
| 경보 유형 | (Snort 시그니처명) |
| 공격자 IP | 10.50.50.17 |
| 대상 | 10.0.10.50:80 |
| 공격 내용 | (구체적 내용) |
| 위험도 | 상 / 중 / 하 |
| 오탐 여부 | 실제 공격 / 오탐 |
| 대응 조치 | (수행한 조치) |
| 검증 결과 | (차단 확인 결과) |
| 처리 상태 | 완료 / 모니터링 중 |
```
