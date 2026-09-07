# Phase 3. 관제 운영 (SOC 시뮬레이션)

> 이전 SOC 실습 양식·자료입니다. 최신 완료 상태와 정정 사항은 [Phase 4 품질 점검 기록](../phase4-soc/quality-audit.md)을 참고하세요.

> mng-mint에서 실시간 모니터링 → 경보 대응 → 차단 검증 → 보고
> Phase 2의 분석이 완료된 후 진행한다.

---

## 모니터링 체계 구축

### Step 1. Splunk 대시보드 생성

> SOC에서는 대시보드를 통해 실시간으로 공격 현황을 모니터링한다.
> 여기서는 Phase 1의 공격 데이터를 시각화하는 대시보드를 구축한다.

**생성 절차:**
1. Splunk 접속 (`http://10.0.100.50:8000`)
2. Dashboards > Create New Dashboard
3. Dashboard 이름: `SOC-공격현황` (Classic Dashboard 선택)
4. 아래 패널을 하나씩 추가 (Add Panel > New > Search)

#### 패널 1: 실시간 이벤트 추이

```spl
index=pfsense | timechart span=5m count
```
- Visualization: **Line Chart**
- 시간 범위: 전체 (All Time) 또는 Phase 1 공격 기간에 맞춤

#### 패널 2: 공격자 IP Top 5

```spl
index=pfsense snort | stats count by src | sort -count | head 5
```
- Visualization: **Bar Chart** (가로)

#### 패널 3: 공격 유형 분포

```spl
index=pfsense snort 10.50.50.17
| rex "snort\[\d+\]:\s+\[\S+\]\s+(?P<signature>[^\[]+)\s+\["
| top 10 signature
```
- Visualization: **Pie Chart**
- 필드 추출이 완료되었으면 `| top 10 signature`만으로 가능

#### 패널 4: 최근 경보 목록

```spl
index=pfsense snort 10.50.50.17
| rex "snort\[\d+\]:\s+\[\S+\]\s+(?P<signature>[^\[]+)\s+\["
| rex "\{TCP\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
| table _time src_ip dest_ip dest_port signature
| sort -_time
| head 20
```
- Visualization: **Statistics Table**

#### 패널 5: 공격 단계별 타임라인 (선택)

```spl
index=pfsense 10.50.50.17
| eval attack_phase=case(
    like(_raw, "%portscan%"), "R-1 PortScan",
    like(_raw, "%Sqlmap%") OR like(_raw, "%SQL%"), "E-1/E-2 SQLi",
    like(_raw, "%script%") OR like(_raw, "%XSS%"), "E-3 XSS",
    like(_raw, "%passwd%") OR like(_raw, "%traversal%"), "R-3/E-6 Traversal",
    like(_raw, "%htpasswd%") OR like(_raw, "%htaccess%"), "R-4 DirBrute",
    1=1, "기타"
  )
| timechart span=5m count by attack_phase
```
- Visualization: **Stacked Area Chart**
- 공격 단계별 색상 구분으로 "언제 무슨 공격이 있었는지" 한눈에 파악

**확인 포인트:**
- [ ] 대시보드 5개 패널 구성 완료
- [ ] 전체 대시보드 캡처 → `images/dashboard-overview.png`
- [ ] 각 패널 개별 캡처 (선택)

---

### Step 2. Splunk Alert 설정

> 대시보드는 "보는 것", Alert는 "알려주는 것". 임계치 기반으로 자동 경보를 설정한다.

**생성 절차:**
1. Settings > Searches, reports and alerts > New Alert
2. 아래 3개 Alert 생성

#### Alert 1: 포트 스캔 탐지

| 항목 | 설정 |
|------|------|
| 이름 | `[SOC] 포트 스캔 탐지` |
| 검색 | `index=pfsense "portscan" \| stats count by src \| where count > 3` |
| 스케줄 | Real-time 또는 Every 5 minutes |
| 트리거 | Number of Results > 0 |
| 액션 | Log event (또는 Send email — 실습에서는 Log만) |

#### Alert 2: 반복 공격 탐지

| 항목 | 설정 |
|------|------|
| 이름 | `[SOC] 반복 공격 탐지` |
| 검색 | `index=pfsense snort \| stats count by src \| where count > 10` |
| 스케줄 | Every 5 minutes |
| 트리거 | Number of Results > 0 |
| 설명 | 5분 내 동일 IP에서 Snort 경보 10건 이상 |

#### Alert 3: SQL Injection 탐지

| 항목 | 설정 |
|------|------|
| 이름 | `[SOC] SQL Injection 탐지` |
| 검색 | `index=pfsense "SQL Injection" OR "Sqlmap"` |
| 스케줄 | Real-time |
| 트리거 | Number of Results > 0 |
| 설명 | SQLi 관련 시그니처 즉시 알림 |

**확인 포인트:**
- [ ] 3개 Alert 생성 완료
- [ ] Alert 목록 캡처 → `images/splunk-alerts.png`
- [ ] (선택) Phase 3 검증 시 Alert가 실제로 트리거되는지 확인

---

## 관제 대응 프로세스

> SOC 관제의 핵심은 **경보 → 분류 → 분석 → 대응 → 검증 → 보고**의 반복이다.
> 아래는 이 실습 환경에서의 구체적 절차.

### 전체 흐름

```
경보 발생 (Splunk Alert / Snort Alert / 대시보드 이상 탐지)
    │
    ▼
[1단계] 경보 분류 (Triage) ─────────── 5분 이내
    │  Q1. 오탐(False Positive)인가?
    │  Q2. 이미 처리된 건인가? (중복 확인)
    │  Q3. 위험도는? (상/중/하)
    │  → 위험도 상: 즉시 2단계로
    │  → 오탐 판단: 사유 기록 후 종료
    │
    ▼
[2단계] 상세 분석 (Analysis) ─────── 15분 이내
    │  - 공격자 IP / 출발지 국가 / 대상 자산 확인
    │  - 공격 페이로드 원문 확인 (Splunk raw 이벤트)
    │  - HTTP 응답코드로 공격 성공 여부 판단
    │    → 200 + SQL 에러 = 성공, 403/차단 = 실패
    │  - 동일 공격자의 과거 이력 조회
    │    → `index=pfsense src=<IP> | stats count by signature`
    │  - 이 공격이 어떤 취약점을 노리는지 (OWASP 매핑)
    │
    ▼
[3단계] 대응 조치 (Response) ─────── 즉시
    │  위험도 상 (Critical/High):
    │    → 즉시 IP 차단 (pfSense WAN Block)
    │    → Snort Block Offenders 확인
    │    → 관제 일지 [INC-xxx] 작성
    │  위험도 중 (Medium):
    │    → Snort 자동차단 모드에서 자동 대응
    │    → 모니터링 강화 (대시보드 주시)
    │    → 관제 일지 기록
    │  위험도 하 (Low/Info):
    │    → 모니터링 지속
    │    → 일지에 참고 기록
    │
    ▼
[4단계] 차단 검증 (Verification) ── 대응 직후
    │  - att-mint에서 동일 공격 재시도
    │  - 접속 불가(timeout/refused) 확인
    │  - pfSense에서 차단 로그 / Snort Blocked 목록 확인
    │  - Splunk에서 차단 이후 이벤트 0건 확인
    │
    ▼
[5단계] 보고 (Reporting)
    - 관제 일지(incident-log.md)에 전체 과정 기록
    - 최종 보고서에 포함
```

### 오탐/정탐 판별 기준

| 판별 항목 | 오탐 가능성 높음 | 실제 공격 가능성 높음 |
|----------|----------------|-------------------|
| 출발지 IP | 내부 관리 대역 (10.0.50.x, 10.0.100.x) | 외부/공격자 대역 (10.50.50.x) |
| 패턴 | 단발성, 정상 요청과 유사 | 반복적, 알려진 공격 페이로드 포함 |
| 시간대 | 업무 시간, 단건 | 새벽/비정상 시간, 대량 |
| 페이로드 | 정상 파라미터, 일반 URL | SQL 구문(`'OR`, `UNION`), `<script>`, `; whoami`, `../` |
| 빈도 | 분당 1~2건 | 분당 수십~수백건 (자동화 도구) |
| 도구 흔적 | 일반 브라우저 User-Agent | sqlmap, nikto, hydra 등 도구 UA |

### 이 실습에서의 오탐/정탐 예시

| 이벤트 | 판정 | 근거 |
|--------|------|------|
| R-3 nikto의 `ET WEB_SERVER /etc/passwd` | **정탐** | nikto 자동 스캔이 실제 경로 접근 시도 |
| `ntpd: error resolving pool` | **오탐(무관)** | pfSense NTP 클라이언트 정상 동작, 공격 아님 |
| R-1 sfPortscan | **정탐** | 1000개 포트 SYN 스캔 = 명백한 정찰 |
| E-4 Stored XSS | **미탐지** | 공격은 성공했지만 IPS가 탐지 못함 → "탐지되지 않은 위협" |

---

## 차단 검증 시나리오

> **선행:** 각 검증은 Phase 2의 [대응 규칙 적용/해제 순서](../phase2-detect/README.md#대응-규칙-적용해제-순서-중요)를 따른다.
> 검증 1 → 순번 ②, 검증 2 → 순번 ④, 검증 3 → 순번 ⑤ 상태에서 수행한다.
> (특히 검증 2는 2차 "WAN 전체 차단"이 **OFF**인 상태여야 Snort 자동차단을 확인할 수 있다.)

### 검증 1: IP 차단 확인

**사전 조건:** Phase 2 순번 ② — 10.50.50.17 WAN Block 규칙만 적용된 상태

**att-mint 터미널에서 실행:**
```bash
# HTTP 접속 시도
curl -v --connect-timeout 5 http://10.0.0.254
# 기대: Connection timed out 또는 Connection refused

# 포트 스캔
sudo nmap -sS -Pn -p 80 10.0.0.254
# 기대: filtered (방화벽이 드롭)

# ping (원래 안 되지만 일관성 위해)
ping -c 3 10.0.0.254
# 기대: 응답 없음
```

**확인 포인트:**
- [ ] curl → timeout/refused 확인
- [ ] nmap → filtered 확인
- [ ] 캡처: 차단 결과 → `images/verify-ip-block.png`
- [ ] Splunk에서 차단 이후 이벤트 0건 확인

**결과:**
> (실습 후 기록)

### 검증 2: Snort 자동차단 확인

**사전 조건:** Phase 2 순번 ④ — Snort Block Offenders **ON**, 1차 IP Block **OFF**, 2차 WAN 전체차단 **OFF**

**att-mint에서 SQLi 공격 재시도:**
```bash
# SQLi 공격 — Snort가 탐지하면 자동 차단
curl "http://10.0.0.254/bWAPP/sqli_1.php?title=%27%20OR%201%3D1--&action=search" \
  --cookie "PHPSESSID=<세션값>;security_level=0"

# 잠시 대기 (Snort 처리 시간)
sleep 3

# 차단 확인 — 이제 접속 불가
curl -v --connect-timeout 5 http://10.0.0.254
# 기대: Connection timed out (Snort가 IP를 차단)
```

**pfSense에서 확인:**
1. Services > Snort > Blocked
2. `10.50.50.17`이 Blocked 목록에 있는지 확인
3. 캡처 → `images/snort-blocked-list.png`

**확인 포인트:**
- [ ] 1회 SQLi 요청 후 자동 차단 발동
- [ ] pfSense Snort Blocked 목록에 `10.50.50.17` 표시
- [ ] curl 재시도 시 접속 불가 확인
- [ ] 캡처 → `images/verify-snort-block.png`

**결과:**
> (실습 후 기록)

### 검증 3: 차단 해제 → 재공격 → 재차단

**절차:**
1. pfSense > Services > Snort > Blocked > `10.50.50.17` 옆 **해제(Remove)** 클릭
2. att-mint에서 재공격:
   ```bash
   # 해제 후 접속 복원 확인
   curl -I http://10.0.0.254
   # 기대: HTTP 200

   # 재공격 — nikto 짧게 실행
   nikto -h http://10.0.0.254 -maxtime 30s

   # 재차단 확인
   curl -v --connect-timeout 5 http://10.0.0.254
   # 기대: 다시 차단
   ```
3. pfSense Blocked 목록에 다시 `10.50.50.17` 등장 확인

**확인 포인트:**
- [ ] 해제 후 접속 복원 확인
- [ ] 재공격 시 Snort가 다시 자동 차단
- [ ] "탐지 → 차단 → 해제 → 재탐지 → 재차단" 사이클 완성
- [ ] 캡처 → `images/verify-reblock.png`

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
| 탐지 일시 | 2026-08-03 19:50 KST |
| 경보 유형 | [122:5:1] sfPortscan: TCP Filtered Portscan |
| 공격자 IP | 10.50.50.17 |
| 대상 | 10.0.0.254 (pfSense WAN → Bee-box) |
| 공격 내용 | 1000개 포트 TCP SYN 스캔 (nmap -sS) |
| 위험도 | 중 (정찰 단계, 직접 피해 없음) |
| 오탐 여부 | 정탐 — 동일 IP에서 후속 공격(SQLi, XSS) 연계 확인 |
| 대응 조치 | Phase 2 1차 대응(IP 차단) 예정 |
| 검증 결과 | (Phase 3에서 기록) |
| 처리 상태 | 모니터링 중 → (차단 후 완료 처리) |
```

### 예상 인시던트 목록

| INC # | 공격 | Snort 시그니처 | 위험도 | 비고 |
|-------|------|--------------|--------|------|
| INC-001 | R-1 포트스캔 | sfPortscan | 중 | 정찰, 후속 공격 연계 |
| INC-002 | R-3 nikto 스캔 | ET WEB_SERVER 다수 | 중 | 868건, 자동 스캐너 |
| INC-003 | R-4 dirb 스캔 | GPL WEB_SERVER | 중 | 민감 파일 탐색 |
| INC-004 | E-1 SQLi (수동) | SELECT USER SQL Injection | **상** | DB 데이터 유출 확인 |
| INC-005 | E-2 SQLi (sqlmap) | ET SCAN Sqlmap | **상** | 211건, 자동화 도구 |
| INC-006 | E-3 Reflected XSS | Script tag in URI | 중 | 쿠키 탈취 가능 |
| INC-007 | E-4 Stored XSS | — | **상** | **IPS 미탐지**, 다수 피해 |
| INC-008 | E-5 Command Injection | (실습 후 확인) | **상** | 서버 장악 가능 |
| INC-009 | E-7 Brute Force | (실습 후 확인) | 중 | 계정 탈취 |

---

## 최종 보고서 작성

> Phase 1~3 전체를 취합하여 제출용 보고서를 작성한다.

### 보고서 구성 (안)

```
1. 개요
   - 프로젝트 목적
   - 실습 환경 (인프라 토폴로지)
   - 실습 기간

2. 공격 수행 결과 (Phase 1)
   - 정찰 단계 요약 (R-1~R-4)
   - 웹 공격 단계 요약 (E-1~E-7)
   - 공격별 성공/탐지 여부 매트릭스

3. 탐지/분석 결과 (Phase 2)
   - Snort IPS 탐지 현황
   - Splunk 로그 분석 결과
   - 공격 유형별·시간대별 분포
   - 탐지 실패 분석 (Stored XSS 등)

4. 방어 대응 (Phase 2~3)
   - 방화벽 정책 (1~3차 대응)
   - Snort 자동차단 설정
   - 차단 검증 결과

5. 관제 운영 (Phase 3)
   - 대시보드·Alert 구축
   - 관제 대응 프로세스
   - 인시던트 일지 요약

6. 결론 및 개선 권고
   - 발견된 취약점 요약 (V-01~V-08)
   - IPS 한계점 및 보완 방안
   - 다층 방어(Defense in Depth) 권고
```

> `/phase-report` 스킬로 자동 생성 가능
