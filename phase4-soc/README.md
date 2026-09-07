# Phase 4 — 관제 운영 (SOC 시뮬레이션)

> 확장된 인프라에서 경보분류 → 분석 → 대응 → 검증 사이클 수행

---

## Step 1. 모니터링 체계 구축

### Splunk 대시보드 (SOC_Monitor) ✅

**대시보드 구성 (8개 패널, 3단 레이아웃):**

**상단 — 핵심 지표:**

| 패널 | 유형 | SPL 쿼리 | 결과 |
|------|------|---------|------|
| events (실시간 이벤트 수) | Single Value | `index=pfsense OR index=idx_web OR index=idx_waf OR index=idx_db \| stats count` | **80,425건** |
| time (시간대별 추이) | Line Chart | `index=pfsense OR index=idx_waf \| timechart span=1h count by index` | pfsense 추이 표시 |
| att_type (공격 유형 분포) | Pie Chart | `index=pfsense "Priority" \| rex "\\[\\d+:\\d+:\\d+\\]\\s+(?P<signature>[^\\[]+?)\\s+\\[" \| top 10 signature` | ET POLICY, SQL Injection 등 6종 |

**중단 — IP/WAF 분석:**

| 패널 | 유형 | SPL 쿼리 | 결과 |
|------|------|---------|------|
| att_ip (공격자 IP Top5) | Bar Chart | `index=pfsense "Priority" \| rex "\\{(?P<proto>\\w+)\\}\\s+(?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" \| top 5 src_ip` | 10.0.0.254 (NAT), 10.50.50.30 (공격자) |
| waf (WAF 탐지 현황) | Bar Chart | `index=idx_web "ModSecurity" \| rex "id\\"(?P<rule_id>\\d+)\\"" \| stats count by rule_id` | rule_id별 분포 (idx_web에서 531건) |

**하단 — 상세 로그:**

| 패널 | 유형 | SPL 쿼리 | 결과 |
|------|------|---------|------|
| db_approach (DB 접근 로그) | Statistics Table | `index=idx_db host=mysql \| head 20 \| table _time host source _raw` | MySQL DNS resolution warning 347건 |
| alerts (최근 경보) | Statistics Table | `index=pfsense "Priority" \| rex "\\[\\d+:\\d+:\\d+\\]\\s+(?P<signature>[^\\[]+?)\\s+\\[" \| rex "\\{(?P<proto>\\w+)\\}\\s+(?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+):?\\d*\\s+->\\s+(?P<dest_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" \| head 20 \| table _time src_ip dest_ip signature` | Snort 경보 + signature 추출 |
| login_history (로그인 시도) | Statistics Table | `index=idx_web "wp-login" \| rex "client\\s+(?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" \| stats count by src_ip` | 10.50.50.30: 255건 (공격), 10.0.50.100: 1건 (정상) |

> **참고:** idx_waf 인덱스는 비어있음 (0건). ModSecurity WAF 로그는 idx_web에 혼합 수집됨 (rsyslog 경유, sourcetype=syslog).
> 대시보드에서 WAF 패널은 `index=idx_web "ModSecurity"` 기반으로 구성.

---

### Splunk Alert 설정 (5개) ✅

Phase 3 실제 탐지 데이터를 근거로 Alert 쿼리 및 임계값 설정:

| Alert 이름 | SPL 쿼리 | Cron | Time Range | Severity | 근거 (Phase 3 실제 탐지) |
|-----------|---------|------|------------|----------|----------------------|
| Brute Force Detection | `index=idx_web "wp-login.php" "POST" \| stats count \| where count >= 10` | `*/5 * * * *` | 5분 | High | 상관분석1: Apache 317건 (Snort 8건보다 탐지력 우수) |
| Scanner Detection | `index=pfsense "1000001" \| stats count \| where count >= 10` | `*/5 * * * *` | 5분 | High | SID 1000001: WPScan 1,973건 탐지 확인 |
| SQL Injection Detection | `index=pfsense ("SQL" OR "1000004") "Priority" \| stats count \| where count >= 2` | `*/5 * * * *` | 5분 | Critical | 상관분석2: ET 18건 + 커스텀 3건 = 21건 |
| Webshell Detection | `index=idx_web "cmd=" \| stats count \| where count >= 1` | `*/5 * * * *` | 5분 | Critical | 상관분석3: Apache cmd= 37건 (Snort 17건보다 탐지력 우수) |
| WAF Alert Surge | `index=idx_web "ModSecurity" \| stats count \| where count >= 30` | `*/10 * * * *` | 10분 | Medium | idx_web ModSecurity 531건 확인 |

> **Alert 설계 원칙:**
> - 브루트포스, 웹쉘은 **Apache 로그(idx_web) 기반** — Snort에서 놓치는 행위까지 탐지
> - SQLi, 스캐너는 **Snort 경보(pfsense) 기반** — 네트워크 레벨 시그니처 탐지
> - WAF는 **idx_web 내 ModSecurity 로그** — idx_waf 인덱스 비어있어 idx_web에서 탐지
> - 임계값은 Phase 3 킬체인 공격 실제 탐지 건수 기준으로 설정
> - 모든 Alert Action: Log Event (Splunk 내부 기록)

---

## Step 2. 관제 대응 프로세스

### 경보 분류 (Triage)

```
[경보 수신] → 정탐/오탐 판별 → 위험도 산정 → 대응 수준 결정
                   │                    │              │
              중복 경보?           CVSS 기준        L1: 모니터링
              알려진 오탐?         영향도×가능성     L2: IP 차단
              정상 업무?                            L3: 서비스 차단
                                                   L4: 긴급 대응
```

### 관제 일지 양식

```markdown
## [INC-xxx] 제목

| 항목 | 내용 |
|------|------|
| 탐지 시각 | YYYY-MM-DD HH:MM |
| 탐지 출처 | Snort / ModSecurity / Splunk Alert |
| 공격자 IP | x.x.x.x |
| 대상 | WordPress / MySQL |
| 공격 유형 | MITRE ATT&CK TID |
| 위험도 | Critical / High / Medium / Low |
| 판별 | 정탐 / 오탐 |
| 판별 근거 | (구체적 로그 근거) |
| 대응 조치 | (수행한 조치) |
| 검증 결과 | (차단 확인 결과) |
```

---

## Step 3. 관제 대응 실행

### 시나리오 A: 킬체인 공격 실시간 대응 ✅

Phase 3에서 수행한 킬체인 공격을 **관제자 관점에서 재실행** (2026-08-27 18:49~19:40 KST):

| 단계 | 공격 도구 | 실행 시각 | Splunk Alert 트리거 | 대시보드 변화 |
|------|----------|----------|-------------------|-------------|
| 1. 정찰 | WPScan (`--enumerate u`) | 18:49~18:50 | (발생 미확인·원인 미확정) | alerts 패널: ET SCAN 다수, att_type 파이차트 변화 |
| 2. 브루트포스 | hydra (rockyou.txt) | 19:16~19:18 | **Brute Force Detection** (Critical, 19:20) + **WAF Alert Surge** (Medium, 19:10/19:20) | login_history: 10.50.50.30 → 965건 |
| 3. SQL Injection | sqlmap (`--dbs --batch`) | 19:21~19:30 | **SQL Injection Detection** (Critical, 19:35) | alerts 패널: SID 1000004 UNION SELECT 4건 |
| 4. 웹쉘 실행 | curl (`/?cmd=id/whoami/cat+/etc/passwd`) | 19:30~19:35 | **Webshell Detection** (Medium, 19:35) + **WAF Alert Surge** (Medium, 19:30/19:40) | — |
| 5. DB 유출 | curl 웹쉘 경유 mysql | 19:35~19:40 | (전용 Alert 미설정) | db_approach 패널: MySQL 로그 확인 |

**Triggered Alerts 최종 현황 (8건):**

| 시각 | Alert | Severity |
|------|-------|----------|
| 19:45:00 | Webshell Detection | Medium |
| 19:40:02 | WAF Alert Surge | Medium |
| 19:35:01 | Webshell Detection | Medium |
| 19:35:01 | SQL Injection Detection | Critical |
| 19:30:03 | WAF Alert Surge | Medium |
| 19:20:01 | WAF Alert Surge | Medium |
| 19:20:01 | Brute Force Detection | Critical |
| 19:10:01 | WAF Alert Surge | Medium |

### 관제 대응 — 공격자 IP 차단 ✅

| 항목 | 내용 |
|------|------|
| 조치 | pfSense Firewall → Rules → WAN에 Block 룰 추가 |
| 차단 대상 | Source: 10.50.50.30, Protocol: TCP, Destination: Any |
| 룰 위치 | WAN 룰 최상단 (NAT 룰보다 앞에 배치) |

### 차단 검증 ✅

| 검증 방법 | 결과 |
|----------|------|
| `curl -s --max-time 10 "http://10.0.0.254:8080/"` | 응답 없음 (타임아웃) |
| `wpscan --url http://10.0.0.254:8080 --enumerate u` | "Scan Aborted: seems to be down (Timeout was reached)" |

→ **차단 성공 확인**

### 시나리오 B: 정탐/오탐 판별 ✅

정상 트래픽(mng-mint cron, 10.0.50.100)과 공격 트래픽(Kali, 10.50.50.30) 혼합 환경에서 판별:

| 경보 | 정탐/오탐 | 판별 근거 |
|------|----------|----------|
| ET SCAN (WPScan) | **정탐** | User-Agent에 "WPScan" 명시, 단시간 대량 요청 |
| Brute Force (login_history 965건) | **정탐** | 동일 IP에서 초당 다수 POST /wp-login.php, User-Agent "Hydra" |
| WAF Alert Surge (ModSecurity) | **정탐** | Rule 913100 security scanner 탐지, anomaly score 8점 초과 |
| SQLi (SID 1000004) | **정탐** | UNION SELECT 페이로드 확인, sqlmap User-Agent |
| Webshell (cmd=) | **정탐** | `/?cmd=id` 등 명령어 파라미터, 응답에 `uid=33(www-data)` |
| login_history 10.0.50.100: 1건 | **정상** | mng-mint 관리자 정상 접속 (cron 또는 수동), 빈도/패턴 정상 |

---

## Step 4. MITRE ATT&CK 매핑

### 공격 매핑 요약

| Tactic | Technique | ID | 탐지 여부 | 탐지 소스 | Alert 트리거 | 대응 |
|--------|-----------|-----|----------|----------|-------------|------|
| Reconnaissance | Active Scanning | T1595 | **탐지** | Snort ET SCAN (WPScan User-Agent) | Scanner Detection (발생 미확인·원인 미확정) | 모니터링 |
| Initial Access | Exploit Public-Facing App | T1190 | **탐지** | Snort SID 1000004 (UNION SELECT) 4건 | **SQL Injection Detection** (Critical) | IP 차단 |
| Credential Access | Brute Force | T1110 | **탐지** | Apache 로그 (965건) + ModSecurity Rule 913100/949110 | **Brute Force Detection** (Critical) + **WAF Alert Surge** | IP 차단 |
| Persistence | Web Shell | T1505.003 | **탐지** | Apache 로그 (`cmd=` 파라미터) + ModSecurity anomaly | **Webshell Detection** (Medium) + **WAF Alert Surge** | 웹쉘 제거 + IP 차단 |
| Discovery | Network Service Scanning | T1046 | **탐지** | 웹쉘 경유 (`ip addr`, `hostname`) — Apache 로그에 cmd= 기록 | Webshell Detection에 포함 | IP 차단 |
| Collection | Data from Information Repos | T1213 | **부분 탐지** | 웹쉘 경유 mysql 명령 — Apache 로그에 cmd= 기록. DB 접근 자체는 정상 경로와 구분 불가 | (전용 Alert 미설정) | DB 비밀번호 변경 |
| Exfiltration | Over C2 Channel | T1041 | **전용 탐지 미설정** | 외부 전송 실패 (Connection refused) | — | 실패 원인 미확정 |

### 킬체인 분석 다이어그램

```
정찰(T1595) → 침투(T1190) → 인증(T1110) → 지속성(T1505) → 내부정찰(T1046) → DB접근(T1213) → 유출(T1041)
    ↑              ↑              ↑              ↑              ↑              ↑            ↑
  wpscan        sqlmap          hydra        웹쉘(hello.php)  cmd=ip+addr    cmd=mysql     curl→외부
    ↓              ↓              ↓              ↓              ↓              ↓            ↓
 [탐지 ✅]     [탐지 ✅]      [탐지 ✅]      [탐지 ✅]      [탐지 ✅]     [부분탐지 ⚠]  [전송 실패]
 ET SCAN      SID 1000004    965건+WAF     cmd= Alert     cmd= Alert    정상경로혼재   원인 미확정
```

### 탐지 커버리지 요약

- **공격 시도 탐지**: 5/7 단계 (정찰, SQLi, 브루트포스, 웹쉘, 내부정찰)
- **부분 탐지**: 1/7 단계 (DB 접근 — 웹쉘 cmd= 로그에서 간접 확인 가능하나, 정상 DB 쿼리와 구분 어려움)
- **외부 전송 실패**: 1/7 단계 (Connection refused; 실패 원인은 방화벽 로그·수신 서비스 상태로 추가 확인)
- **Alert 트리거**: Brute Force Detection, SQL Injection Detection, Webshell Detection, WAF Alert Surge (4/5 Alert 트리거 확인)

---

## Step 5. 최종 보고서 ✅

→ [final-report.md](final-report.md) 참조

### 보고서 구조 (8장)

1. **Executive Summary** (경영진용, 비기술적)
2. **인프라 현황** (토폴로지, 자산 목록, 로그 수집 체계)
3. **공격 분석** (킬체인 7단계 + MITRE ATT&CK 매핑)
4. **탐지 현황** (대시보드, Alert 8건, 정탐/오탐 판별, 커버리지 5/7)
5. **대응 조치** (타임라인, IP 차단, 차단 검증)
6. **개선 권고** (탐지 개선, 인프라 보강, 프로세스 개선)
7. **부록** (IOC 목록, Splunk 쿼리 모음, 관제 일지 요약)
8. **SOC 분석가 사고 확장** (STRIDE/PASTA, IP 평판, EDR 연계, AI 활용, 커리어)

---

## 관제 일지

→ [incident-log.md](incident-log.md) 참조

---

## 스크린샷

- [x] Splunk 대시보드 전체 화면 (SOC_Monitor, 8패널 3단 레이아웃)
- [ ] 경보 발생 시점 대시보드
- [ ] 관제 대응 과정 (경보→분석→차단)
- [ ] 정탐/오탐 판별 근거 화면
- [ ] 차단 검증 (차단 전/후)
- [ ] MITRE ATT&CK Navigator 매핑
