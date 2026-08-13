# Phase 4 — 관제 운영 (SOC 시뮬레이션)

> 확장된 인프라에서 경보분류 → 분석 → 대응 → 검증 사이클 수행

---

## Step 1. 모니터링 체계 구축

### Splunk 대시보드

**대시보드 구성:**

| 패널 | 유형 | SPL 쿼리 |
|------|------|---------|
| 실시간 이벤트 수 | Single Value | `index=pfsense OR index=idx_web OR index=idx_waf \| stats count` |
| 공격자 IP Top 5 | Bar Chart | `index=pfsense "Priority" \| top 5 src_ip` |
| 공격 유형 분포 | Pie Chart | `index=pfsense "Priority" \| rex "\\[\\*\\*\\] \\[\\d+:\\d+:\\d+\\] (?P<signature>.+?) \\[" \| top 10 signature` |
| 최근 경보 | Table | `index=pfsense "Priority" \| head 20 \| table _time src_ip dest_ip signature` |
| WAF 탐지 현황 | Bar Chart | `index=idx_waf \| stats count by rule_id` |
| 시간대별 추이 | Timechart | `index=pfsense OR index=idx_waf \| timechart span=1h count by index` |
| 로그인 시도 | Table | `index=idx_web uri="/wp-login.php" method=POST \| stats count by src_ip` |
| DB 접근 로그 | Table | `index=idx_db sourcetype=mysql:slowquery \| table _time db_user query_time` |

### Splunk Alert 설정

| 알림 | 조건 | 심각도 | 액션 |
|------|------|--------|------|
| 포트 스캔 탐지 | 동일 src 50회 이상/5분 | High | 이메일 + 로그 |
| 브루트포스 탐지 | wp-login POST 10회 이상/5분 | High | 이메일 + 로그 |
| SQLi 탐지 | Snort SQL 관련 경보 5건 이상 | Critical | 이메일 + 로그 |
| 웹쉘 의심 | .phtml/.php 업로드 접근 | Critical | 이메일 + 로그 |
| WAF 탐지 급증 | ModSecurity 50건 이상/10분 | Medium | 로그 |

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

### 시나리오 A: 킬체인 공격 실시간 대응

Phase 3에서 수행한 킬체인 공격을 **관제자 관점에서 재실행**:
1. Kali에서 공격 수행 (Phase 3 시나리오)
2. mng-mint에서 Splunk 대시보드 모니터링
3. 경보 발생 시 관제 일지 작성
4. 대응 조치 실행 (IP 차단, Snort Block 등)
5. 차단 검증

### 시나리오 B: 정탐/오탐 판별

정상 트래픽(mng-mint cron)과 공격 트래픽 혼합 환경에서:
- 동일 경보를 정상/공격으로 구분하는 판별 과정 기록
- 판별 근거: 시간, 빈도, 페이로드 내용, 세션 패턴

---

## Step 4. MITRE ATT&CK 매핑

### 공격 매핑 요약

| Tactic | Technique | ID | 탐지 여부 | 탐지 소스 | 대응 |
|--------|-----------|-----|----------|----------|------|
| Reconnaissance | Active Scanning | T1595 | <!-- --> | <!-- --> | <!-- --> |
| Initial Access | Exploit Public-Facing App | T1190 | <!-- --> | <!-- --> | <!-- --> |
| Credential Access | Brute Force | T1110 | <!-- --> | <!-- --> | <!-- --> |
| Persistence | Web Shell | T1505.003 | <!-- --> | <!-- --> | <!-- --> |
| Discovery | Network Service Scanning | T1046 | <!-- --> | <!-- --> | <!-- --> |
| Collection | Data from Information Repos | T1213 | <!-- --> | <!-- --> | <!-- --> |
| Exfiltration | Over C2 Channel | T1041 | <!-- --> | <!-- --> | <!-- --> |

### 킬체인 분석 다이어그램

```
정찰(T1595) → 침투(T1190) → 인증(T1110) → 지속성(T1505) → 내부정찰(T1046) → DB접근(T1213) → 유출(T1041)
    ↑              ↑              ↑              ↑              ↑              ↑            ↑
  wpscan        sqlmap          hydra         웹쉘 업로드      nmap          mysql         curl
    ↓              ↓              ↓              ↓              ↓              ↓            ↓
 [탐지여부]    [탐지여부]     [탐지여부]     [탐지여부]     [탐지여부]     [탐지여부]    [차단확인]
```

---

## Step 5. 최종 보고서

### 보고서 구조

1. **Executive Summary** (경영진용, 비기술적)
2. **인프라 현황** (토폴로지, 자산 목록)
3. **공격 분석** (킬체인 단계별, MITRE ATT&CK 매핑)
4. **탐지 현황** (로그 소스별, 정탐/오탐 통계)
5. **대응 조치** (방화벽, IPS, WAF 대응 이력)
6. **개선 권고** (탐지 개선, 인프라 보강, 프로세스 개선)
7. **부록** (IOC 목록, Splunk 쿼리 모음, 관제 일지)

---

## 관제 일지

→ [incident-log.md](incident-log.md) 참조

---

## 스크린샷

- [ ] Splunk 대시보드 전체 화면
- [ ] 경보 발생 시점 대시보드
- [ ] 관제 대응 과정 (경보→분석→차단)
- [ ] 정탐/오탐 판별 근거 화면
- [ ] 차단 검증 (차단 전/후)
- [ ] MITRE ATT&CK Navigator 매핑
