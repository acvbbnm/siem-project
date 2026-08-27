# SIEM 공격 탐지 및 대응 실습 — 최종 보고서

> 작성일: 2026-08-27
> 환경: 격리된 가상 SOC 실습 랩 (사설 IP 대역)

---

## 1. Executive Summary

테크솔루션 가상 기업의 WordPress 홈페이지를 대상으로 외부 공격자의 **킬체인 7단계 공격**(정찰 → SQLi → 브루트포스 → 웹쉘 → 내부정찰 → DB 탈취 → 유출 시도)을 시뮬레이션하고, Snort IDS + ModSecurity WAF + Splunk SIEM 기반 탐지·대응 체계의 효과를 검증하였다.

**핵심 결과:**
- 7단계 중 **5단계 완전 탐지**, 1단계 부분 탐지, 1단계 네트워크 차단 성공
- Splunk Alert 5개 중 **4개 정상 트리거** 확인
- 공격자 IP 차단 후 재공격 시 **완전 차단** 검증
- 데이터 유출 시도는 DMZ 아웃바운드 차단 정책에 의해 **사전 차단**

**주요 발견:**
- 시그니처 기반 IDS(Snort)만으로는 행위 기반 공격(브루트포스) 탐지에 한계 → 다중 로그 소스 상관분석 필수
- ModSecurity WAF는 공격 도구(hydra, sqlmap)의 User-Agent를 효과적으로 탐지
- DMZ↔Inner-net 간 DB 통신 허용 규칙이 공격 피벗에 악용됨 → 네트워크 세그멘테이션 강화 필요

---

## 2. 인프라 현황

### 2-1. 네트워크 토폴로지

```
att-mint(10.50.50.17) ──att-net──→ VyOS ──rf-net──→ pfSense(+Snort IPS)
Kali   (10.50.50.30) ─┘                                  │
                                                     ┌─ dmz-net ──→ WordPress(10.0.10.80) + ModSecurity WAF
                                                     │              Bee-box  (10.0.10.50)
                                                     ├─ inner-net ──→ Splunk(10.0.100.50)
                                                     │                MySQL (10.0.100.60)
                                                     └─ mng-net ──→ mng-mint(10.0.50.17, 관제+정상유저)
```

### 2-2. 자산 목록

| 자산 | IP | 역할 | 보안 솔루션 |
|------|-----|------|-----------|
| pfSense | WAN 10.0.0.254 | 방화벽 + IPS | Snort (GPLv2 + ET Open + 커스텀 룰 9개) |
| WordPress | 10.0.10.80 | 회사 홈페이지 (DMZ) | ModSecurity 2.9.3 + OWASP CRS 3.2.0 (DetectionOnly) |
| MySQL | 10.0.100.60 | DB 서버 (Inner-net) | — |
| Splunk | 10.0.100.50 | SIEM (Inner-net) | 4개 인덱스, 8개 로그 소스 |
| Kali | 10.50.50.30 | 공격자 (att-net) | — |

### 2-3. 로그 수집 체계

| 로그 소스 | 수집 경로 | Splunk 인덱스 | 비고 |
|----------|----------|-------------|------|
| Snort alerts | pfSense syslog → UDP 514 | pfsense | 네트워크 레벨 탐지 |
| pfSense filterlog | pfSense syslog → UDP 514 | pfsense | 방화벽 로그 |
| Apache access log | rsyslog → TCP 9514 | idx_web | HTTP 요청 기록 |
| Apache error log | rsyslog → TCP 9514 | idx_web | 에러 및 WAF 로그 |
| ModSecurity audit log | rsyslog → TCP 9514 | idx_web | WAF 탐지 상세 (idx_waf 비어있음) |
| WP auth log | rsyslog → TCP 9514 | idx_web | 로그인 시도 기록 |
| MySQL error log | rsyslog → TCP 9516 | idx_db | DB 에러 |
| MySQL slow query | rsyslog → TCP 9516 | idx_db | 느린 쿼리 |

---

## 3. 공격 분석

### 3-1. 킬체인 단계별 공격 수행

| 단계 | Kill Chain | MITRE ATT&CK | 공격 도구 | 결과 |
|------|-----------|-------------|----------|------|
| 1 | 정찰 | T1595 Active Scanning | wpscan, nmap | WP 7.1 식별, XML-RPC 활성화, Upload 디렉토리 리스팅 노출 |
| 2 | 초기 침투 | T1190 Exploit Public-Facing App | sqlmap | SQLi 실패 (WP 코어 Prepared Statement 보호), 공격 시도 자체가 로그에 기록 |
| 3 | 인증 공격 | T1110 Brute Force | hydra | admin/rlaquddn1@ 크래킹 성공 (965건 시도) |
| 4 | 지속성 | T1505.003 Web Shell | WP File Manager | hello.php에 PHP 웹쉘 삽입, `/?cmd=` 경로로 명령 실행 |
| 5 | 내부 정찰 | T1046 Network Service Scan | 웹쉘 CLI | DMZ IP(10.0.10.80), DB 인증정보(wp_admin/WpAdmin!2024) 획득 |
| 6 | DB 접근 | T1213 Data from Info Repos | mysql (웹쉘 경유) | wp_users 테이블 탈취 (admin 계정 + bcrypt 해시) |
| 7 | 유출 시도 | T1041 Exfiltration Over C2 | curl | Connection refused — DMZ 아웃바운드 차단으로 유출 실패 |

### 3-2. MITRE ATT&CK 매핑

| Tactic | Technique | ID | 탐지 | 탐지 소스 | Alert |
|--------|-----------|-----|------|----------|-------|
| Reconnaissance | Active Scanning | T1595 | ✅ | Snort ET SCAN | Scanner Detection |
| Initial Access | Exploit Public-Facing App | T1190 | ✅ | Snort SID 1000004 | SQL Injection Detection |
| Credential Access | Brute Force | T1110 | ✅ | Apache 로그 + ModSecurity | Brute Force Detection + WAF Alert Surge |
| Persistence | Web Shell | T1505.003 | ✅ | Apache 로그 (cmd=) | Webshell Detection + WAF Alert Surge |
| Discovery | Network Service Scanning | T1046 | ✅ | Apache 로그 (cmd=) | Webshell Detection에 포함 |
| Collection | Data from Information Repos | T1213 | ⚠️ | 웹쉘 cmd= 로그 (간접) | (전용 Alert 미설정) |
| Exfiltration | Over C2 Channel | T1041 | 🛡️ | DMZ 아웃바운드 차단 | — (네트워크 레벨 차단) |

---

## 4. 탐지 현황

### 4-1. SOC 대시보드 (SOC_Monitor)

7개 패널, 3단 레이아웃으로 구성:

| 패널 | 내용 | 공격 시 변화 |
|------|------|------------|
| events | 전체 이벤트 수 | 80,425 → 83,916건 증가 |
| time | 시간대별 추이 | 공격 시간대(18:49~19:40) 급증 |
| att_type | 공격 유형 파이차트 | ET SCAN 비율 급증 |
| att_ip | 공격자 IP Top5 | 10.50.50.30 최다 |
| waf | WAF 탐지 현황 | ModSecurity Rule 949110, 913100 등 |
| alerts | 최근 Snort 경보 | ET SCAN, SID 1000004 표시 |
| login_history | 로그인 시도 IP별 | 10.50.50.30: 965건 |

### 4-2. Splunk Alert 트리거 현황

| 시각 | Alert | Severity | 트리거 원인 |
|------|-------|----------|-----------|
| 19:40:02 | WAF Alert Surge | Medium | 웹쉘 명령 실행 → ModSecurity 탐지 |
| 19:35:01 | Webshell Detection | Medium | `/?cmd=id`, `/?cmd=whoami` 등 |
| 19:35:01 | SQL Injection Detection | Critical | Snort SID 1000004 UNION SELECT 4건 |
| 19:30:03 | WAF Alert Surge | Medium | ModSecurity anomaly score 초과 |
| 19:20:01 | WAF Alert Surge | Medium | hydra 브루트포스 → Rule 913100 |
| 19:20:01 | Brute Force Detection | Critical | idx_web wp-login.php POST 965건 |
| 19:10:01 | WAF Alert Surge | Medium | 브루트포스 초기 탐지 |

### 4-3. 정탐/오탐 판별

| 경보 | 판별 | 근거 |
|------|------|------|
| ET SCAN (WPScan) | **정탐** | User-Agent "WPScan" 명시, 단시간 대량 요청 |
| Brute Force 965건 | **정탐** | 동일 IP 초당 다수 POST, User-Agent "Hydra" |
| ModSecurity 913100 | **정탐** | security scanner User-Agent 탐지 |
| SID 1000004 SQLi | **정탐** | UNION SELECT 페이로드 확인 |
| Webshell cmd= | **정탐** | 시스템 명령 파라미터, 응답에 uid=33(www-data) |
| login_history 10.0.50.100 | **정상** | mng-mint 관리자 정상 접속, 빈도 1건 |

### 4-4. 탐지 커버리지

- **완전 탐지**: 5/7 단계
- **부분 탐지**: 1/7 단계 (DB 접근 — 정상 DB 쿼리와 구분 어려움)
- **네트워크 차단**: 1/7 단계 (유출 시도)

---

## 5. 대응 조치

### 5-1. 대응 타임라인

| 시각 | 이벤트 | 대응 |
|------|--------|------|
| 18:49 | WPScan 정찰 탐지 | L1 모니터링 — 후속 공격 관찰 |
| 19:16 | Brute Force 시작 (965건) | L2 대응 준비 |
| 19:20 | Brute Force Detection Alert 트리거 | 공격 확정, 차단 검토 |
| 19:24 | SQL Injection 시도 (4건) | 공격 에스컬레이션 확인 |
| 19:30 | 웹쉘 명령 실행 탐지 | L3 긴급 대응 판단 |
| 19:35 | DB 데이터 유출 확인 | L4 긴급 대응 — 즉시 차단 결정 |
| 19:40 | pfSense WAN Block 룰 적용 | 10.50.50.30 전체 차단 |
| 19:40~ | 차단 검증 | curl 타임아웃, WPScan Aborted 확인 |

### 5-2. 차단 조치

| 조치 | 상세 |
|------|------|
| pfSense WAN Block | Source: 10.50.50.30, Protocol: TCP, Dest: Any — WAN 룰 최상단 배치 |
| 검증 — curl | `curl -s --max-time 10 "http://10.0.0.254:8080/"` → 응답 없음 (타임아웃) |
| 검증 — WPScan | "Scan Aborted: seems to be down (Timeout was reached)" |

---

## 6. 개선 권고

### 6-1. 탐지 개선

| 영역 | 현재 상태 | 개선 방안 | 우선순위 |
|------|----------|----------|---------|
| 브루트포스 탐지 | Snort 8건 vs Apache 965건 | **Apache 로그 기반 Alert을 주 탐지 소스로** — Snort는 네트워크 레벨에서 HTTP POST body를 제한적으로 검사 | 높음 |
| DB 접근 탐지 | 정상/비정상 구분 불가 | **MySQL 감사 로그(Audit Plugin) 활성화** + 비정상 쿼리 패턴 Alert 추가 | 높음 |
| WAF 모드 | DetectionOnly (탐지만) | **SecRuleEngine On** 전환하여 실제 차단 수행 | 중간 |
| 로그 인덱스 | idx_waf 비어있음 | ModSecurity 로그 전용 인덱스 분리 수집 (rsyslog 설정 수정) | 낮음 |
| Scanner Alert | cron 타이밍 미스매치 | **Real-time Alert** 또는 짧은 주기(1분) 검토 | 낮음 |

### 6-2. 인프라 보강

| 영역 | 현재 상태 | 개선 방안 |
|------|----------|----------|
| DMZ↔Inner-net | WordPress→MySQL 3306 허용 | DB 프록시 도입 또는 접근 제어 강화 (허용 쿼리 화이트리스트) |
| WordPress 보안 | wp-config.php 평문 인증정보 | DB 인증정보 환경변수 또는 별도 보호 파일로 분리 |
| 파일 관리 | WP File Manager로 웹쉘 삽입 가능 | 불필요한 플러그인 제거, 파일 업로드/편집 제한 |
| 비밀번호 정책 | admin/rlaquddn1@ (약한 비밀번호) | 강력한 비밀번호 정책 + 2FA 적용 |

### 6-3. 프로세스 개선

| 영역 | 개선 방안 |
|------|----------|
| 경보 대응 절차 | Triage → 분석 → 대응 → 검증 → 보고의 표준 프로세스 문서화 |
| 에스컬레이션 | L1~L4 단계별 판단 기준 및 에스컬레이션 경로 명확화 |
| IOC 관리 | 탐지된 IOC(IP, User-Agent, 페이로드)를 DB화하여 차단 자동화 |

---

## 7. 부록

### 7-1. IOC (Indicators of Compromise)

**공격자 IP:**
| IP | 역할 | 차단 여부 |
|-----|------|---------|
| 10.50.50.30 | Kali Linux (주 공격자) | ✅ pfSense WAN Block |
| 10.50.50.17 | att-mint (Phase 1~2 공격자) | ✅ pfSense WAN Block (Phase 2) |

**악성 User-Agent:**
| User-Agent | 도구 | 탐지 소스 |
|-----------|------|----------|
| `WPScan v3.8.28` | WPScan | Snort ET SCAN |
| `Mozilla/5.0 (Hydra)` | hydra | Apache 로그 + ModSecurity Rule 913100 |
| `sqlmap/1.10.6#stable` | sqlmap | Snort SID 1000004 |

**악성 페이로드 패턴:**
| 패턴 | 공격 유형 | 탐지 쿼리 |
|------|----------|----------|
| `/?cmd=` | 웹쉘 명령 실행 | `index=idx_web "cmd="` |
| `UNION SELECT` | SQL Injection | `index=pfsense "1000004"` |
| `POST /wp-login.php` (대량) | 브루트포스 | `index=idx_web "wp-login.php" "POST"` |

### 7-2. Splunk 쿼리 모음

**대시보드 쿼리:**
```spl
# 전체 이벤트 수
index=pfsense OR index=idx_web OR index=idx_waf OR index=idx_db | stats count

# 공격자 IP Top5
index=pfsense "Priority" | rex "\{(?P<proto>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)" | top 5 src_ip

# 공격 유형 분포
index=pfsense "Priority" | rex "\[\d+:\d+:\d+\]\s+(?P<signature>[^\[]+?)\s+\[" | top 10 signature

# 로그인 시도 IP별
index=idx_web "wp-login" | rex "client\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip
```

**Alert 쿼리:**
```spl
# Brute Force Detection (Critical, */5)
index=idx_web "wp-login.php" "POST" | stats count | where count >= 10

# Scanner Detection (High, */5)
index=pfsense "1000001" | stats count | where count >= 10

# SQL Injection Detection (Critical, */5)
index=pfsense ("SQL" OR "1000004") "Priority" | stats count | where count >= 2

# Webshell Detection (Critical, */5)
index=idx_web "cmd=" | stats count | where count >= 1

# WAF Alert Surge (Medium, */10)
index=idx_web "ModSecurity" | stats count | where count >= 30
```

### 7-3. 관제 일지 요약

→ 상세: [incident-log.md](incident-log.md)

| 번호 | 제목 | 위험도 | 판별 |
|------|------|--------|------|
| INC-001 | WPScan 정찰 탐지 | Medium | 정탐 |
| INC-002 | WordPress 브루트포스 공격 | Critical | 정탐 |
| INC-003 | SQL Injection 공격 | Critical | 정탐 |
| INC-004 | 웹쉘 명령 실행 탐지 | Critical | 정탐 |
| INC-005 | DB 데이터 유출 | Critical | 정탐 |
| INC-006 | 공격자 IP 차단 및 검증 | — | 차단 성공 |

---

## 8. SOC 분석가의 사고 확장 — 실무에서는 이렇게 생각한다

> 이 프로젝트는 격리 환경에서의 실습이었다. 하지만 실제 SOC 관제 환경에서는 단순 "탐지 → 차단"을 넘어서, 더 깊은 분석과 판단이 요구된다. 아래는 이번 실습의 각 단계에서 **실무 SOC 분석가라면 추가로 어떤 사고를 했을지**를 정리한 것이다.

### 8-1. IP 하나를 차단할 때도 — 평판 조회와 컨텍스트 수집

이번 실습에서는 `10.50.50.30`이 공격자라는 것이 명확했다. 하지만 실제 환경에서 `1.1.1.1`이라는 IP가 공격을 보내왔다면:

- **IP 평판 조회**: VirusTotal, AbuseIPDB, Shodan 등에서 해당 IP의 이력 확인 — 이전에 보고된 악성 활동이 있는지, 어느 ASN/국가 소속인지
- **해당 IP의 다른 활동 확인**: 우리 환경에서 이 IP가 이전에 정상 접속한 적이 있는지 (고객/파트너일 수도 있음)
- **프록시/VPN/TOR 여부**: 공격자가 프록시를 사용했다면 IP 차단만으로는 부족 — 동일 공격 패턴을 가진 다른 IP 대역도 확인
- **"이 공격이 성공했다면 다음 스텝은 무엇이었을까?"**: 공격자의 의도와 킬체인 상 다음 단계를 예측하여 선제 방어

```
실습에서 한 것:    10.50.50.30 차단 → 끝
실무에서 할 것:    10.50.50.30 평판 확인 → 동일 C2 대역 식별 → 유사 패턴 IP 일괄 차단
                  → 공격 성공 시 예상 행동(lateral movement) 모니터링 강화
```

### 8-2. STRIDE 관점 — 이 공격의 위협 모델링

**STRIDE**(Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)는 공격의 원리를 이해하는 프레임워크다. 이번 킬체인을 STRIDE로 분류하면:

| 킬체인 단계 | STRIDE 분류 | 위협 설명 | 이 실습에서의 사례 |
|------------|-----------|----------|----------------|
| 브루트포스 | **Spoofing** | 정상 사용자로 위장하여 인증 우회 | hydra로 admin 크래킹 → 관리자 권한 획득 |
| 웹쉘 삽입 | **Tampering** | 서버 파일 변조 | hello.php에 악성 코드 삽입 |
| 웹쉘 경유 | **Repudiation** | 정상 웹 요청으로 위장하여 추적 회피 | GET /?cmd= 요청이 일반 HTTP 요청과 혼재 |
| DB 탈취 | **Info Disclosure** | 민감 정보 노출 | wp_users 계정·해시, wp-config.php 인증정보 |
| WPScan 정찰 | **Denial of Service** 가능성 | 대량 스캔은 서비스 부하 유발 가능 | 1,970 requests / 4분 |
| 웹쉘 명령 | **Elevation of Privilege** | www-data 권한으로 시스템 명령 실행 | uid=33으로 /etc/passwd 열람, DB 접근 |

**실무 적용**: 새로운 공격 이벤트를 받았을 때 "이건 STRIDE 중 뭐지?"라고 분류하면, 어떤 종류의 대응이 필요한지 빠르게 판단할 수 있다. Spoofing이면 인증 강화, Tampering이면 무결성 검증, Info Disclosure면 데이터 접근 통제.

### 8-3. PASTA 관점 — 맥락과 우선순위

**PASTA**(Process for Attack Simulation and Threat Analysis)는 비즈니스 맥락에서 위협의 우선순위를 매기는 프레임워크다.

이 실습에서 발견된 취약점들의 비즈니스 영향도를 PASTA 관점으로 평가하면:

| 취약점 | 기술적 심각도 | 비즈니스 영향 | 우선순위 |
|--------|------------|------------|---------|
| wp-config.php 인증정보 노출 | High | **Critical** — DB 전체 접근 가능, 고객 데이터 유출 시 법적 책임 | 1순위 |
| 약한 비밀번호 (admin/rlaquddn1@) | Medium | **High** — 관리자 권한 탈취 → 사이트 변조, 악성코드 배포 가능 | 2순위 |
| WP File Manager 취약점 | High | **High** — 웹쉘 삽입 경로, 서버 완전 장악 가능 | 3순위 |
| ModSecurity DetectionOnly | Low | **Medium** — 탐지는 하지만 차단을 안 함, 대응 시간 지연 | 4순위 |
| idx_waf 인덱스 비어있음 | Low | **Low** — 운영 불편 수준, WAF 로그 분석 효율 저하 | 5순위 |

**실무 적용**: 탐지 이벤트를 받았을 때 단순히 "Critical이니까 바로 대응"이 아니라, "이 공격이 성공하면 우리 비즈니스에 어떤 영향이 있는가?"를 먼저 판단한다.

### 8-4. 이 실습에서 놓친 것들 — 실무라면 추가로 했을 분석

**1) 타임라인 심층 분석**

실습에서는 공격 순서가 명확했지만, 실무에서는:
- 공격자가 정찰을 언제부터 했는지 (수일 전부터 소량 스캔이 있었을 수 있음)
- 브루트포스 성공 후 첫 관리자 패널 접근까지의 시간 간격
- 웹쉘 설치 후 첫 명령 실행까지의 dwell time (체류 시간)
- 이러한 타임라인은 공격자의 숙련도와 자동화 수준을 판단하는 근거가 된다

**2) Lateral Movement 모니터링**

웹쉘에서 `ip addr`과 `hostname`을 실행한 것은 **내부 정찰의 전형적 패턴**이다. 실무라면:
- WordPress 서버에서 Inner-net 방향으로 3306 외 다른 포트 접근이 있었는지 확인
- Splunk 서버(10.0.100.50)로의 접근 시도가 있었는지 확인
- 동일 시간대 다른 내부 자산에서 비정상 활동이 있었는지 교차 확인

**3) DB 접근 상세 분석**

웹쉘 경유 DB 접근은 "정상 DB 연결 경로"를 사용하기 때문에 탐지가 어려웠다. 실무라면:
- MySQL Audit Plugin으로 쿼리 레벨 로깅 (SELECT가 아닌 테이블 전체 덤프, INFORMATION_SCHEMA 접근 등 비정상 패턴)
- DB 접근 시간대와 정상 업무 시간 비교 (새벽 접근이면 비정상)
- 쿼리의 결과 row 수가 비정상적으로 많은 경우 탐지

**4) 유출 경로 다각화 검토**

DMZ 아웃바운드 차단으로 `curl` 유출이 막혔지만, 공격자는 다른 경로를 시도할 수 있다:
- DNS 터널링을 통한 데이터 유출 (DNS는 보통 허용됨)
- HTTP 응답 body에 데이터를 포함시켜 공격자가 직접 조회
- 정상 웹 페이지에 데이터를 숨겨 놓고 나중에 수집 (steganography)

### 8-5. EDR 연계 — 다음 단계

현재 환경에는 EDR(Endpoint Detection and Response)이 없다. 실무에서 EDR을 연계하면:

```
[공격 유입]
    │
    ├─ 네트워크 레벨 (Snort/WAF) ──→ SIEM
    │     현재 구현: IP/시그니처 기반 탐지
    │
    └─ 엔드포인트 레벨 (EDR) ──→ SIEM
          추가 가능: 프로세스 트리, 파일 생성/변경, 메모리 분석

[통합 대응 플로우]
    1. SIEM Alert 수신 (네트워크 + 엔드포인트 통합)
    2. 엔드포인트 격리 (EDR에서 네트워크 차단)
    3. 프로세스 트리 분석 (웹쉘 → shell_exec → mysql → 데이터 유출)
    4. 파일 무결성 확인 (hello.php 변조 탐지)
    5. 포렌식 데이터 수집 (메모리 덤프, 타임라인)
```

이번 실습의 웹쉘 탐지를 예로 들면:
- **현재(네트워크만)**: Apache 로그에서 `/?cmd=` 패턴 탐지 → 수동으로 웹쉘 파일 확인
- **EDR 연계 시**: `www-data` 프로세스가 `shell_exec()` 호출 → `mysql` 자식 프로세스 생성 → 파일 변경 이벤트(hello.php) 자동 탐지 → 엔드포인트 자동 격리

### 8-6. AI 활용 — 관제 자동화 방향

안랩 등 보안 기업에서 AI를 관제 업무에 도입하고 있는 흐름과 관련하여:

- **이벤트 자동 분류**: 대량의 경보 중 정탐/오탐을 AI가 1차 분류 → 분석가는 AI가 "확인 필요"로 분류한 것만 집중
- **IP 평판 자동 조회**: 새로운 공격 IP 탐지 시 VirusTotal/AbuseIPDB 자동 조회 → 컨텍스트가 붙은 경보 제공
- **패턴 인식**: 단일 이벤트가 아닌, 킬체인 패턴(정찰 → 브루트포스 → 웹쉘 순서)을 인식하여 조기 경보
- **대응 자동화**: 반복적인 차단 작업(방화벽 룰 추가, EDR 격리)을 AI가 제안하고 분석가가 승인

이번 실습에서 AI가 있었다면:
- hydra 브루트포스 965건이 쌓이기 전에, 10건 시점에서 비정상 패턴 자동 인식
- WPScan 정찰 직후 "후속 공격 가능성 높음" 예측 경보
- 웹쉘 삽입 탐지 시 자동으로 해당 파일 해시 + 웹쉘 키워드 매칭

### 8-7. 관제에서 시작하는 커리어 — 이 프로젝트가 보여주는 것

관제(SOC)는 보안의 시작점이다. 이 프로젝트에서 경험한 **"공격 시뮬레이션 → 탐지 → 분석 → 대응"** 사이클은 실제 SOC Tier 1 업무의 축소판이다.

여기서 더 나아가려면:
- **Tier 1 → Tier 2**: 단순 Alert 대응에서 심층 분석으로. "왜 이 공격이 가능했는가?" "다음에는 어떻게 사전 차단할 것인가?"
- **Tier 2 → Tier 3**: 위협 헌팅. Alert 없이도 비정상을 찾는 능력. "로그에는 없지만 의심스러운 패턴은 없는가?"
- **전문 분야 분기**: 포렌식, 악성코드 분석, 위협 인텔리전스, 레드팀 등

이 프로젝트가 보여주는 핵심 역량:
1. **인프라 이해**: 네트워크 토폴로지 → 방화벽 → IDS → WAF → SIEM 전체 흐름을 구축하고 운영
2. **공격자 관점**: 킬체인을 직접 수행하여 "공격이 어떻게 이루어지는지" 체득
3. **방어자 관점**: 탐지 룰 작성, 상관분석, Alert 설계, 대응 프로세스 수립
4. **사고 과정**: 단순 차단이 아닌, "왜 이 경보가 떴는가? 정탐인가? 다음은 무엇인가?"의 분석적 사고
