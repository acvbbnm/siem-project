# Phase 2. 탐지/분석 + 방화벽 정책

> mng-mint(10.0.50.17)에서 Splunk + pfSense를 통해 분석 및 대응

---

## Snort 경보 확인

pfSense WebGUI > Services > Snort > Alerts

| 공격 | 예상 Snort 탐지 시그니처 | 심각도 |
|------|------------------------|--------|
| 포트 스캔 (R-1) | sfPortscan: Portscan Detected | 중 |
| nikto 스캔 (R-3) | ET SCAN Nikto Web App Scanner | 중 |
| SQL Injection (E-1) | ET WEB_SERVER SQL Injection Attempt | 상 |
| sqlmap (E-2) | ET WEB_SERVER sqlmap User Agent | 상 |
| XSS (E-3) | ET WEB_SERVER XSS Attempt | 중 |
| Command Injection (E-5) | ET WEB_SERVER Command Injection | 상 |
| Brute Force (E-7) | 다수 로그인 실패 로그 (반복 접근) | 중 |

**Snort Alerts 캡처:**
> (실습 후 캡처 삽입)

---

## Splunk 로그 분석

접속: mng-mint Firefox → http://10.0.100.50:8000

### 기본 검색 쿼리

| 분석 목적 | 쿼리 | 기대 결과 |
|----------|------|----------|
| 전체 로그 | `index=pfsense` | pfSense/Snort 전체 이벤트 |
| Snort 경보만 | `index=pfsense "snort" OR "ALERT"` | IPS 탐지 이벤트 |
| 공격자 IP 필터 | `index=pfsense src=10.50.50.17` | att-mint 발 트래픽 전체 |
| SQL Injection | `index=pfsense "SQL" OR "sql injection"` | SQLi 관련 경보 |
| 포트 스캔 | `index=pfsense "portscan" OR "scan"` | 스캔 탐지 이벤트 |
| XSS | `index=pfsense "XSS" OR "script"` | XSS 관련 경보 |
| Command Injection | `index=pfsense "command injection" OR "cmd"` | 명령 삽입 경보 |

### 분석용 쿼리

```spl
# 시간대별 공격 분포
index=pfsense src=10.50.50.17 | timechart count by signature

# 공격 유형 Top 10
index=pfsense src=10.50.50.17 | top 10 signature

# 공격자별 이벤트 수
index=pfsense | stats count by src | sort -count

# 목적지 포트 분포
index=pfsense src=10.50.50.17 | stats count by dest_port | sort -count

# 공격 성공/실패 판별 (HTTP 상태코드)
index=pfsense src=10.50.50.17 | stats count by status
```

### 분석 결과

**전체 이벤트 수:**
> (실습 후 기록)

**공격 유형별 분포:**
> (실습 후 기록)

**시간대별 추이 차트:**
> (실습 후 캡처 삽입)

---

## 방화벽 정책 수립 및 적용

pfSense WebGUI > Firewall > Rules

### 1차 대응 — 공격자 IP 즉시 차단

| 순서 | 인터페이스 | Action | Source | Destination | Protocol | 근거 |
|------|-----------|--------|--------|-------------|----------|------|
| 1 | WAN | **Block** | 10.50.50.17 | Any | Any | 명확한 공격자 IP |

**적용 전 규칙 캡처:**
> (실습 후 캡처)

**적용 후 규칙 캡처:**
> (실습 후 캡처)

### 2차 대응 — 서비스 제한

| 순서 | 인터페이스 | Action | Source | Destination | Protocol/Port | 근거 |
|------|-----------|--------|--------|-------------|--------------|------|
| 1 | WAN | Pass | Any | 10.0.10.50 | TCP/80 | HTTP만 허용 |
| 2 | WAN | Block | Any | Any | Any | 나머지 전체 차단 |
| 3 | DMZNET | Block | 10.0.10.50 | 10.0.100.0/24 | Any | DMZ→내부 차단 |
| 4 | DMZNET | Block | 10.0.10.50 | Any | Any | DMZ 아웃바운드 차단 (리버스쉘 방지) |

### 3차 대응 — Snort IPS 차단 모드 전환

pfSense > Services > Snort > Interfaces > WAN > Edit

| 설정 | 변경 전 | 변경 후 | 효과 |
|------|--------|--------|------|
| Block Offenders | 미체크 | **체크** | 탐지 시 자동 IP 차단 |
| IPS Policy | — | Connectivity | 탐지 룰 정책 |
| Kill States | 미체크 | **체크** | 차단 시 기존 연결도 종료 |
| Block Duration | — | **3600초** | 1시간 차단 유지 |

**변경 전 Snort 설정 캡처:**
> (실습 후 캡처)

**변경 후 Snort 설정 캡처:**
> (실습 후 캡처)

---

## 정책 적용 결과 요약

| 대응 단계 | 적용 내용 | 효과 |
|----------|----------|------|
| 1차 | 공격자 IP 차단 | 해당 IP에서의 모든 접근 차단 |
| 2차 | HTTP만 허용 + DMZ 아웃바운드 차단 | 불필요 포트 접근 방지 + 리버스쉘 차단 |
| 3차 | Snort 자동차단 활성화 | 새로운 공격자도 자동 탐지/차단 |
