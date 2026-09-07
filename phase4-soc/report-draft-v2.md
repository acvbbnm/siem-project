# SOC 구축 및 위협 탐지·대응 체계 검증 프로젝트

> 작성자: (이름)
> 작성일: 2026-08-29
> 환경: 격리된 가상 SOC 실습 랩 (사설 IP 대역)

---

## 1. 프로젝트 개요

### 1-1. 목적 및 범위

본 프로젝트는 가상 기업 "테크솔루션"의 IT 인프라를 대상으로 **SOC(Security Operations Center) 환경을 구축**하고, 실제 공격 시나리오를 통해 **탐지·분석·대응 체계의 실효성을 검증**하는 것을 목표로 한다.

| 구분 | 내용 |
|------|------|
| **프로젝트 유형** | 통합보안관제(SOC) 구축 및 탐지 체계 검증 |
| **수행 범위** | 인프라 설계 → 보안 솔루션 배치 → 공격 시뮬레이션 → 탐지 엔지니어링 → 관제 운영 → 대응·검증 |
| **수행 환경** | VMware ESXi 6.7 기반 격리 가상 네트워크 (사설 IP 대역) |
| **수행 기간** | 2026.07 ~ 2026.08 |

### 1-2. 수행 방법론

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  1. 인프라    │───→│  2. 보안 솔루션│───→│  3. 공격      │───→│  4. 탐지      │───→│  5. 관제·대응 │
│     설계·구축  │    │     배치·설정  │    │     시뮬레이션  │    │     엔지니어링  │    │     ·검증     │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
  네트워크 5개 존      Snort IPS           Bee-box 7종 공격    커스텀 룰 9개        대시보드 8패널
  방화벽 정책 설계     ModSecurity WAF     킬체인 7단계 공격    Splunk Alert 5개    실시간 모니터링
  자산 배치           Splunk SIEM         MITRE ATT&CK 매핑   상관분석 쿼리        차단·검증 수행
```

### 1-3. 핵심 성과 요약

- 7단계 킬체인 공격 중 **5단계에서 공격 시도를 탐지**(Alert 트리거 또는 로그 기록), 1단계 부분 탐지(DB 접근), 1단계 외부 전송 실패 확인
- Splunk Alert 5종 설계 → **4종 정상 트리거** 확인 (Scanner Detection은 발생 미확인 (원인 미확정))
- 공격자 IP 차단 후 재공격 시 **접근 차단** 검증 (curl 타임아웃, WPScan Aborted)
- 데이터 유출 시도 시 **외부 전송 실패** 확인 (Connection refused — 원인: 방화벽 아웃바운드 차단 또는 수신 서비스 미존재, 방화벽 로그 추가 확인 필요)
- 탐지 한계 분석 및 **7건의 개선 권고** 도출

---

## 2. 환경 구성

### 2-0. 네트워크 설계 근거

#### 실제 기업 네트워크와의 대응 관계

본 프로젝트의 네트워크 설계는 실제 기업의 보안 아키텍처를 참고하여, SOC 관제에 필요한 핵심 요소를 격리된 랩 환경에 축소 구현하였다.

```
[실제 기업 네트워크]                          [본 프로젝트 랩 환경]
───────────────────                         ─────────────────────
인터넷 → Router → External F/W              인터넷 → VyOS Router
                    │                                    │
              DMZ Zone (WEB/DNS/메일)         att-net ── 공격자 격리 존
                    │                                    │
              Internal F/W + IPS              rf-net ── pfSense(F/W+Snort IPS)
                    │                            ┌───────┼───────┐
          ┌────────┼────────┐              dmz-net   inner-net   mng-net
     Server Zone  DB Zone  User Zone       (웹서버)   (DB/SIEM)   (관제PC)
     (WAS 1~4)   (DB#1~2)  (사용자)
          │
     Backup Zone / 보안존(DLP,접근통제)
```

#### 존(Zone) 분리 설계 의도

| 존 | 서브넷 | 설계 의도 | 실제 기업 대응 영역 |
|----|--------|----------|-------------------|
| **att-net** | 10.50.50.0/24 | 공격 트래픽을 내부망과 완전 격리. VyOS를 경유해야만 내부 접근 가능하도록 하여, 실제 외부 공격자가 인터넷에서 유입되는 시나리오를 모사 | 인터넷(외부 위협 영역) |
| **rf-net** | 10.0.0.0/24 | VyOS↔pfSense 간 전송 네트워크. 모든 외부 트래픽이 pfSense(Snort IPS)를 **반드시 통과**하도록 강제하는 choke point 역할 | Router ↔ External F/W 구간 |
| **dmz-net** | 10.0.10.0/24 | 외부에 노출되는 웹서버(WordPress, Bee-box)를 내부 DB/SIEM과 분리. 웹서버가 침해되더라도 inner-net 직접 접근 제한 | DMZ Zone (WEB#1, WEB#2) |
| **inner-net** | 10.0.100.0/24 | DB(MySQL), SIEM(Splunk) 등 민감 자산 보호. DMZ에서 필요한 포트(MySQL 3306)만 화이트리스트로 허용하고 나머지 차단 → **최소 권한 원칙** 적용 | Server Zone + DB Zone |
| **mng-net** | 10.0.50.0/24 | SOC 분석가(관제) 전용 네트워크. 공격/DMZ 트래픽과 격리하여 관제 시스템의 안전성 확보 | 사무실 / 보안관제센터 |

#### 핵심 보안 설계 원칙

**1) Defense in Depth (심층 방어)**
- L3 라우팅(VyOS)과 보안 필터링(pfSense+Snort)을 별도 장비로 분리
- 네트워크 레벨(Snort IPS) + 애플리케이션 레벨(ModSecurity WAF) + 로그 분석(Splunk SIEM) 3중 탐지 체계

**2) Network Segmentation (네트워크 분리)**
- 5개 존 분리로 Lateral Movement(횡이동) 경로 제한
- DMZ→inner-net 방향은 WordPress→MySQL:3306만 허용, 나머지 전면 차단
- DMZ 아웃바운드(외부 방향) 차단 정책 설정 → 외부 데이터 유출 경로 제한 (실제 차단 여부는 방화벽 로그로 확인 필요)

**3) Choke Point (집중 관제 지점)**
- 모든 외부 트래픽이 pfSense를 통과하도록 설계 → Snort IPS가 100% 트래픽 검사 가능
- 방화벽 로그 + IPS 경보를 Splunk로 전량 수집하여 가시성 확보

#### 교육 과정 기본 랩 대비 확장 사항

이글루코퍼레이션 교육 과정의 기본 랩(Bee-box 단일 웹서버)을 실제 기업 환경에 가깝게 확장하였다.

| 항목 | 기본 랩 (교육 과정) | 확장 후 (본 프로젝트) |
|------|-------------------|-------------------|
| 웹서버 | Bee-box 1대 (bWAPP) | Bee-box + **WordPress** (실제 CMS) |
| DB | Bee-box 내장 MySQL | **독립 MySQL 서버** (inner-net 별도 VM) |
| WAF | 없음 | **ModSecurity 2.9.3** + OWASP CRS 3.2.0 |
| 공격자 | att-mint 1대 | att-mint + **Kali Linux** |
| 로그 소스 | Snort + filterlog (2개) | **8개** (Snort, filterlog, Apache×2, ModSec, WP auth, MySQL×2) |
| 트래픽 | 공격만 | 공격 + **정상 트래픽** 혼합 |
| 탐지 | 기본 Snort 룰셋 | 커스텀 Snort 룰 9개 + Splunk Alert 5개 + 상관분석 |
| 관제 | 없음 | **SOC 대시보드** 8패널 + 관제 일지 |

### 2-1. 네트워크 토폴로지

```
att-mint(10.50.50.17) ──att-net──→ VyOS ──rf-net──→ pfSense(+Snort IPS)
Kali   (10.50.50.30) ─┘                                  │
                                                     ┌─ dmz-net ──→ WordPress(10.0.10.80) + ModSecurity WAF
                                                     │              Bee-box  (10.0.10.50)
                                                     ├─ inner-net ──→ Splunk(10.0.100.50)
                                                     │                MySQL (10.0.100.60)
                                                     └─ mng-net ──→ mng-mint(10.0.50.100, 관제+정상유저)
```

### 2-2. 자산 목록

| 자산 | IP | 존 | 역할 | 보안 솔루션 |
|------|-----|-----|------|-----------|
| VyOS | eth2: 10.50.50.1, eth1: 10.0.0.1 | att-net / rf-net | 외부 라우터 | NAT, Static Routing |
| pfSense | WAN: 10.0.0.254, LAN: 10.0.50.1, OPT1: 10.0.10.1, OPT2: 10.0.100.1 | rf-net / mng / dmz / inner | 방화벽 + IPS | Snort (GPLv2 + ET Open + 커스텀 룰 9개) |
| WordPress | 10.0.10.80 | dmz-net | 회사 홈페이지 | ModSecurity 2.9.3 + OWASP CRS 3.2.0 (DetectionOnly) |
| Bee-box | 10.0.10.50 | dmz-net | 취약 웹서버 (bWAPP) | — |
| MySQL | 10.0.100.60 | inner-net | DB 서버 | — |
| Splunk | 10.0.100.50:8000 | inner-net | SIEM | 4개 인덱스, 8개 로그 소스 |
| att-mint | 10.50.50.17 | att-net | 공격자 PC | — |
| Kali | 10.50.50.30 | att-net | 공격 전용 PC | — |
| mng-mint | 10.0.50.100 | mng-net | 관제/관리 PC | — |

### 2-3. 방화벽 정책 설계

| 인터페이스 | 방향 | 정책 | 설계 의도 |
|-----------|------|------|----------|
| WAN | 외부→DMZ | NAT 8080→80 (WordPress) | 외부 웹 접근 허용 (포트 변환) |
| WAN | 외부→내부 | Default Deny | 불필요한 외부 접근 차단 |
| DMZNET | DMZ→MySQL | Pass TCP 3306 (10.0.10.80→10.0.100.60) | WordPress DB 연동만 허용 |
| DMZNET | DMZ→inner-net | Block (나머지 전체) | 웹서버 침해 시 내부망 확산 방지 |
| DMZNET | DMZ→외부 | Block (아웃바운드 전체) | 데이터 유출 경로 차단 |
| INNERNET | inner→any | Default Deny | 민감 자산 외부 노출 차단 |

### 2-4. 로그 수집 체계

| 로그 소스 | 수집 경로 | Splunk 인덱스 | 탐지 목적 |
|----------|----------|-------------|----------|
| Snort alerts | pfSense syslog → UDP 514 | pfsense | 네트워크 레벨 침입 탐지 |
| pfSense filterlog | pfSense syslog → UDP 514 | pfsense | 방화벽 룰 매칭 로그 |
| Apache access log | rsyslog → TCP 9514 | idx_web | HTTP 요청 패턴 분석 |
| Apache error log | rsyslog → TCP 9514 | idx_web | 웹서버 에러 및 WAF 로그 |
| ModSecurity audit | rsyslog → TCP 9514 | idx_web | WAF 탐지 상세 기록 |
| WP auth log | rsyslog → TCP 9514 | idx_web | 로그인 시도 추적 |
| MySQL error log | rsyslog → TCP 9516 | idx_db | DB 에러 모니터링 |
| MySQL slow query | rsyslog → TCP 9516 | idx_db | 비정상 쿼리 탐지 |

---

## 3. 공격 수행

### 3-1. Bee-box 기반 공격 실습 (Phase 1)

교육 과정의 기본 공격 실습으로, 7종의 웹 공격을 Bee-box(bWAPP) 대상으로 수행하고 Snort IDS의 탐지 능력을 검증하였다.

| 구분 | 공격 유형 | 도구 | Snort 탐지 | 비고 |
|------|----------|------|-----------|------|
| R-1 | TCP 포트스캔 | nmap -sS | ✅ sfPortscan | [그림 3-1] |
| E-1 | SQL Injection (수동) | 브라우저 | ✅ 4건 | |
| E-2 | SQL Injection (자동) | sqlmap | ✅ 211건 | |
| E-3 | Reflected XSS | 브라우저 | ✅ 3건 | |
| E-4 | Stored XSS | 브라우저 | ❌ 미탐지 | 해당 실습의 룰·설정에서 탐지되지 않음 |
| E-5 | OS Command Injection | 브라우저 | ⚠️ 1건 | 응답 측만 탐지 (ATTACK_RESPONSE) [그림 3-2] |
| E-7 | 브루트포스 | hydra 시도 후 수동 | ❌ 미탐지 | NAT 리다이렉트로 자동화 실패, 수동 로그인 성공. WordPress 경보 8건과 별개 |

**핵심 발견**: 이번 실습에서 적용한 Snort 룰·설정은 저장형 XSS(E-4)를 탐지하지 못함 → **다중 탐지 소스(WAF, 애플리케이션 로그)의 필요성** 확인 [그림 3-4]

### 3-2. WordPress 킬체인 7단계 공격 (Phase 3)

실제 기업 환경을 모사한 WordPress 홈페이지 대상으로, 공격자 관점의 **킬체인 7단계 시나리오**를 설계·수행하였다.

| 단계 | Kill Chain | MITRE ATT&CK | 공격 도구 | 수행 결과 |
|------|-----------|-------------|----------|----------|
| 1 | 정찰 | T1595 Active Scanning | WPScan | WP 7.1 식별, XML-RPC 활성화, Upload 디렉토리 리스팅 노출 [그림 3-5] |
| 2 | 초기 침투 시도 | T1190 Exploit Public-Facing App | sqlmap | SQLi 실패 (WP 코어 Prepared Statement 보호) — 공격 시도 자체가 로그에 기록 |
| 3 | 인증 공격 | T1110 Brute Force | hydra | admin/rlaquddn1@ 크래킹 성공 (POST 965건 기록) [그림 3-6] |
| 4 | 지속성 확보 | T1505.003 Web Shell | WP File Manager 8.0.4 (관리자 편집 경로) | hello.php에 PHP 웹쉘 삽입, `/?cmd=` 경로로 명령 실행 [그림 3-7] |
| 5 | 내부 정찰 | T1046 Network Service Scan | 웹쉘 CLI | DMZ IP(10.0.10.80), DB 인증정보(wp_admin/WpAdmin!2024) 획득 [그림 3-8] |
| 6 | DB 접근 | T1213 Data from Info Repos | mysql (웹쉘 경유) | wp_users 테이블 탈취 — admin 계정 + bcrypt 해시 [그림 3-9] |
| 7 | 유출 시도 | T1041 Exfiltration Over C2 | curl | **실패** — Connection refused 발생. 원인: DMZ 아웃바운드 차단 정책 또는 수신 서비스 미존재 (방화벽 로그 확인 필요) |

---

## 4. 탐지 엔지니어링

### 4-1. Snort 커스텀 룰 설계

기본 Snort 룰셋(GPLv2 + ET Open)만으로는 WordPress 특화 공격 탐지에 한계가 있어, 킬체인 각 단계에 대응하는 **커스텀 룰 9개**를 직접 작성하였다. [그림 4-1]

**설계 룰 (git local.rules 기준):**

| git SID | 탐지 대상 | 킬체인 단계 | 룰 로직 |
|---------|----------|-----------|---------|
| 1000001 | WP Login 브루트포스 | 3단계 | POST /wp-login.php 5회/60초 초과 |
| 1000002 | XML-RPC 브루트포스 | 3단계 | POST /xmlrpc.php + wp.getUsersBlogs |
| 1000003 | PHP 파일 업로드 | 4단계 | multipart/form-data + .php |
| 1000004 | PHTML WAF 우회 업로드 | 4단계 | .phtml 확장자 업로드 |
| 1000005 | DMZ→Inner-net 비정상 통신 | 5단계 | 10.0.10.0/24 → 10.0.100.0/24 !3306 |
| 1000006 | DMZ→관리망 접근 | 5단계 | 10.0.10.0/24 → 10.0.50.0/24 |
| 1000007 | 웹쉘 명령 출력 | 4단계 | 응답에 uid= + gid= 패턴 |
| 1000008 | WP File Manager CVE | 4단계 | connector.minimal.php URI |
| 1000009 | WPScan 스캐너 탐지 | 1단계 | User-Agent "WPScan" |

> **⚠️ SID 매핑 불일치**: pfSense에 실제 배포된 룰은 git 버전과 SID 번호·내용이 다르다. 운영 중 룰을 수동 수정/추가하면서 발생한 차이이며, 본 보고서의 탐지 결과는 **pfSense 실제 배포 SID** 기준으로 기술한다.
>
> | pfSense SID | pfSense 실제 메시지 | 대응 git SID | 비고 |
> |-------------|-------------------|-------------|------|
> | 1000001 | LOCAL WordPress wpscan detected | git 1000009 | SID 번호 불일치 |
> | 1000002 | LOCAL WordPress login brute-force attempt | git 1000001 | SID 번호 불일치 |
> | 1000004 | LOCAL SQL Injection attempt UNION SELECT | — | git에 없는 룰 (pfSense에서 추가) |
> | 1000006 | LOCAL Webshell access attempt | git 1000007 | SID·메시지 모두 다름 |

### 4-2. Splunk Alert 설계

| Alert 이름 | Severity | 주기 | 트리거 조건 | 탐지 대상 |
|-----------|----------|------|-----------|----------|
| Scanner Detection | High | */5분 | Snort pfSense SID 1000001 (wpscan detected) ≥ 10건 | 정찰 도구 탐지 |
| Brute Force Detection | Critical | */5분 | wp-login.php POST ≥ 10건 | 로그인 브루트포스 |
| SQL Injection Detection | Critical | */5분 | Snort SQL/SID 1000004 ≥ 2건 | SQLi 시도 |
| Webshell Detection | Critical | */5분 | idx_web "cmd=" ≥ 1건 | 웹쉘 명령 실행 |
| WAF Alert Surge | Medium | */10분 | ModSecurity 이벤트 ≥ 30건 | WAF 탐지 급증 |

### 4-3. 상관분석 쿼리

킬체인 단계별 시간순 상관분석을 통해 단일 이벤트가 아닌 **공격 흐름 전체**를 파악하도록 설계하였다.

[그림 4-2] SOC 대시보드 전체 화면
[그림 4-3] Splunk 킬체인 Timechart
[그림 4-4] 킬체인 6단계 상관분석 차트

### 4-4. 탐지 결과 종합

| 킬체인 단계 | MITRE ATT&CK | 공격 시도 탐지 | 경보(Alert) 발생 | 침해 여부 확인 | 대응 |
|------------|-------------|-------------|---------------|-------------|------|
| 1. 정찰 | T1595 | ✅ Snort ET SCAN + pfSense SID 1000001 | ⚠️ Scanner Detection (Triggered Alerts 발생 미확인 (원인 미확정), Snort 경보에서 직접 확인) | — (정찰 단계) | L1 모니터링 |
| 2. SQLi 시도 | T1190 | ✅ Snort ET SQL + pfSense SID 1000004 | ✅ SQL Injection Detection | 공격 실패 (Prepared Statement 보호) | 기록 |
| 3. 브루트포스 | T1110 | ✅ Apache 로그 POST 965건 + ModSecurity Rule 913100 | ✅ Brute Force Detection + WAF Alert Surge | 인증 성공 (admin 크래킹) | L2 대응 |
| 4. 웹쉘 | T1505.003 | ✅ Apache 로그 cmd= 요청 + ModSecurity | ✅ Webshell Detection + WAF Alert Surge | 명령 실행 성공 (uid=33 확인) | L3 긴급 대응 |
| 5. 내부 정찰 | T1046 | ✅ Apache 로그 cmd= (4단계 탐지에 포함) | (4단계 Alert에 포함) | wp-config.php DB 인증정보 획득 | — |
| 6. DB 접근 | T1213 | ⚠️ 간접 탐지 (웹쉘 cmd= 로그) | ❌ 전용 Alert 미설정 | DB 데이터 조회 성공 | L4 긴급 대응 |
| 7. 유출 시도 | T1041 | ❌ 전용 탐지 미설정 | ❌ — | 외부 전송 실패 (Connection refused) | — |

**탐지 기준별 정리:**

| 기준 | 결과 | 설명 |
|------|------|------|
| **공격 시도 탐지** (로그 기록 또는 IPS 경보) | 5/7 단계 | 1~5단계. 6단계는 간접 탐지, 7단계는 탐지 미설정 |
| **경보(Alert) 발생** | 5종 중 4종, 총 8회 | 2026-08-27 19:45 KST 최종 캡처 기준. 공격 단계별 커버리지와 별도로 집계 |
| **침해 성공 확인** | 4/7 단계 | 3~6단계에서 실제 침해 발생 (인증 크래킹, 웹쉘 실행, DB 접근 성공) |
| **외부 전송 실패** | 1/7 단계 | 7단계 curl → Connection refused (원인 미확정: 방화벽 차단 또는 수신 서비스 미존재) |

> **참고 — 미시험 항목**: 설계한 커스텀 룰 중 .phtml 업로드(SID 1000004), DMZ→관리망 접근(SID 1000006) 등은 해당 공격 경로를 **실행하지 않아 탐지 여부를 확인할 수 없다**. 이들은 "미탐지"가 아닌 **"미시험"**으로 분류한다.

---

## 5. 관제 운영

### 5-1. SOC 대시보드 구성

8개 패널, 3단 레이아웃으로 실시간 관제 대시보드를 구성하였다.

| 패널 | 내용 | 공격 시 변화 |
|------|------|------------|
| events | 전체 이벤트 수 | 80,425 → 83,916건 증가 |
| time | 시간대별 추이 | 공격 시간대(18:49~19:40) 급증 |
| att_type | 공격 유형 파이차트 | ET SCAN 비율 급증 |
| att_ip | 공격자 IP Top5 | 10.50.50.30 최다 |
| waf | WAF 탐지 현황 | ModSecurity Rule 949110, 913100 |
| alerts | 최근 Snort 경보 | ET SCAN, SID 1000004 |
| db_approach | MySQL 에러 로그 | DNS 해석 경고 347건; DB 조회 감사 로그와 구분 |
| login_history | 로그인 시도 IP별 | 10.50.50.30: POST 965건 (로그인 시도 횟수, 실패·성공 미구분) |

### 5-2. Alert 트리거 현황

[그림 5-1] Triggered Alerts 최종 8건

| 시각 | Alert | Severity | 트리거 원인 |
|------|-------|----------|-----------|
| 19:45:00 | Webshell Detection | Medium | 최종 Triggered Alerts 캡처에서 확인; 해당 검색 결과의 상세 원인은 추가 확인 |
| 19:40:02 | WAF Alert Surge | Medium | 웹쉘 명령 실행 → ModSecurity 탐지 |
| 19:35:01 | Webshell Detection | Medium | `/?cmd=id`, `/?cmd=whoami` 등 |
| 19:35:01 | SQL Injection Detection | Critical | Snort SID 1000004 UNION SELECT 4건 |
| 19:30:03 | WAF Alert Surge | Medium | ModSecurity anomaly score 초과 |
| 19:20:01 | WAF Alert Surge | Medium | hydra 브루트포스 → Rule 913100 |
| 19:20:01 | Brute Force Detection | Critical | idx_web wp-login.php POST 965건 (요청 수 기준, 실패·성공 미구분) |
| 19:10:01 | WAF Alert Surge | Medium | 브루트포스 초기 탐지 |

[그림 5-2] 실시간 모니터링 스플릿스크린

---

## 6. 대응 및 검증

### 6-1. 대응 타임라인

| 시각 | 이벤트 | 대응 단계 | 조치 |
|------|--------|---------|------|
| 18:49 | WPScan 정찰 탐지 | L1 모니터링 | 후속 공격 관찰 |
| 19:16 | Brute Force 시작 (POST 965건 기록) | L2 대응 준비 | 공격 패턴 분석 |
| 19:20 | Brute Force Detection Alert | L2 대응 | 공격 확정, 차단 검토 |
| 19:24 | SQL Injection 시도 (4건) | L2→L3 에스컬레이션 | 공격 에스컬레이션 확인 |
| 19:30 | 웹쉘 명령 실행 탐지 | L3 긴급 대응 | 침해 확인, 즉시 차단 결정 |
| 19:35 | DB 데이터 유출 확인 | L4 긴급 대응 | 차단 실행 지시 |
| 19:40 | pfSense WAN Block 룰 적용 | 차단 실행 | 10.50.50.30 TCP 접근 차단 |
| 19:40~ | 차단 검증 | 검증 | curl 타임아웃, WPScan Aborted 확인 |

### 6-2. 차단 조치 및 검증

| 조치 | 상세 |
|------|------|
| pfSense WAN Block | Source: 10.50.50.30, Protocol: TCP, Dest: Any — WAN 룰 최상단 배치 [그림 6-1] |
| 검증 — curl | `curl -s --max-time 10 "http://10.0.0.254:8080/"` → 응답 없음 (타임아웃) [그림 6-2] |
| 검증 — WPScan | "Scan Aborted: seems to be down (Timeout was reached)" [그림 6-3] |

---

## 7. 분석 및 개선 권고

### 7-1. 탐지 체계 분석

| 구분 | 강점 | 한계 |
|------|------|------|
| Snort IPS | 네트워크 레벨 시그니처 탐지에 효과적 (SQLi, 스캐너) | 행위 기반 공격(브루트포스) 탐지율 낮음 — Apache POST 965건 중 Snort 8건만 탐지 (Snort는 threshold 기반으로 집계하므로 단순 비교는 부정확) |
| ModSecurity WAF | 공격 도구 User-Agent 효과적 탐지 (hydra, sqlmap) | DetectionOnly 모드로 실제 차단 미수행 |
| Splunk SIEM | 다중 소스 상관분석으로 킬체인 전체 가시성 확보 | Alert cron 주기(5분) 내 미스매치 가능 |
| 네트워크 분리 | DMZ 아웃바운드 차단 정책으로 외부 유출 경로 제한 | DMZ→MySQL 3306 허용이 공격 피벗에 악용됨. 유출 실패 원인(방화벽 vs 수신 서비스 미존재) 미확정 |

### 7-2. 개선 권고

| 영역 | 현재 상태 | 개선 방안 | 우선순위 |
|------|----------|----------|---------|
| 브루트포스 탐지 | Snort 8건(threshold 집계) vs Apache POST 965건(요청 수) | Apache 로그 기반 Alert을 주 탐지 소스로 운용. 로그인 실패만 카운트하도록 쿼리 개선 필요 | 높음 |
| DB 접근 탐지 | 정상/비정상 구분 불가 | MySQL Audit Plugin 활성화 + 비정상 쿼리 패턴 Alert | 높음 |
| WAF 모드 | DetectionOnly (탐지만) | SecRuleEngine On 전환하여 실제 차단 | 중간 |
| DMZ↔Inner-net | WordPress→MySQL 3306 허용 | DB 프록시 도입 또는 접근 제어 강화 | 중간 |
| WordPress 보안 | wp-config.php 평문 인증정보 | 인증정보 환경변수 분리, 불필요 플러그인 제거, 2FA 적용 | 중간 |
| 로그 인덱스 | idx_waf 비어있음 | ModSecurity 전용 인덱스 분리 수집 | 낮음 |
| Alert 주기 | 발생 미확인 (원인 미확정) | 검색 실행 이력·시간 범위·임계값·수집 지연 확인 후 조정 | 낮음 |

---

## 8. SOC 분석가 사고 확장

> 이 프로젝트는 격리된 가상 환경에서의 실습이다. 실제 SOC 관제 환경에서는 아래와 같은 추가 분석과 판단이 요구된다.

### 8-1. 실무 확장 — IP 차단 시 추가 분석

```
실습에서 한 것:    10.50.50.30 차단 → 끝
실무에서 할 것:    IP 평판 조회(VirusTotal, AbuseIPDB) → 동일 C2 대역 식별
                  → 유사 패턴 IP 일괄 차단 → Lateral Movement 모니터링 강화
```

### 8-2. 위협 모델링 — STRIDE 분류

| 킬체인 단계 | STRIDE | 대응 방향 |
|------------|--------|---------|
| 브루트포스 | Spoofing | 인증 강화 (2FA, 계정 잠금) |
| 웹쉘 삽입 | Tampering | 파일 무결성 검증 (FIM) |
| 웹쉘 경유 | Repudiation | 감사 로그 강화 |
| DB 탈취 | Info Disclosure | 데이터 접근 통제, 암호화 |
| 대량 스캔 | DoS 가능성 | Rate Limiting |
| 명령 실행 | Elevation of Privilege | 최소 권한 원칙 |

### 8-3. 비즈니스 영향 평가 — PASTA 관점

| 취약점 | 기술적 심각도 | 비즈니스 영향 | 우선순위 |
|--------|------------|------------|---------|
| wp-config.php 인증정보 노출 | High | Critical — 고객 데이터 유출 시 법적 책임 | 1순위 |
| 약한 비밀번호 | Medium | High — 관리자 권한 탈취 → 사이트 변조 가능 | 2순위 |
| WP File Manager 취약점 | High | High — 웹쉘 삽입 → 서버 장악 가능 | 3순위 |
| ModSecurity DetectionOnly | Low | Medium — 탐지는 하지만 차단 미수행 | 4순위 |

### 8-4. 실무에서 추가로 수행할 분석

- **타임라인 심층 분석**: 공격자의 dwell time(체류 시간), 자동화 수준 판단
- **Lateral Movement 모니터링**: 웹쉘에서 inner-net 방향 3306 외 접근 시도 확인
- **DB 접근 상세 분석**: MySQL Audit Plugin으로 쿼리 레벨 로깅
- **유출 경로 다각화 검토**: DNS 터널링, HTTP 응답 body 삽입 등 우회 가능성

### 8-5. EDR 연계 및 AI 관제 자동화

```
[현재 — 네트워크 레벨 탐지만]
  Apache 로그 → "cmd=" 패턴 탐지 → 수동 웹쉘 확인

[EDR 연계 시]
  www-data → shell_exec() → mysql 자식 프로세스 → 파일 변경(hello.php) 자동 탐지 → 엔드포인트 격리

[AI 관제 시]
  10건 시점에서 브루트포스 비정상 패턴 인식 → 정찰 직후 후속 공격 예측 → 대응 자동화
```

---

## 부록

### A. IOC (Indicators of Compromise)

**공격자 IP:**
| IP | 역할 | 차단 여부 |
|-----|------|---------|
| 10.50.50.30 | Kali Linux (킬체인 공격) | ✅ pfSense WAN Block |
| 10.50.50.17 | att-mint (Bee-box 공격) | ✅ pfSense WAN Block (Phase 2) |

**악성 User-Agent:**
| User-Agent | 도구 | 탐지 소스 |
|-----------|------|----------|
| `WPScan v3.8.28` | WPScan | Snort ET SCAN |
| `Mozilla/5.0 (Hydra)` | hydra | Apache + ModSecurity Rule 913100 |
| `sqlmap/1.10.6#stable` | sqlmap | Snort SID 1000004 |

### B. Splunk 쿼리 모음

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

### C. 관제 일지 요약

| 번호 | 제목 | 위험도 | 판별 |
|------|------|--------|------|
| INC-001 | WPScan 정찰 탐지 | Medium | 정탐 |
| INC-002 | WordPress 브루트포스 공격 | Critical | 정탐 |
| INC-003 | SQL Injection 공격 | Critical | 정탐 |
| INC-004 | 웹쉘 명령 실행 탐지 | Critical | 정탐 |
| INC-005 | DB 데이터 유출 | Critical | 정탐 |
| INC-006 | 공격자 IP 차단 및 검증 | — | 차단 성공 |

### D. MITRE ATT&CK 매핑

| Tactic | Technique | ID | 탐지 | 탐지 소스 | Alert |
|--------|-----------|-----|------|----------|-------|
| Reconnaissance | Active Scanning | T1595 | ✅ | Snort ET SCAN | Scanner Detection |
| Initial Access | Exploit Public-Facing App | T1190 | ✅ | Snort SID 1000004 | SQL Injection Detection |
| Credential Access | Brute Force | T1110 | ✅ | Apache + ModSecurity | Brute Force + WAF Alert |
| Persistence | Web Shell | T1505.003 | ✅ | Apache (cmd=) | Webshell + WAF Alert |
| Discovery | Network Service Scanning | T1046 | ✅ | Apache (cmd=) | Webshell에 포함 |
| Collection | Data from Info Repos | T1213 | ⚠️ | 간접 탐지 | (미설정) |
| Exfiltration | Over C2 Channel | T1041 | ❌ | 전송 실패 확인 (탐지 미설정, 원인 미확정) | — |
