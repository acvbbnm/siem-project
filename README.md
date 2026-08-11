# SIEM 공격 탐지 및 대응 실습 프로젝트

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
| Kali Linux (공격자) | TBD | att-net | 공격 전용 PC (추가 예정) |
| Bee-box (웹서버) | 10.0.10.50 | dmz-net | 취약 웹서버 (bWAPP) |
| Ubuntu/Splunk (SIEM) | 10.0.100.50 | inner-net | 로그 수집/분석 |
| mng-mint (관리자) | 10.0.50.17 | mng-net | 관제/관리 PC |

```
att-mint ──att-net──→ VyOS ──rf-net──→ pfSense(+Snort) ──dmz-net──→ Bee-box
                                            │
                                       inner-net──→ Splunk (로그 수집)
                                            │
                                        mng-net──→ mng-mint (관제)
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
  - [x] mng-mint(10.0.50.17) 설치 및 mng-net 연결
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
- [ ] Kali Linux VM 설치 (att-net, ESXi에 추가)
  - [ ] Kali Linux ISO 다운로드 및 VM 생성
  - [ ] att-net 네트워크 연결 및 IP 확인
- [ ] Kali 공격 도구 확인 (nmap, nikto, sqlmap, hydra, metasploit 등 기본 탑재)
  - [ ] 정찰 도구 확인 (nmap, nikto, dirb)
  - [ ] 익스플로잇 도구 확인 (sqlmap, hydra, metasploit)
- [ ] Kali → Bee-box 접속 확인
  - [ ] pfSense NAT 경유 접속 확인 (`curl -I http://10.0.0.254`)
  - [ ] bWAPP 페이지 로딩 확인

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
  - [ ] Alerts 화면 캡처 저장 (이미지 업로드 필요)

**Splunk 로그 분석**
- [x] Splunk 로그 분석 — 공격자 IP 식별
  - [x] `"Priority" "10.50.50.17"` → **1,142건 (97.8%)** 확인 — 공격자 IP 특정 완료
- [x] Splunk 로그 분석 — 공격 유형별 분류
  - [x] 카테고리별 Top 7: ET WEB_SERVER(640), SCAN(155), WEB_SPECIFIC_APPS(65), POLICY(17), INFO(9), EXPLOIT(4), ATTACK_RESPONSE(2)
- [x] Splunk 로그 분석 — 시간대별 공격 분포
  - [x] timechart 실행: 8/3(925건), 8/4(214건), 8/10(31건) — Visualization 차트 확인 완료
  - [ ] 시간대별 추이 차트 캡처 (이미지 업로드 필요)

**방화벽 정책 대응**
- [ ] 1차 대응: 공격자 IP 전체 차단 (WAN 규칙)
  - [x] 적용 전 WAN 규칙 확인 (NAT→10.0.10.50:80 + 기본 Block)
  - [ ] WAN에 10.50.50.17 Block 규칙 추가 ← **여기까지 진행됨**
  - [ ] 적용 전/후 규칙 캡처
- [ ] 2차 대응: 서비스 제한 (HTTP만 허용, DMZ 아웃바운드 차단)
  - [ ] HTTP(TCP/80)만 허용, 나머지 차단 규칙 적용
  - [ ] DMZ→내부(10.0.100.0/24) 차단
  - [ ] DMZ 아웃바운드 차단 (리버스쉘 방지)
- [ ] 3차 대응: Snort 차단 모드 전환 (Block Offenders 활성화)
  - [ ] Block Offenders + Kill States 체크
  - [ ] Block Duration(3600초) 설정
  - [ ] 변경 전/후 설정 캡처
- [ ] 대응 규칙 적용/해제 순서표 정리 (1~3차 on/off 순서 → Phase 3 검증 선행조건)

### Phase 3. 관제 운영 (SOC 시뮬레이션)

**모니터링 체계 구축**
- [ ] Splunk 대시보드 구축 (공격 현황 시각화)
  - [ ] 실시간 이벤트 수 패널
  - [ ] 공격자 IP Top 5 / 공격 유형 분포 패널
  - [ ] 최근 경보 목록 테이블 패널
  - [ ] 대시보드 캡처 저장
- [ ] Splunk Alert 설정 (임계치 기반 경보)
  - [ ] 포트 스캔 탐지 알림 (동일 src 50회 이상)
  - [ ] 반복 공격 탐지 알림 (ALERT 10회 이상)
  - [ ] SQLi 탐지 알림

**관제 대응 및 검증**
- [ ] 관제 대응 프로세스 실행 (경보분류→분석→대응→검증)
  - [ ] 1단계: 경보 분류(Triage) — 오탐/위험도 판별
  - [ ] 2단계: 상세 분석 — 페이로드·성공여부·과거이력
  - [ ] 3단계: 대응 조치 — 위험도별 차단/모니터링
- [ ] 차단 검증 — IP 차단 후 재공격 시도
  - [ ] att-mint에서 curl/nmap/ping 재시도
  - [ ] 차단(Connection refused/timeout) 확인
- [ ] 차단 검증 — Snort 자동차단 동작 확인
  - [ ] SQLi 재시도 후 자동 차단 확인
  - [ ] pfSense Snort > Blocked 목록 확인
  - [ ] 차단 해제 → 재공격 → 재차단 검증

**보고**
- [ ] 관제 일지 작성
  - [ ] INC-xxx 양식으로 탐지 건별 기록 (incident-log.md)
- [ ] 최종 보고서 작성
  - [ ] Phase 1~3 결과 취합
  - [ ] 제출용 보고서 초안 생성 (`/phase-report`)

---

## 폴더 구조

```
project/
├── README.md              ← 이 파일 (전체 진행상황 체크리스트)
├── phase1-attack/          ← 공격 수행 기록
│   ├── README.md           ← Phase 1 상세 절차 및 결과
│   └── images/             ← 공격 실행 캡처
├── phase2-detect/          ← 탐지/분석 + 방화벽 정책
│   ├── README.md           ← Phase 2 상세 분석 및 정책
│   └── images/             ← Splunk 쿼리, Snort 경보, 방화벽 규칙 캡처
└── phase3-soc/             ← 관제 운영
    ├── README.md           ← Phase 3 관제 프로세스 및 결과
    ├── images/             ← 대시보드, 알림, 관제 화면 캡처
    └── incident-log.md     ← 관제 일지
```

---

## 산출물 목록

| 산출물 | 위치 | 상태 |
|--------|------|------|
| 인프라 구축 보고서 | `../13_SIEM_실습보고서.md` / `.docx` | 완료 |
| 공격 실행 기록 | `phase1-attack/README.md` | **완료** (R-1~R-4, E-1~E-7 전체 기록) |
| Splunk 분석 결과 | `phase2-detect/README.md` | **진행중** (Step 1~2 완료, Step 3 방화벽 정책 진행중) |
| 방화벽 정책 변경 이력 | `phase2-detect/README.md` | **진행중** (1차 대응 시작) |
| 관제 일지 | `phase3-soc/incident-log.md` | 미시작 |
| 최종 보고서 | `project/` | 미시작 |
