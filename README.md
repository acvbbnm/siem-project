# SIEM 공격 탐지 및 대응 실습 프로젝트

> 통합보안관제 가상환경에서 공격 수행 → 탐지/분석 → 관제 대응까지 전체 사이클 실습

---

## 인프라 현황

| 구성요소 | IP | 네트워크 | 역할 |
|---------|-----|---------|------|
| VyOS 라우터 | eth0:DHCP / eth1:10.0.0.1 / eth2:10.50.50.1 | out/rf/att | NAT + 라우팅 |
| pfSense 방화벽 | WAN:10.0.0.254 / LAN:10.0.50.1 / OPT1:10.0.10.1 / OPT2:10.0.100.1 | 전체 | 방화벽 + Snort IPS |
| att-mint (공격자) | 10.50.50.17 | att-net | 공격 수행 PC |
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

### Phase 0. 인프라 구축
- [x] ESXi 6.7.0 설치 및 데이터스토어 확장
- [x] VyOS 라우터 설치 (NAT Masquerade + 정적 라우팅)
- [x] pfSense 방화벽 설치 (4개 인터페이스 + IP 설정)
- [x] mng-mint / att-mint 설치
- [x] Bee-box(bWAPP) 설치 및 DMZ 배치
- [x] Ubuntu + Splunk 8.2.0 설치 (inner-net)
- [x] Snort IPS 설치 (WAN, GPLv2 + ET Open)
- [x] syslog 원격 전송 설정 (pfSense → Splunk UDP 514)
- [x] 로그 수집 확인 (index=pfsense, 483 events)

### Phase 1. 공격 수행 (att-mint → Bee-box)
- [ ] att-mint 공격 도구 설치 (nmap, nikto, sqlmap, hydra, dirb)
- [ ] bWAPP 접속 확인 (att-mint → pfSense NAT → Bee-box)
- [ ] R-1: TCP 포트 스캔 (nmap -sS)
- [ ] R-2: 서비스 버전 탐지 (nmap -sV)
- [ ] R-3: 웹 취약점 스캔 (nikto)
- [ ] R-4: 디렉토리 브루트포스 (dirb)
- [ ] E-1: SQL Injection (수동, bWAPP)
- [ ] E-2: SQL Injection (sqlmap 자동화)
- [ ] E-3: Reflected XSS
- [ ] E-4: Stored XSS
- [ ] E-5: OS Command Injection
- [ ] E-6: Directory Traversal
- [ ] E-7: Brute Force (hydra)

### Phase 2. 탐지/분석 + 방화벽 정책 (mng-mint)
- [ ] Snort Alerts 확인 (pfSense WebGUI)
- [ ] Splunk 로그 분석 — 공격자 IP 식별
- [ ] Splunk 로그 분석 — 공격 유형별 분류
- [ ] Splunk 로그 분석 — 시간대별 공격 분포
- [ ] 1차 대응: 공격자 IP 전체 차단 (WAN 규칙)
- [ ] 2차 대응: 서비스 제한 (HTTP만 허용, DMZ 아웃바운드 차단)
- [ ] 3차 대응: Snort 차단 모드 전환 (Block Offenders 활성화)

### Phase 3. 관제 운영 (SOC 시뮬레이션)
- [ ] Splunk 대시보드 구축 (공격 현황 시각화)
- [ ] Splunk Alert 설정 (임계치 기반 경보)
- [ ] 관제 대응 프로세스 실행 (경보분류→분석→대응→검증)
- [ ] 차단 검증 — IP 차단 후 재공격 시도
- [ ] 차단 검증 — Snort 자동차단 동작 확인
- [ ] 관제 일지 작성
- [ ] 최종 보고서 작성

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
| 공격 실행 기록 | `phase1-attack/README.md` | 미시작 |
| Splunk 분석 결과 | `phase2-detect/README.md` | 미시작 |
| 방화벽 정책 변경 이력 | `phase2-detect/README.md` | 미시작 |
| 관제 일지 | `phase3-soc/incident-log.md` | 미시작 |
| 최종 보고서 | `project/` | 미시작 |
