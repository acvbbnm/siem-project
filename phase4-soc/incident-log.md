# 관제 일지 (Incident Log)

> Phase 4 관제 운영 중 탐지된 경보를 기록한다.
> 작성일: 2026-08-27

---

## [INC-001] WPScan 정찰 탐지

| 항목 | 내용 |
|------|------|
| 탐지 시각 | 2026-08-27 18:49~18:50 KST |
| 탐지 출처 | Snort (pfSense WAN) |
| 경보명 | ET SCAN Suspicious User-Agent Containing Security Scanner Likely Scan |
| 공격자 IP | 10.50.50.30 (Kali) |
| 대상 | WordPress (10.0.10.80, NAT 10.0.0.254:8080) |
| 공격 유형 | T1595 — Active Scanning |
| 위험도 | Medium |
| 판별 | **정탐** |
| 판별 근거 | Snort ET SCAN 시그니처 다수 탐지. WPScan User-Agent(Mozilla/5.0 (compatible; WPScan)) 확인. 대시보드 alerts 패널에 10.50.50.30 → 10.0.0.254 다수 기록. att_type 파이차트에 ET SCAN 비율 급증. |
| 대응 조치 | 모니터링 지속 (L1). 후속 공격 여부 관찰. |
| 검증 결과 | 후속 공격(브루트포스, SQLi) 발생 확인 → L2 이상 대응으로 격상 |
| 담당자 | SOC Analyst |
| 비고 | Scanner Detection Splunk Alert는 발생 원인 미확정으로 Triggered Alerts에 미표시. Snort 경보(pfsense 인덱스)에서 직접 확인. |

---

## [INC-002] WordPress 브루트포스 공격

| 항목 | 내용 |
|------|------|
| 탐지 시각 | 2026-08-27 19:16~19:18 KST |
| 탐지 출처 | Splunk Alert (Brute Force Detection) + ModSecurity WAF (WAF Alert Surge) |
| 경보명 | Brute Force Detection (Critical) / WAF Alert Surge (Medium) |
| 공격자 IP | 10.50.50.30 (Kali) |
| 대상 | WordPress wp-login.php (10.0.10.80) |
| 공격 유형 | T1110 — Brute Force |
| 위험도 | **Critical** |
| 판별 | **정탐** |
| 판별 근거 | login_history 패널: 10.50.50.30에서 965건 로그인 시도 (정상 유저 10.0.50.100은 1건). Apache 로그에 `POST /wp-login.php` + User-Agent `Mozilla/5.0 (Hydra)` 확인. ModSecurity Rule 913100 "Found User-Agent associated with security scanner (hydra)" 탐지. Rule 949110 Inbound Anomaly Score Exceeded (Total Score: 8) CRITICAL 다수. |
| 대응 조치 | L2 대응 — pfSense WAN에 10.50.50.30 Block 룰 추가 (Step 후반 실행) |
| 검증 결과 | Splunk Triggered Alerts: 19:20 Brute Force Detection (Critical) + WAF Alert Surge (Medium) 트리거 확인 |
| 담당자 | SOC Analyst |
| 비고 | hydra 도구 사용. rockyou.txt 사전 파일 기반 공격. Snort SID 1000002(브루트포스)보다 Apache 로그 기반 탐지가 더 효과적. |

---

## [INC-003] SQL Injection 공격

| 항목 | 내용 |
|------|------|
| 탐지 시각 | 2026-08-27 19:24~19:25 KST |
| 탐지 출처 | Snort (pfSense WAN) + Splunk Alert (SQL Injection Detection) |
| 경보명 | SQL Injection Detection (Critical) |
| 공격자 IP | 10.50.50.30 (Kali) |
| 대상 | WordPress (10.0.10.80, NAT 10.0.0.254:8080) |
| 공격 유형 | T1190 — Exploit Public-Facing Application (SQL Injection) |
| 위험도 | **Critical** |
| 판별 | **정탐** |
| 판별 근거 | Snort SID 1000004 "LOCAL SQL Injection attempt UNION SELECT" 4건 탐지. 출발지 10.50.50.30 → 10.0.0.254:8080. sqlmap 자동화 도구에 의한 다양한 SQL 페이로드(boolean blind, UNION, error-based) 시도 확인. |
| 대응 조치 | L2 대응 — 공격자 IP 차단 (INC-002 대응과 통합) |
| 검증 결과 | Splunk Triggered Alerts: 19:35 SQL Injection Detection (Critical) 트리거 확인 |
| 담당자 | SOC Analyst |
| 비고 | sqlmap 도구 사용. WordPress 코어의 Prepared Statement 보호로 실제 SQLi 성공 여부는 불분명하나, 공격 시도 자체가 Snort에 탐지됨. |

---

## [INC-004] 웹쉘 명령 실행 탐지

| 항목 | 내용 |
|------|------|
| 탐지 시각 | 2026-08-27 19:30~19:35 KST |
| 탐지 출처 | Splunk Alert (Webshell Detection) + ModSecurity WAF (WAF Alert Surge) |
| 경보명 | Webshell Detection (Medium) / WAF Alert Surge (Medium) |
| 공격자 IP | 10.50.50.30 (Kali) |
| 대상 | WordPress (10.0.10.80) |
| 공격 유형 | T1505.003 — Server Software Component: Web Shell |
| 위험도 | **Critical** |
| 판별 | **정탐** |
| 판별 근거 | Apache 로그에 `/?cmd=id`, `/?cmd=whoami`, `/?cmd=cat+/etc/passwd` 요청 확인. 응답 본문에 `uid=33(www-data)`, 시스템 계정 목록(/etc/passwd) 노출. ModSecurity에서도 anomaly score 초과로 탐지. |
| 대응 조치 | L3 긴급 대응 — 공격자 IP 차단 + 웹쉘 파일 제거 필요 |
| 검증 결과 | Splunk Triggered Alerts: 19:35 Webshell Detection (Medium) 트리거 확인. WAF Alert Surge 19:40 추가 트리거. |
| 담당자 | SOC Analyst |
| 비고 | 웹쉘을 통해 wp-config.php의 DB 인증정보(wp_admin/WpAdmin!2024, DB_HOST 10.0.100.60) 유출. 후속 DB 접근(INC-005)으로 이어짐. |

---

## [INC-005] DB 데이터 유출

| 항목 | 내용 |
|------|------|
| 탐지 시각 | 2026-08-27 19:35~19:40 KST |
| 탐지 출처 | Splunk 대시보드 (db_approach 패널) |
| 경보명 | (Alert 미설정 — 웹쉘 경유 DB 접근) |
| 공격자 IP | 10.50.50.30 (Kali) → 웹쉘(10.0.10.80) → MySQL(10.0.100.60) |
| 대상 | MySQL (10.0.100.60) — wordpress DB, wp_users 테이블 |
| 공격 유형 | T1213 — Data from Information Repositories |
| 위험도 | **Critical** |
| 판별 | **정탐** |
| 판별 근거 | 웹쉘 경유 mysql 명령 실행으로 wp_users 테이블 SELECT 성공. admin 계정 정보(user_login, user_email, user_pass bcrypt 해시) 유출 확인. DB 접근은 WordPress 서버(10.0.10.80)에서 정상 DB 연결 경로를 통해 수행되어 별도 Alert 트리거 안 됨. |
| 대응 조치 | L4 긴급 대응 — 공격자 IP 차단 + DB 비밀번호 변경 + 웹쉘 제거 + wp-config.php 인증정보 교체 필요 |
| 검증 결과 | pfSense WAN에 10.50.50.30 Block 룰 추가 후 재공격 시도 → curl 타임아웃, WPScan "Scan Aborted: seems to be down (Timeout was reached)" 확인. 차단 성공. |
| 담당자 | SOC Analyst |
| 비고 | DMZ→Inner-net MySQL 허용 규칙(WordPress↔MySQL 연동용)이 공격 피벗에 악용됨. 네트워크 세그멘테이션 강화 권고. |

---

## [INC-006] 관제 대응 — 공격자 IP 차단 및 검증

| 항목 | 내용 |
|------|------|
| 조치 시각 | 2026-08-27 19:40~ KST |
| 조치 내용 | pfSense Firewall → Rules → WAN에 Block 룰 추가 |
| 차단 대상 | Source: 10.50.50.30, Protocol: TCP, Destination: Any |
| 룰 위치 | WAN 룰 최상단 (NAT 룰보다 앞에 배치) |
| 검증 방법 | Kali에서 재공격 시도 |
| 검증 결과 — curl | `curl -s --max-time 10 "http://10.0.0.254:8080/"` → 응답 없음 (타임아웃) |
| 검증 결과 — WPScan | `wpscan --url http://10.0.0.254:8080 --enumerate u` → "Scan Aborted: The url supplied seems to be down (Timeout was reached)" |
| 결론 | **차단 성공** — 공격자 IP에서의 모든 TCP 접근이 pfSense에서 드롭됨 |
| 담당자 | SOC Analyst |
| 비고 | att-mint(10.50.50.17)도 기존 Phase 2에서 Block 처리 완료. 두 공격자 IP 모두 차단 상태. |
