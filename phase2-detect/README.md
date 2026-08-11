# Phase 2. 탐지/분석 + 방화벽 정책

> mng-mint(10.0.50.17)에서 Splunk + pfSense를 통해 분석 및 대응
> Phase 1의 공격이 **모두 완료된 후** 진행한다.

---

## 사전 준비

### Splunk 필드 추출 설정 (중요)

> 현재 Splunk의 `index=pfsense` 로그는 CSV 원본(raw) 상태로, `src`, `dest_port`, `signature` 같은 필드가 자동 추출되지 않는다.
> Phase 2 분석 쿼리가 제대로 동작하려면 **아래 중 하나**를 먼저 수행해야 한다.

**방법 A: Splunk Add-on for pfSense (TA-pfsense) 설치 (권장)**
1. mng-mint에서 Splunk 접속 (`http://10.0.100.50:8000`)
2. Apps > Find More Apps > "pfsense" 검색 > `TA-pfsense` 설치
   - Splunk 계정 필요 (무료 계정으로 가능)
   - 또는 [Splunkbase](https://splunkbase.splunk.com/app/1527/)에서 `.tgz` 다운 → Splunk에 업로드
3. 설치 후 Splunk 재시작
4. 확인: `index=pfsense | table src dest dest_port signature` → 필드가 채워지면 성공

**방법 B: 수동 필드 추출 (TA 설치가 안 될 경우)**
1. Settings > Fields > Field Extractions > New Field Extraction
2. sourcetype = `syslog`, index = `pfsense`
3. 대표 이벤트에서 `src`, `dest`, `dest_port`, `signature` 필드를 드래그하여 추출 규칙 생성
4. 또는 정규식으로 직접 추출:
   ```
   # Snort alert에서 src IP 추출
   \{TCP\}\s+(?P<src>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?P<dest>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)
   ```

**방법 C: 쿼리 내 인라인 추출 (임시)**
```spl
index=pfsense snort
| rex "(?P<src>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?P<dest>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)"
| rex "snort\[\d+\]:\s+\[\S+\]\s+(?P<signature>[^\[]+)\s+\["
| table _time src dest dest_port signature
```
> 방법 C는 매 쿼리마다 `rex`를 넣어야 하므로 번거롭다. 가능하면 A 또는 B를 먼저 한다.

### 필드 추출 확인 테스트

```spl
index=pfsense src=10.50.50.17 | stats count by signature | sort -count | head 10
```
- 결과가 나오면 → 필드 추출 정상, Phase 2 진행 가능
- "No results" → 필드 추출 설정 필요

### 타임존 확인

- Splunk 계정 타임존: **Asia/Seoul (GMT+9)** 설정 완료 확인
- pfSense syslog 원본: **UTC**로 전송됨 (Phase 1에서 확인)
- Splunk이 자동 변환하므로 검색 시 KST 기준으로 시간 범위 지정하면 됨

---

## Step 1. Snort 경보 확인 (pfSense WebGUI)

> 먼저 pfSense의 Snort Alerts 화면에서 전체 경보를 한눈에 확인한다.
> 이후 Splunk에서 동일 이벤트를 쿼리로 분석하는 흐름.

### 확인 절차

1. mng-mint 브라우저에서 pfSense 접속: `https://10.0.50.1`
2. Services > Snort > Alerts
3. Interface: **WAN** 선택

### 확인해야 할 경보 카테고리

| 구분 | 공격 단계 | 예상 Snort 시그니처 | 심각도 | Phase 1 결과 |
|------|----------|-------------------|--------|-------------|
| 정찰 | R-1 포트스캔 | `[122:5:1] sfPortscan: TCP Filtered Portscan` | P2 | ✅ 탐지 |
| 정찰 | R-3 nikto | `ET WEB_SERVER /etc/passwd`, `WEBROOT DIRECTORY TRAVERSAL` 등 | P1~2 | ✅ 868건 |
| 정찰 | R-4 dirb | `GPL WEB_SERVER .htpasswd access`, `.htaccess access` 등 | P1~2 | ✅ 탐지 |
| 웹공격 | E-1 SQLi (수동) | `ET WEB_SERVER SELECT USER SQL Injection Attempt in URI` | P1 | ✅ 4건 |
| 웹공격 | E-2 SQLi (sqlmap) | `ET SCAN Sqlmap SQL Injection Scan` | P1 | ✅ 211건 |
| 웹공격 | E-3 Reflected XSS | `ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt` | P1 | ✅ 3건 |
| 웹공격 | E-4 Stored XSS | — | — | ❌ **미탐지** (IPS 한계) |
| 웹공격 | E-5 Command Injection | `ET WEB_SERVER cmd=` 또는 `/etc/passwd` | P1 | ⚠️ 응답측 1건 (`ET ATTACK_RESPONSE`) |
| 웹공격 | E-6 Directory Traversal | `ET WEB_SERVER /etc/passwd in URI` | P1 | ✅ 양방향 2건 |
| 인증 | E-7 Brute Force | `ET SCAN Hydra User-Agent Detected` | P2 | ❌ **미탐지** (행위기반 한계) |

### 확인 포인트 및 캡처

- [ ] Alerts 전체 목록 캡처 → `images/snort-alerts-overview.png`
- [ ] 정찰 관련 경보 필터 → `images/snort-alerts-recon.png`
- [ ] 웹 공격 관련 경보 필터 → `images/snort-alerts-exploit.png`
- [x] 총 Alert 건수 기록: **1,170건** (Snort 경보, Splunk 기준)
- [x] 가장 많이 발생한 시그니처 카테고리 Top 7:
  1. ET WEB_SERVER — 640건 (54.7%)
  2. ET SCAN — 155건 (13.2%)
  3. ET WEB_SPECIFIC_APPS — 65건 (5.6%)
  4. ET POLICY — 17건 (1.5%)
  5. ET INFO — 9건 (0.8%)
  6. ET EXPLOIT — 4건 (0.3%)
  7. ET ATTACK_RESPONSE — 2건 (0.2%)
- [x] pfSense WebGUI Snort Alerts 확인 완료 (Active Log에는 최근 ipify 정보성 경보만 잔존, Phase 1 공격 경보는 Splunk에 보존됨)

---

## Step 2. Splunk 로그 분석

접속: mng-mint Firefox → `http://10.0.100.50:8000` → Search & Reporting

### 2-1. 공격자 IP 식별

> 관제 실무에서는 "누가 공격했는지" 먼저 식별한다.

```spl
# 전체 이벤트에서 출발지 IP별 이벤트 수
index=pfsense | stats count by src | sort -count | head 10
```

**확인 포인트:**
- [ ] `10.50.50.17`이 최상위에 위치 = 공격자 IP 특정
- [ ] 다른 IP(10.0.100.1 등)는 pfSense 내부 트래픽 — 정상
- [ ] 캡처 → `images/splunk-src-stats.png`

### 2-2. 공격자 트래픽 전체 조회

```spl
# 공격자 IP 전체 트래픽 — 시간순
index=pfsense 10.50.50.17 | sort _time | table _time signature src dest
```

### 2-3. 공격 유형별 분류

```spl
# 시그니처별 탐지 건수 Top 10
index=pfsense 10.50.50.17 snort | top 10 signature

# 키워드 기반 분류 (필드 추출이 안 될 경우)
index=pfsense 10.50.50.17 "SQL"       | stats count as SQLi
index=pfsense 10.50.50.17 "portscan"  | stats count as PortScan
index=pfsense 10.50.50.17 "XSS" OR "script" | stats count as XSS
index=pfsense 10.50.50.17 "passwd"    | stats count as Traversal
```

**확인 포인트:**
- [ ] 공격 유형별 건수 정리표 작성
- [ ] 캡처: `top 10 signature` 결과 → `images/splunk-top-signature.png`

### 2-4. 목적지 포트 분포

```spl
index=pfsense 10.50.50.17 | stats count by dest_port | sort -count
```

- 예상: `80`(HTTP)이 압도적 — 모든 공격이 웹 대상이므로
- 다른 포트가 나오면 비정상 접근 시도 가능성

### 2-5. 시간대별 공격 분포 (핵심 시각화)

```spl
# 시그니처별 시간대 분포
index=pfsense 10.50.50.17 snort | timechart span=5m count by signature

# 전체 이벤트 시간대 분포
index=pfsense 10.50.50.17 | timechart span=1m count
```

**확인 포인트:**
- [ ] Phase 1의 "실제 수행 시각 기록표"와 대조하여 각 피크가 어떤 공격인지 매핑
  - 8/3 19:50~20:05 → R-1~R-4 정찰 (대량 스캔 트래픽)
  - 8/4 09:29~09:37 → E-1~E-2 SQLi
  - 8/4 10:03~10:04 → E-3 XSS
  - 8/4 10:08 → E-4 Stored XSS (이벤트 없을 수 있음)
- [ ] 시간대별 추이 차트 캡처 → `images/splunk-timechart.png`
- [ ] Visualization 탭에서 Line Chart로 전환하여 캡처

### 2-6. 공격 성공/실패 판별 (심화)

```spl
# HTTP 응답 코드 분포 (Snort가 HTTP inspect로 잡은 경우)
index=pfsense 10.50.50.17 | stats count by status

# SQL 에러 노출 = 공격 성공 지표
index=pfsense "SQL Errors in HTTP 200 Response" | stats count
```

- `HTTP 200` + SQL 에러 = 공격 성공 (서버가 에러를 클라이언트에 노출)
- `HTTP 403/404` = 차단/실패

### 분석 결과 종합

> Phase 1 완료 후 아래 표를 채운다.

| 분석 항목 | 결과 |
|----------|------|
| 총 이벤트 수 | **1,170건** (Snort 경보) |
| 공격자 IP | **10.50.50.17** — 1,142건 (97.8%) |
| 공격 유형 수 | 7개 카테고리 (ET WEB_SERVER, SCAN, WEB_SPECIFIC_APPS, POLICY, INFO, EXPLOIT, ATTACK_RESPONSE) |
| 가장 많은 시그니처 | ET WEB_SERVER — 640건 (54.7%) |
| Snort 미탐지 공격 | **E-4 Stored XSS** (POST body 미검사), **E-7 Brute Force** (행위기반 탐지 부재) |
| E-5 Command Injection | 응답측 1건만 탐지 (POST body 미검사, 응답의 /etc/passwd 노출만 탐지) |
| 시간대별 분포 | 8/3: 925건, 8/4: 214건, 8/5~9: 0건, 8/10: 31건 |
| 비고 | Snort가 WAN 인터페이스에서 동작하여 Bee-box IP(10.0.10.50) 대신 pfSense WAN IP가 목적지로 기록됨 |

---

## Step 3. 방화벽 정책 수립 및 적용

pfSense WebGUI > Firewall > Rules

> 분석 결과를 바탕으로 **단계적 방어 정책**을 적용한다.
> 각 단계마다 적용 전/후 규칙을 캡처하여 변경 이력을 남긴다.

### 1차 대응 — 공격자 IP 즉시 차단

> **근거:** Splunk 분석에서 `10.50.50.17`이 모든 공격의 출발지로 확인됨

**pfSense 설정 절차:**
1. Firewall > Rules > **WAN** 탭
2. Add (▲ 맨 위) — 새 규칙을 기존 규칙 위에 추가
3. 설정:

| 항목 | 값 |
|------|-----|
| Action | **Block** |
| Interface | WAN |
| Protocol | Any |
| Source | Single host or alias: `10.50.50.17` |
| Destination | Any |
| Description | `[Phase2-1차] 공격자 IP 차단 — INC-001` |

4. Save > Apply Changes

**적용 결과:**
- Action: **Block**, Interface: WAN, Protocol: **Any**, Source: **10.50.50.17**, Destination: Any
- 규칙 순서: Block(10.50.50.17) > Pass(NAT→10.0.10.50:80) > Block(기본) — **최상위 배치 확인**
- Apply Changes 완료 — "The changes have been applied successfully"

**차단 검증 (att-mint에서 실행):**
```
$ ping 10.0.10.50
From 10.50.50.1 icmp_seq=1 Destination Host Unreachable
(6 packets transmitted, 0 received, 100% packet loss)

$ curl http://10.0.10.50
curl: (7) Failed to connect to 10.0.10.50 port 80: No route to host
```
→ **ICMP·HTTP 모두 차단 확인 — 1차 대응 성공**

**캡처:**
- [ ] 적용 전 WAN 규칙 목록 → `images/fw-1st-before.png`
- [ ] 적용 후 WAN 규칙 목록 → `images/fw-1st-after.png`
- [ ] 차단 검증 결과 (ping + curl) → `images/fw-1st-verify.png`

### 2차 대응 — 서비스 제한 (HTTP만 허용 + DMZ 아웃바운드 차단)

> **근거:** 공격자 IP만 차단하면 다른 IP에서 같은 공격 가능 → 서비스 레벨에서 제한

**WAN 규칙 (Firewall > Rules > WAN):**

| 순서 | Action | Source | Destination | Protocol/Port | Description |
|------|--------|--------|-------------|--------------|-------------|
| 1 | **Pass** | Any | 10.0.10.50 | TCP/80 | HTTP만 허용 |
| 2 | **Block** | Any | Any | Any | 나머지 전체 차단 |

**DMZNET 규칙 (Firewall > Rules > OPT1):**

| 순서 | Action | Source | Destination | Protocol | Description |
|------|--------|--------|-------------|----------|-------------|
| 1 | **Block** | 10.0.10.0/24 | 10.0.100.0/24 | Any | DMZ→내부(Splunk) 차단 |
| 2 | **Block** | 10.0.10.0/24 | Any | Any | DMZ 아웃바운드 전체 차단 (리버스쉘 방지) |

**적용 결과:**
- DMZNET 규칙 순서: Block(아웃바운드 전체) > Block(→Splunk 10.0.100.0/24) > Pass(기존) > Block(기본)
- Apply Changes 완료 — "The changes have been applied successfully"
- WAN: 기존 NAT 규칙이 TCP/80만 Pass하므로 추가 변경 불필요

**캡처:**
- [ ] WAN 규칙 → `images/fw-2nd-wan.png`
- [ ] DMZNET 규칙 → `images/fw-2nd-dmz.png`

### 3차 대응 — Snort IPS 차단 모드 전환

> **근거:** 수동 IP 차단은 사후 대응 → Snort 자동차단으로 **실시간 대응** 전환

**pfSense 설정 절차:**
1. Services > Snort > Interfaces > WAN > Edit (연필 아이콘)
2. Alert Settings 섹션에서:

| 설정 | 변경 전 | 변경 후 | 효과 |
|------|--------|--------|------|
| Block Offenders | ☐ | **☑** | 탐지 시 자동 IP 차단 |
| Kill States | ☐ | **☑** | 차단 시 기존 연결도 종료 |
| Which IP to Block | — | **SRC** | 공격 출발지 IP 차단 |
| Block Duration | — | **3600** (초) | 1시간 차단 유지 |

3. Save > Snort 서비스 재시작 (Interfaces 목록에서 ▶ 재시작)

**적용 결과:**
- Block Offenders: ☑, Kill States: ☑, Which IP to Block: SRC, IPS Mode: Legacy Mode
- Snort 서비스 재시작 완료 (Blocking Mode: LEGACY MODE 확인)

**자동차단 검증 (att-mint에서 실행):**
```
# 1) 접속 확인 — 1차 Block 규칙 비활성화 상태에서 정상 접속
$ curl -I http://10.0.0.254 → HTTP/1.1 200 OK

# 2) nmap 포트스캔 → Snort sfPortscan 탐지 트리거
$ sudo nmap -sS -Pn -p 1-100 10.0.0.254
80/tcp open http (1.81초 완료)

# 3) 자동차단 확인 — 응답 없음(타임아웃)
$ curl -I http://10.0.0.254 → 타임아웃 (차단됨)
```
→ **Snort 자동차단(Block Offenders) 정상 동작 확인 — 3차 대응 성공**

**캡처:**
- [ ] 변경 전 Snort 설정 → `images/snort-block-before.png`
- [ ] 변경 후 Snort 설정 → `images/snort-block-after.png`
- [ ] Snort Blocked 목록 (차단된 IP) → `images/snort-blocked-list.png`
- [ ] 자동차단 검증 결과 (nmap + curl 타임아웃) → `images/snort-block-verify.png`

---

## 정책 적용 결과 요약

| 대응 단계 | 적용 내용 | 방어 범위 | 한계 |
|----------|----------|----------|------|
| 1차 | 공격자 IP 차단 | 특정 IP 완전 차단 | 다른 IP에서는 동일 공격 가능 |
| 2차 | HTTP만 허용 + DMZ 격리 | 불필요 포트·리버스쉘 차단 | 웹 공격(SQLi/XSS)은 HTTP 안에서 발생 |
| 3차 | Snort 자동차단 | 시그니처 기반 실시간 차단 | 미탐지 공격(Stored XSS 등)에는 무력 |

> **결론:** 1~3차 대응을 **모두 조합**해야 효과적. 단일 대응은 반드시 빈틈이 있다.
> → 보고서에서 "다층 방어(Defense in Depth)" 개념과 연결한다.

---

## 대응 규칙 적용/해제 순서 (중요)

> 1~3차 대응 규칙은 서로 겹쳐서, 켠 상태 그대로 두면 Phase 3의 Snort 자동차단 검증이 불가능해진다.
> (2차 대응의 "WAN 전체 차단"이 이미 모든 트래픽을 막고 있으면, 3차 Snort가 실제로 차단하는지 확인할 수 없기 때문)
> 따라서 아래 순서대로 **규칙을 켜고 끄며** 각 대응 효과를 개별 검증한다.

| 순번 | 시점 | 조작 | 목적 | 이 시점의 검증 |
|------|------|------|------|----------------|
| ① | 공격 종료 직후 | 모든 대응 규칙 **OFF** | 공격 로그가 정상 수집됐는지 확인 | Splunk에서 전체 공격 이벤트 확인 |
| ② | 1차 대응 | WAN 10.50.50.17 Block **ON** | IP 단위 차단 효과 확인 | Phase 3 검증 1 (IP 차단) |
| ③ | 1차 검증 후 | 1차 Block **OFF** | 다음 검증 위해 접근 복원 | — |
| ④ | 3차 대응 | Snort Block Offenders **ON** (2차 전체차단은 아직 OFF) | Snort **자동** 차단 동작 확인 | Phase 3 검증 2 (Snort 자동차단) |
| ⑤ | 3차 검증 후 | Snort Blocked 목록에서 10.50.50.17 **해제** | 재공격→재차단 반복 검증 | Phase 3 검증 3 |
| ⑥ | 최종 | 2차 대응(HTTP만 허용 + DMZ 아웃바운드 차단) **ON** | 상시 운영 정책으로 마무리 | 정상 HTTP만 통과하는지 확인 |

> 핵심: **2차 "WAN 전체 차단"은 3차 Snort 자동차단 검증(④)이 끝난 뒤 마지막(⑥)에 켠다.**
> 각 순번에서 규칙 적용 전/후 화면을 캡처하여 대응 이력으로 남긴다.
