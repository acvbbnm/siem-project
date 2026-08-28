# Phase 2.5 — 실제 운영 환경 구축 가이드

> "테크솔루션" 가상 회사의 IT 인프라를 구축하여 Phase 3(킬체인 공격) 환경을 준비한다.

---

## 목표

Bee-box 단일 취약서버 → **실제 기업 운영 환경 시뮬레이션**으로 확장

| 항목 | Before | After |
|------|--------|-------|
| 웹서버 | Bee-box (bWAPP) | Bee-box + **WordPress** |
| DB | Bee-box 내장 MySQL | **독립 MySQL 서버** (inner-net) |
| WAF | 없음 | **ModSecurity + OWASP CRS** |
| 로그 소스 | Snort + filterlog (2개) | **8개** (Snort, filterlog, Apache×2, ModSec, WP auth, MySQL×2) |
| 공격자 | att-mint 1대 | att-mint + **Kali Linux** |
| 트래픽 | 공격만 | 공격 + **정상 트래픽** 혼합 |

---

## 구축 순서

### Step ① WordPress + Apache + PHP 설치 (WordPress VM)

**대상:** 새 Ubuntu 22.04 VM (10.0.10.80, dmz-net)

```bash
# VM 생성 후 네트워크 설정
sudo nano /etc/netplan/00-installer-config.yaml
# ethernets: ens160: addresses: [10.0.10.80/24], gateway4: 10.0.10.1, nameservers: [8.8.8.8]
sudo netplan apply

# WordPress 설치
sudo bash scripts/01-wordpress-install.sh

# 브라우저에서 http://10.0.10.80/ → 설치 마법사 진행
# 사이트명: 테크솔루션 / admin / Admin!2024secure

# 후속 설정 (플러그인, 사용자, 페이지)
sudo bash scripts/01b-wordpress-post-install.sh
```

**확인:**
- [ ] `curl -I http://10.0.10.80` → HTTP 200
- [ ] wp-admin 로그인 성공
- [ ] WP File Manager 6.9 활성화 확인

---

### Step ② MySQL 서버 설치 (MySQL VM)

**대상:** 새 Ubuntu 22.04 VM (10.0.100.60, inner-net)

```bash
# VM 생성 후 네트워크 설정
# IP: 10.0.100.60/24, Gateway: 10.0.100.1

# MySQL 설치 + DB/계정 생성 + 더미 데이터
sudo bash scripts/02-mysql-setup.sh
```

**확인:**
- [ ] WordPress 서버에서: `mysql -h 10.0.100.60 -u wp_admin -p wordpress -e 'SHOW TABLES;'`
- [ ] `SELECT COUNT(*) FROM wp_customers;` → 200건
- [ ] `SELECT COUNT(*) FROM wp_inquiries;` → 50건
- [ ] WordPress 사이트 정상 동작 (DB 연동)

---

### Step ③ ModSecurity WAF 설치 (WordPress VM)

**대상:** WordPress 서버 (10.0.10.80)

```bash
# ModSecurity + OWASP CRS 설치
sudo bash scripts/03-modsecurity-install.sh

# Apache 설정 적용
sudo cp configs/apache/wordpress.conf /etc/apache2/sites-available/000-default.conf
sudo cp configs/apache/security.conf /etc/apache2/conf-available/security.conf
sudo a2enconf security
sudo cp configs/php/custom-php.ini /etc/php/8.1/apache2/conf.d/99-custom.ini
sudo systemctl restart apache2
```

**확인:**
- [ ] `curl 'http://10.0.10.80/?id=1+UNION+SELECT+1' -v` → SQLi 통과 (DetectionOnly)
- [ ] `tail /var/log/modsecurity/audit.log` → SQLi 탐지 로그 확인
- [ ] `curl 'http://10.0.10.80/?q=<script>alert(1)</script>' -v` → XSS 차단 (403)

---

### Step ④ pfSense 방화벽 규칙 추가

**대상:** pfSense WebGUI

```
참조: configs/pfsense/firewall-rules.md
```

1. **NAT 추가:** WAN:8080 → 10.0.10.80:80
2. **DMZNET 규칙:** WordPress(10.0.10.80) → MySQL(10.0.100.60:3306) 허용
3. **Snort 커스텀 룰:** `configs/snort/local.rules` 내용을 Custom Rules에 붙여넣기

**확인:**
- [ ] att-mint에서: `curl -I http://10.0.0.254:8080` → WordPress 응답
- [ ] WordPress에서: `mysql -h 10.0.100.60 -u wp_admin -p` → 접속 성공
- [ ] WordPress에서: `curl http://10.0.50.100` → 차단 (아웃바운드 Block)

---

### Step ⑤ Splunk 다중 로그 소스 연동

**WordPress/MySQL 서버 각각:**
```bash
# Splunk Universal Forwarder 설치 후
sudo bash scripts/04-splunk-forwarder.sh
```

**Splunk 서버 (10.0.100.50):**
1. `splunk/indexes.conf` 내용으로 인덱스 3개 생성 (idx_web, idx_waf, idx_db)
2. `splunk/props.conf` 복사하여 필드 추출 설정
3. Settings > Forwarding and receiving > Configure receiving → Port 9997

**확인:**
- [ ] `index=idx_web sourcetype=apache:access | head 5` → 로그 수신
- [ ] `index=idx_waf sourcetype=modsecurity | head 5` → WAF 로그 수신
- [ ] `index=idx_db sourcetype=mysql:slowquery | head 5` → DB 로그 수신
- [ ] `index=pfsense "snort" | head 5` → 기존 Snort 로그 정상

---

### Step ⑥ 정상 트래픽 생성 (mng-mint)

**대상:** mng-mint (10.0.50.100)

```bash
# 스크립트 복사
cp scripts/05-normal-traffic.sh ~/normal-traffic.sh
chmod +x ~/normal-traffic.sh

# crontab 등록 (5분마다 실행)
crontab -e
# */5 * * * * /home/user/normal-traffic.sh >> /var/log/normal-traffic.log 2>&1

# 수동 테스트
bash ~/normal-traffic.sh
```

**확인:**
- [ ] Splunk에서 `index=idx_web src_ip=10.0.50.100` → mng-mint 정상 트래픽 확인
- [ ] 공격 트래픽과 구분되는 정상 패턴 확인

---

### Step ⑦ Kali Linux 추가 (att-net)

**대상:** 새 Kali VM (10.50.50.30, att-net)

1. ESXi에 Kali Linux VM 생성 (1vCPU / 2GB RAM / 25GB)
2. att-net 포트그룹 연결
3. IP 설정: 10.50.50.30/24, Gateway: 10.50.50.1

**확인:**
- [ ] `curl -I http://10.0.0.254` → Bee-box 응답 (HTTP 200)
- [ ] `curl -I http://10.0.0.254:8080` → WordPress 응답
- [ ] `wpscan --url http://10.0.0.254:8080 --enumerate` → 플러그인 스캔

---

## 파일 구조

```
phase2.5-setup/
├── README.md                ← 이 파일
├── scripts/
│   ├── 01-wordpress-install.sh      ← WordPress + Apache + PHP
│   ├── 01b-wordpress-post-install.sh ← 플러그인·사용자·페이지
│   ├── 02-mysql-setup.sh            ← MySQL 서버
│   ├── 03-modsecurity-install.sh    ← ModSecurity WAF
│   ├── 04-splunk-forwarder.sh       ← Splunk UF
│   └── 05-normal-traffic.sh         ← 정상 트래픽 생성
├── configs/
│   ├── apache/
│   │   ├── wordpress.conf           ← VirtualHost 설정
│   │   └── security.conf            ← 보안 설정 (의도적 취약점)
│   ├── php/
│   │   └── custom-php.ini           ← PHP 설정 (의도적 취약점)
│   ├── modsecurity/
│   │   └── custom-exclusions.conf   ← WAF 예외 (의도적 허점)
│   ├── snort/
│   │   └── local.rules              ← 커스텀 Snort 룰 9개
│   └── pfsense/
│       └── firewall-rules.md        ← 방화벽 규칙 변경 명세
├── sql/
│   ├── 02-custom-tables.sql         ← wp_customers, wp_inquiries 테이블
│   └── 03-dummy-data.sql            ← 더미 데이터 250건
└── splunk/
    ├── inputs.conf                  ← UF 입력 설정
    ├── props.conf                   ← 필드 추출
    └── indexes.conf                 ← 인덱스 정의
```

---

## 예상 소요 시간

| 단계 | 예상 시간 | 비고 |
|------|----------|------|
| ① WordPress | 30분 | 스크립트 자동화 |
| ② MySQL | 20분 | 스크립트 자동화 |
| ③ ModSecurity | 30분 | CRS 다운로드 포함 |
| ④ pfSense 규칙 | 15분 | GUI 작업 |
| ⑤ Splunk 연동 | 40분 | UF 설치 + 인덱스 생성 |
| ⑥ 정상 트래픽 | 10분 | cron 등록 |
| ⑦ Kali | 30분 | ISO 설치 |
| **합계** | **약 3시간** | |

구축 완료 후 → Phase 3 (킬체인 공격 + 탐지 엔지니어링) 진행
