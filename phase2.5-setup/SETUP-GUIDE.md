# Phase 2.5 상세 구축 가이드 — Ubuntu VM 생성부터

> ESXi 6.7.0 환경에서 WordPress VM, MySQL VM 생성부터 전체 환경 구축까지

---

## 사전 준비

### Ubuntu 22.04 ISO 다운로드

mng-mint 또는 호스트 PC에서 다운로드 후 ESXi 데이터스토어에 업로드:

```
https://releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso
```

ESXi Web Client > Storage > datastore > Upload 로 ISO 업로드

---

## VM 1: WordPress 서버 (10.0.10.80)

### 1-1. ESXi에서 VM 생성

ESXi Web Client (`https://<ESXi IP>/ui`) 접속

**Virtual Machines > Create / Register VM**

| 항목 | 설정 |
|------|------|
| Creation type | Create a new virtual machine |
| Name | **wordpress** |
| Compatibility | ESXi 6.7 |
| Guest OS family | Linux |
| Guest OS version | **Ubuntu Linux (64-bit)** |

**Customize settings:**

| 항목 | 설정 |
|------|------|
| CPU | **1 vCPU** |
| Memory | **2048 MB** (2GB) |
| Hard disk 1 | **20 GB** (Thin Provisioned) |
| Network Adapter 1 | **dmz-net** (OPT1 포트그룹) |
| CD/DVD Drive 1 | Datastore ISO > `ubuntu-22.04.4-live-server-amd64.iso` |

> **중요:** Network Adapter를 반드시 **dmz-net** 포트그룹에 연결해야 합니다.
> Bee-box와 같은 네트워크(10.0.10.0/24)에 위치해야 합니다.

**Finish** 클릭 → VM 생성 완료

---

### 1-2. Ubuntu 설치

VM 전원 켜기 → Console 열기

**설치 과정:**

1. **Language:** English (기본)
2. **Keyboard:** Korean 또는 English
3. **Installation type:** Ubuntu Server
4. **Network:** 설치 중에는 DHCP 또는 수동 설정 모두 가능 (설치 후 고정 IP 설정)
5. **Proxy:** 빈칸 (없음)
6. **Mirror:** 기본값 유지
7. **Storage:** Use an Entire Disk → 기본값으로 진행
8. **Profile setup:**

| 항목 | 값 |
|------|-----|
| Your name | admin |
| Server name | **wordpress** |
| Username | **admin** |
| Password | **Admin!2024** |

9. **SSH:** Install OpenSSH server ☑ (체크)
10. **Featured snaps:** 아무것도 선택하지 않음

설치 완료 후 **Reboot Now** → ISO 제거 확인

---

### 1-3. 고정 IP 설정

로그인 후 (admin / Admin!2024):

```bash
# 네트워크 인터페이스 이름 확인
ip a
```

인터페이스 이름이 `ens160`, `ens192`, 또는 `ens33` 등으로 표시됩니다.
아래에서 `ens160` 부분을 실제 인터페이스 이름으로 바꿔주세요.

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

**파일 내용 (전체 교체):**

```yaml
network:
  version: 2
  ethernets:
    ens160:
      addresses:
        - 10.0.10.80/24
      routes:
        - to: default
          via: 10.0.10.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

> **주의:** YAML은 들여쓰기가 중요합니다. 탭이 아닌 **스페이스 2칸**으로 들여쓰세요.

```bash
# 적용
sudo netplan apply

# 확인
ip a | grep 10.0.10.80
ping -c 3 10.0.10.1      # pfSense(게이트웨이) 응답 확인
```

**예상 결과:**
```
inet 10.0.10.80/24 brd 10.0.10.255 scope global ens160
```

```
PING 10.0.10.1: 64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.5ms
```

> pfSense에서 ping 응답이 안 오면:
> pfSense > Firewall > Rules > DMZNET 에서 ICMP 허용 규칙 확인

---

### 1-4. 인터넷 접속 확인

```bash
# DNS 테스트
ping -c 3 8.8.8.8

# 패키지 다운로드 테스트
sudo apt update
```

> **인터넷 안 될 경우:**
> pfSense에서 DMZNET → WAN(인터넷) 방향이 차단되어 있을 수 있습니다.
> 
> **해결:** pfSense > Firewall > Rules > DMZNET에 임시 허용 규칙 추가:
> - Action: Pass
> - Source: 10.0.10.80
> - Destination: any
> - Description: "WordPress - temp internet access (설치용)"
>
> **설치 완료 후 이 규칙을 반드시 삭제하세요** (아웃바운드 차단이 보안 설계의 일부입니다)

---

### 1-5. WordPress 설치

인터넷 접속이 확인되면:

```bash
# 이 리포지토리의 스크립트를 직접 복사하거나, 수동으로 입력
# 방법 1: mng-mint에서 scp로 전송
#   scp scripts/01-wordpress-install.sh admin@10.0.10.80:~/

# 방법 2: 직접 명령 실행

# --- 패키지 설치 ---
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 \
  php8.1 libapache2-mod-php8.1 \
  php8.1-mysql php8.1-xml php8.1-mbstring php8.1-curl \
  php8.1-zip php8.1-gd php8.1-intl \
  curl wget unzip mysql-client

# --- WordPress 다운로드 ---
cd /tmp
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo rm /var/www/html/index.html

# --- 퍼미션 ---
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/

# --- wp-config.php 생성 ---
sudo cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
```

wp-config.php 편집:

```bash
sudo nano /var/www/html/wp-config.php
```

아래 4줄을 찾아서 수정:

```php
define( 'DB_NAME', 'wordpress' );          // database_name_here → wordpress
define( 'DB_USER', 'wp_admin' );           // username_here → wp_admin
define( 'DB_PASSWORD', 'WpAdmin!2024' );   // password_here → WpAdmin!2024
define( 'DB_HOST', '10.0.100.60' );        // localhost → 10.0.100.60
```

파일 맨 아래(require_once 줄 위)에 추가:

```php
define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', true);
define('WP_DEBUG_LOG', true);
```

저장 후:

```bash
sudo a2enmod rewrite
sudo systemctl restart apache2
sudo systemctl enable apache2
```

> **이 시점에서 WordPress 설치 마법사는 아직 안 됩니다.**
> MySQL 서버가 먼저 필요하기 때문에 VM 2(MySQL) 구축 후 진행합니다.

---

## VM 2: MySQL 서버 (10.0.100.60)

### 2-1. ESXi에서 VM 생성

**Virtual Machines > Create / Register VM**

| 항목 | 설정 |
|------|------|
| Name | **mysql** |
| Guest OS version | Ubuntu Linux (64-bit) |
| CPU | **1 vCPU** |
| Memory | **1024 MB** (1GB) |
| Hard disk 1 | **15 GB** (Thin Provisioned) |
| Network Adapter 1 | **inner-net** (OPT2 포트그룹) |
| CD/DVD Drive 1 | 위와 같은 Ubuntu ISO |

> **중요:** Network Adapter를 **inner-net** 포트그룹에 연결
> Splunk(10.0.100.50)과 같은 네트워크(10.0.100.0/24)

---

### 2-2. Ubuntu 설치

VM 1과 동일한 과정. 차이점:

| 항목 | 값 |
|------|-----|
| Server name | **mysql** |
| Username | **admin** |
| Password | **Admin!2024** |

---

### 2-3. 고정 IP 설정

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    ens160:
      addresses:
        - 10.0.100.60/24
      routes:
        - to: default
          via: 10.0.100.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

```bash
sudo netplan apply
ip a | grep 10.0.100.60
ping -c 3 10.0.100.1      # pfSense 응답 확인
ping -c 3 10.0.100.50     # Splunk 서버 응답 확인
```

---

### 2-4. MySQL 설치

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y mysql-server
```

원격 접속 허용:

```bash
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
```

아래 줄을 찾아서 수정:

```
# 변경 전
bind-address = 127.0.0.1

# 변경 후
bind-address = 0.0.0.0
```

로깅 설정 추가 (파일 맨 아래):

```ini
# Slow query log (Splunk 연동)
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2

# Error log
log_error = /var/log/mysql/error.log
```

저장 후:

```bash
sudo systemctl restart mysql
sudo systemctl enable mysql
```

---

### 2-5. 데이터베이스 및 사용자 생성

```bash
sudo mysql -u root
```

MySQL 프롬프트에서:

```sql
-- WordPress 데이터베이스
CREATE DATABASE wordpress
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- WordPress 전용 계정 (정상)
CREATE USER 'wp_admin'@'10.0.10.80'
  IDENTIFIED BY 'WpAdmin!2024';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_admin'@'10.0.10.80';

-- 읽기 전용 계정
CREATE USER 'wp_readonly'@'10.0.10.80'
  IDENTIFIED BY 'ReadOnly!2024';
GRANT SELECT ON wordpress.* TO 'wp_readonly'@'10.0.10.80';

-- 백업 계정 (의도적 취약점: 모든 호스트 허용)
CREATE USER 'backup'@'%'
  IDENTIFIED BY 'Backup2024';
GRANT SELECT, LOCK TABLES ON wordpress.* TO 'backup'@'%';

FLUSH PRIVILEGES;
EXIT;
```

---

### 2-6. 커스텀 테이블 생성

```bash
sudo mysql -u root wordpress
```

```sql
-- 고객 데이터 테이블
CREATE TABLE wp_customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    company VARCHAR(100),
    project_type VARCHAR(50),
    contract_amount INT,
    status ENUM('active','completed','pending') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 문의 내역 테이블
CREATE TABLE wp_inquiries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    message TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

더미 데이터 삽입 (핵심 20건만 — 나머지는 sql/03-dummy-data.sql 파일 참조):

```sql
INSERT INTO wp_customers (name, email, phone, company, project_type, contract_amount, status) VALUES
('김민수', 'minsu.kim@koreantech.co.kr', '010-1234-5678', '코리안테크', '클라우드 마이그레이션', 45000000, 'active'),
('이서연', 'seoyeon@dataflow.kr', '010-2345-6789', '데이터플로우', '보안 컨설팅', 32000000, 'active'),
('박준혁', 'junhyuk.park@smartbiz.com', '010-3456-7890', '스마트비즈', 'ERP 구축', 78000000, 'active'),
('최유진', 'yujin@nexgen.co.kr', '010-4567-8901', '넥스젠솔루션', '웹 개발', 25000000, 'completed'),
('정하늘', 'haneul.j@cloudway.kr', '010-5678-9012', '클라우드웨이', '인프라 구축', 56000000, 'active'),
('강도윤', 'doyun.kang@ailab.kr', '010-6789-0123', 'AI연구소', 'AI 시스템 구축', 120000000, 'active'),
('윤서진', 'seojin@greendata.com', '010-7890-1234', '그린데이터', '데이터센터 이전', 95000000, 'pending'),
('임채원', 'chaewon@fintech.kr', '010-8901-2345', '핀테크코리아', '보안 인증', 42000000, 'active'),
('한지민', 'jimin.han@edusoft.co.kr', '010-9012-3456', '에듀소프트', 'LMS 개발', 38000000, 'completed'),
('송태양', 'taeyang@solarit.kr', '010-0123-4567', '솔라IT', '모니터링 시스템', 28000000, 'active');

INSERT INTO wp_inquiries (name, email, message, ip_address, created_at) VALUES
('김태호', 'taeho@naver.com', '클라우드 마이그레이션 견적 문의드립니다.', '211.234.56.78', '2024-07-01 09:15:00'),
('이수진', 'sujin@gmail.com', '보안 취약점 진단 서비스에 대해 알고 싶습니다.', '175.123.45.67', '2024-07-02 14:30:00'),
('박영호', 'youngho@daum.net', '기존 시스템 유지보수 계약 관련 문의', '220.78.90.12', '2024-07-03 11:00:00'),
('최은비', 'eunbi@company.co.kr', '인프라 구축 프로젝트 일정 조율 가능한가요?', '119.56.78.90', '2024-07-05 16:45:00'),
('정민재', 'minjae@naver.com', 'ERP 도입 컨설팅 비용이 궁금합니다.', '203.45.67.89', '2024-07-08 10:20:00');

-- 확인
SELECT COUNT(*) AS '고객 수' FROM wp_customers;
SELECT COUNT(*) AS '문의 수' FROM wp_inquiries;

EXIT;
```

---

### 2-7. WordPress에서 DB 접속 확인

**WordPress 서버(10.0.10.80)에서:**

```bash
mysql -h 10.0.100.60 -u wp_admin -pWpAdmin!2024 wordpress -e "SHOW TABLES;"
```

**예상 결과:**
```
+---------------------+
| Tables_in_wordpress |
+---------------------+
| wp_customers        |
| wp_inquiries        |
+---------------------+
```

> **접속 실패 시 확인사항:**
> 1. MySQL bind-address가 0.0.0.0인지 확인
> 2. pfSense DMZNET 규칙에서 10.0.10.80 → 10.0.100.60:3306 허용 여부
> 3. `sudo ufw status` → UFW 방화벽이 켜져 있으면 3306 포트 허용

---

## pfSense 방화벽 규칙 추가

### NAT 규칙: WAN:8080 → WordPress

**pfSense > Firewall > NAT > Port Forward > Add (↑)**

| 항목 | 설정 |
|------|------|
| Interface | WAN |
| Protocol | TCP |
| Destination | WAN address |
| Destination port range | From: 8080 / To: 8080 |
| Redirect target IP | 10.0.10.80 |
| Redirect target port | 80 |
| Description | WAN:8080 → WordPress HTTP |

**Save → Apply Changes**

> 자동으로 WAN Firewall 규칙도 생성됩니다.

### DMZNET 규칙: WordPress → MySQL 허용

**pfSense > Firewall > Rules > DMZNET > Add (↑)** (맨 위에)

| 항목 | 설정 |
|------|------|
| Action | Pass |
| Interface | DMZNET |
| Protocol | TCP |
| Source | Single host — 10.0.10.80 |
| Destination | Single host — 10.0.100.60 |
| Destination Port | 3306 (MySQL) |
| Description | WordPress → MySQL only |

**Save → Apply Changes**

**최종 DMZNET 규칙 순서:**

| # | Action | Source | Destination | Port | 설명 |
|---|--------|--------|-------------|------|------|
| 1 | **Pass** | 10.0.10.80 | 10.0.100.60 | 3306 | WordPress→MySQL (신규) |
| 2 | Block | DMZNET net | 10.0.100.0/24 | * | DMZ→inner 차단 (기존) |
| 3 | Block | DMZNET net | * | * | 아웃바운드 전체 차단 (기존) |

### DMZNET 임시 인터넷 규칙 (설치용)

아직 추가하지 않았다면:

| # | Action | Source | Destination | Port | 설명 |
|---|--------|--------|-------------|------|------|
| 0 | **Pass** | 10.0.10.80 | * | * | **임시: 설치용 인터넷** |

> **WordPress + ModSecurity 설치가 완전히 끝난 후 이 규칙을 삭제하세요!**

---

## WordPress 설치 마법사 실행

MySQL이 준비되었으니, 브라우저에서 WordPress 설치를 진행합니다.

**mng-mint 브라우저에서:**

```
http://10.0.10.80/
```

또는 att-mint에서 (pfSense NAT 경유):

```
http://10.0.0.254:8080/
```

### 설치 마법사 입력

| 항목 | 값 |
|------|-----|
| Site Title | **테크솔루션 (TechSolution)** |
| Username | **admin** |
| Password | **Admin!2024secure** |
| Your Email | **admin@techsolution.local** |
| Search engine visibility | ☑ 체크 (색인 방지) |

**Install WordPress** 클릭

### 설치 후 확인

```bash
# WordPress 서버에서
curl -s -o /dev/null -w "%{http_code}" http://localhost/
# → 200 또는 301 (정상)

# mng-mint에서
curl -I http://10.0.10.80/
# → HTTP/1.1 200 OK
```

---

## WordPress 후속 설정

### 사용자 추가

**wp-admin > Users > Add New**

| 사용자 | 이메일 | 역할 | 비밀번호 |
|--------|--------|------|----------|
| editor | editor@techsolution.local | Editor | Editor!2024 |
| customer1 | customer1@example.com | Subscriber | Customer1! |
| customer2 | customer2@example.com | Subscriber | Customer2! |
| customer3 | customer3@example.com | Subscriber | Customer3! |

### 페이지 생성

**wp-admin > Pages > Add New**

1. **회사 소개** — 테크솔루션 소개 내용
2. **고객 포털** — "로그인 후 프로젝트 현황을 확인하세요"
3. **문의하기** — Contact Form 7 연결 (플러그인 설치 후)

### 블로그 포스트 생성

**wp-admin > Posts > Add New** (3개)

1. "클라우드 마이그레이션 사례"
2. "보안 컨설팅 서비스 안내"
3. "2024 IT 트렌드 전망"

### 취약한 플러그인 설치

**wp-admin > Plugins > Add New**

1. **Contact Form 7** — 검색 후 설치 + 활성화 (정상 플러그인)

2. **WP File Manager 6.9** — 자동 설치 불가능 (구버전), 수동 설치:

```bash
# WordPress 서버에서
cd /var/www/html/wp-content/plugins/
sudo wget "https://downloads.wordpress.org/plugin/wp-file-manager.6.9.zip"
sudo unzip wp-file-manager.6.9.zip
sudo rm wp-file-manager.6.9.zip
sudo chown -R www-data:www-data wp-file-manager/
```

wp-admin > Plugins에서 **WP File Manager** 활성화

> **버전 확인 필수:** 플러그인 목록에서 Version 6.9 표시 확인
> 6.9 이하만 CVE-2020-25213 취약점이 존재합니다.

### Permalink 설정

**wp-admin > Settings > Permalinks**
- **Post name** 선택 (`/%postname%/`)
- **Save Changes**

---

## ModSecurity WAF 설치

**WordPress 서버(10.0.10.80)에서:**

```bash
# ModSecurity 설치
sudo apt install -y libapache2-mod-security2 git

# OWASP CRS 다운로드
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# 기본 설정 활성화
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
```

modsecurity.conf 수정:

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

**변경:** `SecRuleEngine DetectionOnly` → `SecRuleEngine On`

**맨 아래 추가:**

```
# 감사 로그 (Splunk 연동)
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/audit.log
SecAuditLogParts ABCFHZ
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
```

로그 디렉토리 생성:

```bash
sudo mkdir -p /var/log/modsecurity
sudo chown www-data:www-data /var/log/modsecurity
```

### 커스텀 예외 규칙 (의도적 허점)

```bash
sudo nano /etc/modsecurity/custom-exclusions.conf
```

**핵심 내용만 입력 (전체 파일은 리포지토리의 configs/modsecurity/custom-exclusions.conf 참조):**

```
# SQLi 탐지: DetectionOnly (로그만, 차단 안 함)
SecRuleUpdateActionById 942100 "pass,log,auditlog"
SecRuleUpdateActionById 942110 "pass,log,auditlog"
SecRuleUpdateActionById 942120 "pass,log,auditlog"
SecRuleUpdateActionById 942130 "pass,log,auditlog"
SecRuleUpdateActionById 942140 "pass,log,auditlog"
SecRuleUpdateActionById 942150 "pass,log,auditlog"
SecRuleUpdateActionById 942160 "pass,log,auditlog"
SecRuleUpdateActionById 942170 "pass,log,auditlog"
SecRuleUpdateActionById 942180 "pass,log,auditlog"
SecRuleUpdateActionById 942190 "pass,log,auditlog"
SecRuleUpdateActionById 942200 "pass,log,auditlog"

# Scanner 탐지: DetectionOnly (wpscan 로그만)
SecRuleUpdateActionById 913100 "pass,log,auditlog"
SecRuleUpdateActionById 913110 "pass,log,auditlog"
SecRuleUpdateActionById 913120 "pass,log,auditlog"

# .phtml 업로드 허용 (WAF 우회 벡터)
SecRule REQUEST_FILENAME "@endsWith .phtml" \
    "id:999001,phase:2,pass,nolog,\
    ctl:ruleRemoveById=930120"
```

### Apache에 ModSecurity 연동

```bash
sudo nano /etc/apache2/mods-available/security2.conf
```

**전체 내용:**

```
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
    IncludeOptional /etc/modsecurity/custom-exclusions.conf
</IfModule>
```

```bash
sudo a2enmod security2
sudo systemctl restart apache2
```

### WAF 동작 테스트

```bash
# XSS → 차단 (403)
curl -s -o /dev/null -w "%{http_code}" "http://localhost/?q=<script>alert(1)</script>"
# → 403

# SQLi → 통과 (200) — DetectionOnly이므로
curl -s -o /dev/null -w "%{http_code}" "http://localhost/?id=1+OR+1=1"
# → 200 (차단 안 됨)

# ModSecurity 로그 확인
sudo tail -5 /var/log/modsecurity/audit.log
# → SQLi 탐지 로그가 기록되어 있어야 함
```

---

## Apache / PHP 의도적 취약점 설정

### Apache 보안 설정

```bash
sudo nano /etc/apache2/conf-available/security.conf
```

아래 항목을 찾아서 수정:

```
ServerTokens Full
ServerSignature On
TraceEnable On
```

```bash
sudo a2enconf security
```

### VirtualHost 설정

```bash
sudo nano /etc/apache2/sites-available/000-default.conf
```

`<VirtualHost *:80>` 블록 안에 추가:

```
    # 의도적 취약점: uploads 디렉토리 리스팅
    <Directory /var/www/html/wp-content/uploads>
        Options +Indexes
    </Directory>
```

### PHP 설정

```bash
sudo nano /etc/php/8.1/apache2/conf.d/99-custom.ini
```

```ini
display_errors = On
display_startup_errors = On
upload_max_filesize = 10M
post_max_size = 12M
max_execution_time = 60
```

```bash
sudo systemctl restart apache2
```

### 설정 확인

```bash
# 서버 버전 전체 노출 확인
curl -I http://localhost/ 2>/dev/null | grep Server
# → Server: Apache/2.4.52 (Ubuntu) ... (전체 버전 표시)

# uploads 디렉토리 리스팅
curl -s http://localhost/wp-content/uploads/ | grep "Index of"
# → Index of /wp-content/uploads (디렉토리 리스팅 활성화)
```

---

## 임시 인터넷 규칙 삭제

WordPress + ModSecurity + 플러그인 설치가 모두 완료되었으면:

**pfSense > Firewall > Rules > DMZNET**에서 "WordPress - temp internet access" 규칙 **삭제**

**Apply Changes**

---

## 구축 완료 확인 체크리스트

### WordPress 서버 (10.0.10.80)

```bash
# mng-mint에서 테스트
curl -I http://10.0.10.80/
# → HTTP/1.1 200 OK, Server: Apache/2.4.52 (전체 버전)

curl -s -o /dev/null -w "%{http_code}" "http://10.0.10.80/?q=<script>alert(1)</script>"
# → 403 (WAF 차단)

curl -s -o /dev/null -w "%{http_code}" "http://10.0.10.80/?id=1+OR+1=1"
# → 200 (SQLi 통과, 의도적)
```

### att-mint에서 NAT 경유

```bash
curl -I http://10.0.0.254:8080/
# → HTTP/1.1 200 OK (WordPress)

curl -I http://10.0.0.254/
# → HTTP/1.1 200 OK (Bee-box, 기존)
```

### MySQL 서버 (10.0.100.60)

```bash
# WordPress 서버에서
mysql -h 10.0.100.60 -u wp_admin -pWpAdmin!2024 wordpress \
  -e "SELECT COUNT(*) FROM wp_customers;"
# → 10 이상
```

### 아웃바운드 차단 확인

```bash
# WordPress 서버에서
curl -m 5 http://google.com
# → 타임아웃 (아웃바운드 차단 정상)
```

---

## 다음 단계

구축 확인이 완료되면:

1. **Snort 커스텀 룰 등록** → `configs/snort/local.rules` 내용을 pfSense Snort에 추가
2. **Splunk 로그 연동** → Splunk Universal Forwarder 설치 (04-splunk-forwarder.sh)
3. **정상 트래픽 생성** → mng-mint에 cron 등록 (05-normal-traffic.sh)
4. **Kali Linux 추가** → att-net에 Kali VM 설치

전부 완료 후 → **Phase 3 (킬체인 공격)** 진행
