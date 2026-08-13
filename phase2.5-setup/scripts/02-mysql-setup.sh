#!/bin/bash
# MySQL 서버 설치 및 설정
# 대상: Ubuntu 22.04 (10.0.100.60, inner-net)
# 실행: sudo bash 02-mysql-setup.sh

set -e

echo "=== [1/5] MySQL 서버 설치 ==="
apt update
apt install -y mysql-server

echo "=== [2/5] MySQL 원격 접속 허용 ==="
sed -i 's/bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

echo "=== [3/5] 로깅 설정 (Splunk 연동용) ==="
cat >> /etc/mysql/mysql.conf.d/mysqld.cnf << 'MYSQLEOF'

# Slow query log (이상 쿼리 탐지)
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2

# Error log
log_error = /var/log/mysql/error.log

# General log (필요 시 활성화 — 성능 영향 큼)
# general_log = 1
# general_log_file = /var/log/mysql/general.log
MYSQLEOF

systemctl restart mysql
systemctl enable mysql

echo "=== [4/5] 데이터베이스 및 사용자 생성 ==="
mysql -u root << 'SQLEOF'
-- WordPress 데이터베이스
CREATE DATABASE IF NOT EXISTS wordpress
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- WordPress 전용 계정 (정상)
CREATE USER IF NOT EXISTS 'wp_admin'@'10.0.10.80'
  IDENTIFIED BY 'WpAdmin!2024';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_admin'@'10.0.10.80';

-- 읽기 전용 계정 (정상)
CREATE USER IF NOT EXISTS 'wp_readonly'@'10.0.10.80'
  IDENTIFIED BY 'ReadOnly!2024';
GRANT SELECT ON wordpress.* TO 'wp_readonly'@'10.0.10.80';

-- 백업 계정 (의도적 취약점: host '%' — 모든 호스트 접근 허용)
CREATE USER IF NOT EXISTS 'backup'@'%'
  IDENTIFIED BY 'Backup2024';
GRANT SELECT, LOCK TABLES ON wordpress.* TO 'backup'@'%';

FLUSH PRIVILEGES;
SQLEOF

echo "=== [5/5] 커스텀 테이블 + 더미 데이터 삽입 ==="
mysql -u root wordpress < "$(dirname "$0")/../sql/02-custom-tables.sql"
mysql -u root wordpress < "$(dirname "$0")/../sql/03-dummy-data.sql"

echo ""
echo "=== MySQL 설정 완료 ==="
echo ""
echo "생성된 계정:"
echo "  wp_admin    / WpAdmin!2024    (10.0.10.80 전용, ALL)"
echo "  wp_readonly / ReadOnly!2024   (10.0.10.80 전용, SELECT)"
echo "  backup      / Backup2024     (모든 호스트, SELECT+LOCK — 취약!)"
echo ""
echo "WordPress 서버에서 접속 테스트:"
echo "  mysql -h 10.0.100.60 -u wp_admin -p wordpress -e 'SHOW TABLES;'"
echo ""
echo "다음 스크립트: 03-modsecurity-install.sh (WordPress 서버에서 실행)"
