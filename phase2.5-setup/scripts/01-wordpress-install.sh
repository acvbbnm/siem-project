#!/bin/bash
# WordPress + Apache + PHP 설치 스크립트
# 대상: Ubuntu 22.04 (10.0.10.80, dmz-net)
# 실행: sudo bash 01-wordpress-install.sh

set -e

echo "=== [1/6] 패키지 업데이트 ==="
apt update && apt upgrade -y

echo "=== [2/6] Apache + PHP 설치 ==="
apt install -y apache2 \
  php8.1 libapache2-mod-php8.1 \
  php8.1-mysql php8.1-xml php8.1-mbstring php8.1-curl \
  php8.1-zip php8.1-gd php8.1-intl \
  curl wget unzip

echo "=== [3/6] MySQL 클라이언트 설치 ==="
apt install -y mysql-client

echo "=== [4/6] WordPress 다운로드 ==="
cd /tmp
wget -q https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf /var/www/html/index.html

echo "=== [5/6] 퍼미션 설정 ==="
chown -R www-data:www-data /var/www/html/
chmod -R 755 /var/www/html/
find /var/www/html/ -type f -exec chmod 644 {} \;

echo "=== [6/6] wp-config.php 생성 ==="
cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
sed -i "s/database_name_here/wordpress/" /var/www/html/wp-config.php
sed -i "s/username_here/wp_admin/" /var/www/html/wp-config.php
sed -i "s/password_here/WpAdmin\!2024/" /var/www/html/wp-config.php
sed -i "s/localhost/10.0.100.60/" /var/www/html/wp-config.php

cat >> /var/www/html/wp-config.php << 'WPEOF'

/* 디버그 설정 (의도적 취약점 — display_errors 노출) */
define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', true);
define('WP_DEBUG_LOG', true);
WPEOF

a2enmod rewrite
systemctl restart apache2
systemctl enable apache2

echo ""
echo "=== WordPress 설치 완료 ==="
echo "브라우저에서 http://10.0.10.80/ 접속 후 설치 마법사 진행"
echo "- 사이트 제목: 테크솔루션 (TechSolution)"
echo "- 관리자 계정: admin / Admin!2024secure"
echo "- 이메일: admin@techsolution.local"
echo ""
echo "설치 마법사 완료 후 다음 스크립트 실행:"
echo "  sudo bash 01b-wordpress-post-install.sh"
