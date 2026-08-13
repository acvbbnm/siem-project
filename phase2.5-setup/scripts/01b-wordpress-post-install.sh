#!/bin/bash
# WordPress 설치 후 추가 설정
# 대상: WordPress 서버 (10.0.10.80)
# 실행: WordPress 설치 마법사 완료 후 실행

set -e

echo "=== [1/4] 취약한 플러그인 설치 ==="

# WP File Manager 6.9 (CVE-2020-25213 — 미인증 파일 업로드)
cd /var/www/html/wp-content/plugins/
wget -q "https://downloads.wordpress.org/plugin/wp-file-manager.6.9.zip" -O wp-file-manager.zip 2>/dev/null || {
    echo "[!] WP File Manager 6.9 자동 다운로드 실패"
    echo "    수동 다운로드: https://downloads.wordpress.org/plugin/wp-file-manager.6.9.zip"
    echo "    /var/www/html/wp-content/plugins/ 에 압축 해제"
}
[ -f wp-file-manager.zip ] && unzip -qo wp-file-manager.zip && rm wp-file-manager.zip

# Contact Form 7 (최신 — 정상 플러그인, 비교 대상)
wget -q "https://downloads.wordpress.org/plugin/contact-form-7.latest-stable.zip" -O cf7.zip 2>/dev/null || {
    echo "[!] Contact Form 7 자동 다운로드 실패 — wp-admin에서 수동 설치"
}
[ -f cf7.zip ] && unzip -qo cf7.zip && rm cf7.zip

chown -R www-data:www-data /var/www/html/wp-content/plugins/

echo "=== [2/4] WordPress 사용자 추가 (WP-CLI) ==="
cd /tmp
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

WP="/var/www/html"

# 에디터 계정
sudo -u www-data wp user create editor editor@techsolution.local \
    --role=editor --user_pass='Editor!2024' --path="$WP" 2>/dev/null || true

# 고객 계정 5개
for i in $(seq 1 5); do
    sudo -u www-data wp user create "customer${i}" "customer${i}@example.com" \
        --role=subscriber --user_pass="Customer${i}!" --path="$WP" 2>/dev/null || true
done

echo "=== [3/4] 페이지 생성 ==="
sudo -u www-data wp post create --post_type=page --post_title='회사 소개' \
    --post_content='<h2>테크솔루션</h2><p>중소기업 IT 컨설팅 전문 기업입니다.</p>' \
    --post_status=publish --path="$WP" 2>/dev/null || true

sudo -u www-data wp post create --post_type=page --post_title='고객 포털' \
    --post_content='<p>로그인 후 프로젝트 현황을 확인하세요.</p>' \
    --post_status=publish --path="$WP" 2>/dev/null || true

sudo -u www-data wp post create --post_type=page --post_title='문의하기' \
    --post_content='<p>문의 사항은 아래 양식을 이용해 주세요.</p>' \
    --post_status=publish --path="$WP" 2>/dev/null || true

# 블로그 포스트 3개
for title in "클라우드 마이그레이션 사례" "보안 컨설팅 서비스 안내" "2024 IT 트렌드 전망"; do
    sudo -u www-data wp post create --post_title="$title" \
        --post_content="<p>테크솔루션의 전문 서비스를 소개합니다.</p>" \
        --post_status=publish --path="$WP" 2>/dev/null || true
done

echo "=== [4/4] Permalink 설정 ==="
sudo -u www-data wp rewrite structure '/%postname%/' --path="$WP" 2>/dev/null || true
sudo -u www-data wp rewrite flush --path="$WP" 2>/dev/null || true

echo ""
echo "=== WordPress 후속 설정 완료 ==="
echo ""
echo "wp-admin에서 수동으로 확인할 것:"
echo "  1. 플러그인 > WP File Manager 활성화 (6.9 버전 확인)"
echo "  2. 플러그인 > Contact Form 7 활성화"
echo "  3. 외모 > 메뉴에서 페이지 연결"
echo ""
echo "다음 스크립트: 02-mysql-setup.sh (MySQL 서버에서 실행)"
