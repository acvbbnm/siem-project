#!/bin/bash
# Splunk Universal Forwarder 설치
# 대상: WordPress 서버(10.0.10.80) 및 MySQL 서버(10.0.100.60) 각각 실행
# 실행: sudo bash 04-splunk-forwarder.sh

set -e

SPLUNK_SERVER="10.0.100.50"
SPLUNK_PORT="9997"

echo "=== [1/4] Splunk Universal Forwarder 다운로드 ==="
echo ""
echo "Splunk UF는 라이선스 동의 후 수동 다운로드가 필요합니다."
echo "https://www.splunk.com/en_us/download/universal-forwarder.html"
echo ""
echo "다운로드한 .deb 파일을 이 서버에 복사한 뒤 아래 명령으로 설치:"
echo "  dpkg -i splunkforwarder-*.deb"
echo ""

# 이미 설치되어 있으면 계속 진행
if [ ! -d /opt/splunkforwarder ]; then
    echo "[!] Splunk UF가 설치되어 있지 않습니다."
    echo "    설치 후 이 스크립트를 다시 실행하세요."
    exit 1
fi

echo "=== [2/4] Splunk UF 초기 설정 ==="
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt \
    --seed-passwd 'SplunkUF!2024'

echo "=== [3/4] 전송 대상 서버 설정 ==="
/opt/splunkforwarder/bin/splunk add forward-server "${SPLUNK_SERVER}:${SPLUNK_PORT}" \
    -auth admin:SplunkUF!2024

echo "=== [4/4] 모니터링 입력 설정 ==="

HOSTNAME=$(hostname)

if [ "$HOSTNAME" = "wordpress" ] || ip addr show | grep -q "10.0.10.80"; then
    echo "--- WordPress 서버 감지: 웹 로그 모니터링 설정 ---"

    # Apache access log
    /opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/access.log \
        -index idx_web -sourcetype apache:access -auth admin:SplunkUF!2024

    # Apache error log
    /opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/error.log \
        -index idx_web -sourcetype apache:error -auth admin:SplunkUF!2024

    # ModSecurity audit log
    /opt/splunkforwarder/bin/splunk add monitor /var/log/modsecurity/audit.log \
        -index idx_waf -sourcetype modsecurity -auth admin:SplunkUF!2024

    # WordPress auth log (wp-content/debug.log에 로그인 이벤트 포함)
    /opt/splunkforwarder/bin/splunk add monitor /var/www/html/wp-content/debug.log \
        -index idx_web -sourcetype wp:auth -auth admin:SplunkUF!2024

elif [ "$HOSTNAME" = "mysql" ] || ip addr show | grep -q "10.0.100.60"; then
    echo "--- MySQL 서버 감지: DB 로그 모니터링 설정 ---"

    # MySQL slow query log
    /opt/splunkforwarder/bin/splunk add monitor /var/log/mysql/slow-query.log \
        -index idx_db -sourcetype mysql:slowquery -auth admin:SplunkUF!2024

    # MySQL error log
    /opt/splunkforwarder/bin/splunk add monitor /var/log/mysql/error.log \
        -index idx_db -sourcetype mysql:error -auth admin:SplunkUF!2024
fi

/opt/splunkforwarder/bin/splunk restart

echo ""
echo "=== Splunk Forwarder 설정 완료 ==="
echo ""
echo "Splunk 서버(${SPLUNK_SERVER})에서 추가로 설정할 것:"
echo "  1. Settings > Forwarding and receiving > Configure receiving"
echo "     → New Receiving Port: ${SPLUNK_PORT}"
echo "  2. Settings > Indexes 에서 새 인덱스 생성:"
echo "     - idx_web  (웹 로그)"
echo "     - idx_waf  (WAF 로그)"
echo "     - idx_db   (DB 로그)"
