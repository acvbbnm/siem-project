#!/bin/bash
# ModSecurity WAF 설치 및 OWASP CRS 적용
# 대상: WordPress 서버 (10.0.10.80)
# 실행: sudo bash 03-modsecurity-install.sh

set -e

echo "=== [1/5] ModSecurity 설치 ==="
apt install -y libapache2-mod-security2

echo "=== [2/5] OWASP CRS 다운로드 ==="
cd /etc/modsecurity/
git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs 2>/dev/null || {
    echo "[!] git clone 실패 — 오프라인 환경이면 수동 다운로드 필요"
    echo "    https://github.com/coreruleset/coreruleset/releases"
    exit 1
}
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

echo "=== [3/5] ModSecurity 기본 설정 ==="
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# DetectionOnly 모드로 시작 (로그만, 차단 안 함)
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# 감사 로그 설정 (Splunk 연동)
cat >> /etc/modsecurity/modsecurity.conf << 'MODEOF'

# 감사 로그 (Splunk 연동)
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/audit.log
SecAuditLogParts ABCFHZ
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
MODEOF

mkdir -p /var/log/modsecurity
chown www-data:www-data /var/log/modsecurity

echo "=== [4/5] 커스텀 룰 적용 (의도적 허점 포함) ==="
cp "$(dirname "$0")/../configs/modsecurity/custom-exclusions.conf" \
   /etc/modsecurity/custom-exclusions.conf

echo "=== [5/5] Apache에 ModSecurity 연동 ==="
# Apache 설정에 ModSecurity 포함
cat > /etc/apache2/mods-available/security2.conf << 'APACHEMOD'
<IfModule security2_module>
    # ModSecurity 기본 설정
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # OWASP CRS
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf

    # 커스텀 예외 (의도적 허점)
    IncludeOptional /etc/modsecurity/custom-exclusions.conf
</IfModule>
APACHEMOD

a2enmod security2
systemctl restart apache2

echo ""
echo "=== ModSecurity 설치 완료 ==="
echo ""
echo "WAF 동작 테스트:"
echo "  curl 'http://10.0.10.80/?id=1+OR+1=1' -v"
echo "  → 403 Forbidden이면 WAF 차단 동작 정상"
echo ""
echo "로그 확인:"
echo "  tail -f /var/log/modsecurity/audit.log"
echo ""
echo "주의: custom-exclusions.conf에 의도적 허점이 설정되어 있음"
echo "  - SQLi 942xxx: DetectionOnly (로그만, 차단 안 함)"
echo "  - File Upload 930xxx: .php만 차단, .phtml 우회 가능"
echo "  - Scanner 913xxx: DetectionOnly (wpscan 허용)"
