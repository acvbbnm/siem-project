#!/bin/bash
# 정상 트래픽 생성 스크립트
# 대상: mng-mint (10.0.50.100) — crontab에 등록
# 실행: crontab에 등록하여 자동 실행
#   */5 * * * * /home/user/normal-traffic.sh >> /var/log/normal-traffic.log 2>&1

WP_URL="http://10.0.10.80"

# 랜덤 지연 (1~10초)
random_delay() {
    sleep $((RANDOM % 10 + 1))
}

# 메인 페이지 방문
curl -s -o /dev/null -w "GET / -> %{http_code}\n" "${WP_URL}/"
random_delay

# 블로그 페이지 탐색
curl -s -o /dev/null -w "GET /blog/ -> %{http_code}\n" "${WP_URL}/blog/" 2>/dev/null
random_delay

# 회사 소개 페이지
curl -s -o /dev/null -w "GET /about/ -> %{http_code}\n" "${WP_URL}/%ed%9a%8c%ec%82%ac-%ec%86%8c%ea%b0%9c/" 2>/dev/null
random_delay

# 문의 페이지 접근
curl -s -o /dev/null -w "GET /contact/ -> %{http_code}\n" "${WP_URL}/%eb%ac%b8%ec%9d%98%ed%95%98%ea%b8%b0/" 2>/dev/null
random_delay

# 정상 로그인 시도 (간헐적 — 30% 확률)
if [ $((RANDOM % 10)) -lt 3 ]; then
    # 쿠키 저장하여 로그인 세션 유지
    curl -s -o /dev/null -c /tmp/wp-cookies.txt \
        -d "log=editor&pwd=Editor!2024&wp-submit=Log+In" \
        "${WP_URL}/wp-login.php"
    random_delay

    # 로그인 후 대시보드 접근
    curl -s -o /dev/null -b /tmp/wp-cookies.txt \
        "${WP_URL}/wp-admin/"
    rm -f /tmp/wp-cookies.txt
fi

# RSS 피드 확인 (검색엔진 봇 시뮬레이션)
if [ $((RANDOM % 10)) -lt 2 ]; then
    curl -s -o /dev/null -A "Googlebot/2.1" "${WP_URL}/feed/"
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 정상 트래픽 생성 완료"
