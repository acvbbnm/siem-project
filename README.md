# SIEM 공격 탐지·대응 실습

가상 기업망에서 네트워크·웹·DB 로그를 Splunk로 모아 경보를 판정하고, 방화벽 차단 결과를 검증한 개인 프로젝트입니다.

[최종 보고서 · 9월 정정본](https://github.com/acvbbnm/siem-project/blob/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/final-report.md) · [31쪽 요약 보고서](phase4-soc/project-summary-report.pdf) · [관제 일지](https://github.com/acvbbnm/siem-project/blob/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/incident-log.md)

![Splunk SOC_Monitor 대시보드](https://raw.githubusercontent.com/acvbbnm/siem-project/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/images/soc-12-dashboard-fullscreen-overview.png)

## 가상망과 로그 수집

ESXi에 공격 실습망, DMZ, 내부망, 관리망을 나눴습니다. pfSense·Snort는 망 경계에, ModSecurity는 웹 서버에 두고 방화벽·IPS, 웹·WAF, MySQL 로그를 Splunk로 모았습니다. [환경 구축](phase2.5-setup/README.md) · [로그 인덱스 설정](phase2.5-setup/splunk/indexes.conf)

## 경보 판정과 정책 검증

경보의 시각과 출발지를 웹·WAF 기록에 맞춰 어떤 요청이 도달했는지 확인했습니다. DB 접근은 전용 경보 없이 일부 흔적만 관찰돼 감사 로그 수집을 개선안으로 남겼습니다. 스캐너 경보가 발생하지 않은 원인과 별도 외부 전송 시도의 실패 원인은 미확정으로 기록했습니다.

pfSense 정책 적용 전후를 비교해 같은 출발지의 HTTP 재접속이 타임아웃되는 것을 확인했습니다. DMZ 통신 제한과 Snort 차단 모드도 별도로 검증했습니다. [방화벽·IPS 검증](phase2-detect/README.md) · [SOC 대응 기록](https://github.com/acvbbnm/siem-project/blob/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/README.md)

## Splunk 검색 예시

랩을 구성하고 수집을 시작한 뒤 인덱스별 이벤트 수를 조회합니다. 한 인덱스의 값이 비어 있으면 먼저 입력과 라우팅 설정을 확인합니다.

~~~spl
(index=pfsense OR index=idx_web OR index=idx_waf OR index=idx_db)
| stats count by index
~~~

이 저장소의 [구축 문서](phase2.5-setup/README.md)와 [개발 기록](DEVELOPMENT.md)에서 필요한 VM, 네트워크, 수집 설정을 확인할 수 있습니다.
