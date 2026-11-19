# SIEM 공격 탐지·대응 실습

가상 기업망에서 네트워크·웹·DB 로그를 대조해 사고 흐름을 재구성하고 방화벽 차단을 검증했습니다.

개인 프로젝트 · 2026년 8월 실습, 9월 보고서 정정 · 가상망 구성, 탐지, 관제 기록과 보고서 작성

[최종 보고서 · 정정본](https://github.com/acvbbnm/siem-project/blob/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/final-report.md) · [31쪽 PDF](phase4-soc/project-summary-report.pdf) · [관제 일지](https://github.com/acvbbnm/siem-project/blob/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/incident-log.md)

![경보, 최근 웹 요청, WAF와 DB 기록을 모아 본 Splunk SOC_Monitor 화면](https://raw.githubusercontent.com/acvbbnm/siem-project/d2b206ccab362037f6dfd3596c7700641aba744f/phase4-soc/images/soc-12-dashboard-fullscreen-overview.png)

## 구역마다 관측할 로그를 배치한 방법

~~~mermaid
flowchart LR
    A["격리 실습망"] --> F["pfSense · Snort"]
    F --> W["DMZ · 웹 · ModSecurity"]
    W --> D["내부망 · MySQL"]
    F --> S["Splunk"]
    W --> S
    D --> S
    S --> T["경보 판정 · 사고 기록"]
~~~

망 경계의 Snort는 네트워크 요청을, 웹 서버의 Apache·ModSecurity는 애플리케이션 동작을 관측했습니다. Splunk에서 시각과 출발지를 대조해 경보가 난 시점에 실제로 어디까지 접근했는지 확인했습니다.

## DB 접근과 외부 전송을 구분한 조사

- **문제.** 웹 서버를 거친 DB 접근이 있었지만 DB의 전용 경보가 없었습니다. 별도 외부 전송 시도도 응답 오류로 끝났습니다.
- **판단.** 웹 응답에서 DB 정보 노출을 확인했습니다. 당시 MySQL 오류·슬로우 로그만으로 조회 의도를 판별하기 어려웠고, 외부 전송 실패 원인은 미확정으로 기록했습니다.
- **대응과 검증.** pfSense 정책 적용 전후에 같은 출발지의 HTTP 재접속을 확인했습니다. 정책 적용 뒤 타임아웃을 기록했고, DMZ 통신 제한과 Snort 차단 모드도 별도로 검증했습니다.
- **결과.** 실습의 7단계 중 5단계에서 공격 시도 탐지, DB 접근 1단계에서 부분 탐지를 기록했습니다. DB 쿼리 감사 로그 수집은 후속 개선안으로 남겼습니다.

[방화벽·IPS 검증](phase2-detect/README.md) · [가상망 구축과 Splunk 설정](phase2.5-setup/README.md)
