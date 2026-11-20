# SIEM 공격 탐지·대응 실습

ESXi에 웹·DB·관리망을 분리해 가상 기업망을 만들고, 네트워크·웹·DB 로그를 Splunk에 모았습니다. 같은 시각대의 방화벽·IPS와 서버 기록을 대조해 모의 사고가 어디까지 이어졌는지 조사했습니다.

2026년 8월 · 개인 프로젝트

## 최종 보고서

**[SIEM 구축 및 탐지 대응 보고서](report/README.md)**에서 최종 실습망, 사고 타임라인, 탐지와 차단 결과를 읽을 수 있습니다. [PDF](report/siem-report.pdf) · [Word](report/siem-report.docx)

웹 요청과 실행 응답을 대조해 DB 정보가 노출된 범위를 확인했습니다. pfSense 정책을 적용한 뒤 같은 출발지에서 다시 접속해 차단 결과를 확인했습니다.

## 실습 기록

| 작업 | 내용 |
| --- | --- |
| [네트워크 구성](network/README.md) | 최종 ESXi 가상망과 Splunk로 들어오는 로그의 출처 |
| [공격 시나리오](scenario/README.md) | Bee-box 사전 실습, WordPress·MySQL 환경의 모의 사고 흐름 |
| [로그 분석과 탐지](detection/README.md) | [Snort 룰](detection/local.rules), [Splunk 검색](detection/spl), [ATT&CK 매핑과 관측 지표](detection/indicators.md) |
| [관제와 대응](response/README.md) | 사건 일지와 pfSense 정책 적용 전후의 관측 결과 |
