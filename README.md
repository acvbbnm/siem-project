# SIEM 공격 탐지·대응 실습

가상 기업망에서 네트워크·웹·DB 로그를 Splunk로 수집하고, 모의 사고의 흐름과 차단 결과를 확인한 개인 프로젝트입니다.

[최종 보고서](report/README.md) · [요약 PDF](report/siem-report.pdf)

![Splunk SOC_Monitor 대시보드](report/images/soc-dashboard.png)

## 실습 기록

| 작업 | 내용 |
| --- | --- |
| [네트워크 구성](network/README.md) | ESXi 가상망, pfSense·Snort, WordPress·MySQL, Splunk 로그 수집 |
| [공격 시나리오](scenario/README.md) | Bee-box 사전 실습과 WordPress·MySQL 환경의 7단계 시나리오 |
| [로그 분석과 탐지](detection/README.md) | Snort 룰, Splunk 검색과 경보, ATT&CK 매핑과 관측 지표 |
| [관제와 대응](response/README.md) | 사건 일지, 방화벽 정책 적용, 차단 전후 확인 |

실습은 2026년 8월에 진행했습니다. 보고서의 탐지 결과와 미확정 항목은 9월 정정본을 기준으로 정리했습니다.
