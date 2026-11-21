# SIEM 공격 탐지·대응 실습

기업의 기본 3계층(웹·애플리케이션·DB) 인프라를 ESXi에 구축했습니다. Apache와 WordPress는 DMZ에, MySQL은 내부망에 배치했습니다. 망 경계에는 pfSense와 Snort를, 웹 서버에는 ModSecurity WAF를 붙였습니다. 방화벽 정책과 탐지 룰을 설정하고, 장비와 서버 로그를 Splunk에 연동해 관제 환경을 구성했습니다.

이 환경에서 외부 정찰부터 웹을 거쳐 DB에 접근하는 모의 침해 시나리오를 실습했습니다. pfSense는 망 사이의 연결을 제어하고, Snort는 네트워크 트래픽의 패턴을, ModSecurity는 HTTP 요청의 내용을 검사했습니다. 같은 시도의 흔적이 장비마다 어떻게 남는지 비교하고, 웹 응답과 DB 로그를 대조해 영향 범위를 판단했습니다.

방어자 관점에서는 Splunk 대시보드와 경보로 각 장비의 이벤트를 모니터링했습니다. 경보를 원본 로그와 대조해 사고 흐름을 재구성하고, pfSense 정책을 적용한 뒤 재접속으로 차단을 확인했습니다. 탐지에서 놓친 부분과 재발 방지 방안은 최종 보고서에 정리했습니다.

개인 프로젝트

## 최종 네트워크 구성

![최종 보고서의 네트워크 구성도. DMZ에는 WordPress와 Bee-box, 내부망에는 Splunk와 MySQL이 있습니다.](report/images/final-topology.png)

[가상 스위치와 VM 배치](docs/environment/README.md#가상-스위치와-vm-배치)

### Splunk 로그 수집

![pfSense·Snort, WordPress·WAF, MySQL에서 Splunk로 보내는 로그](report/images/log-collection.png)

## 최종 보고서

**[SIEM 구축 및 탐지 대응 보고서 PDF](report/siem-report.pdf)** · [Word](report/siem-report.docx)

계층별 탐지 결과, 로그로 확인한 침해 범위, 방화벽 차단 결과와 재발 방지 방안을 담았습니다.

## 실습 기록

1. **[환경 구축](docs/environment/README.md)** · 포트 그룹, VM 배치, 로그 전송 경로
2. **[공격 시나리오](docs/scenario/README.md)** · 사고 전개 순서와 관측 근거 / **[계층별 탐지](docs/detection/README.md)** · Snort·WAF 탐지, Splunk 검색과 경보
3. **[관제·대응](docs/response/README.md)** · 사건 일지, 차단 전후 기록, 후속 조치
