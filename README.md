# SIEM 공격 탐지·대응 실습

ESXi에 기업 서비스의 기본 3계층(웹·애플리케이션·DB)을 구성했습니다. Apache와 WordPress는 DMZ의 같은 VM에 두고, MySQL은 내부망에 배치했습니다. pfSense 방화벽, Snort, ModSecurity WAF를 연동하고 장비별 정책과 탐지 룰을 설정했습니다. 보안 장비와 서버의 로그는 Splunk에 모아 한곳에서 관제했습니다.

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

1. **[환경 구축](docs/environment/README.md)** — ESXi에서 망을 분리하고 경계에 pfSense·Snort, 웹 서버에 ModSecurity를 배치했습니다. 방화벽 정책과 탐지 룰을 설정한 뒤 Splunk에 로그를 연동했습니다.
2. **[공격 시나리오](docs/scenario/README.md)와 [계층별 탐지](docs/detection/README.md)** — 정찰부터 웹을 거쳐 DB에 접근하는 흐름을 실습했습니다. Snort의 네트워크 경보, ModSecurity의 HTTP 요청 탐지, 웹·DB 로그를 비교해 각 계층에서 무엇을 확인할 수 있는지 기록했습니다.
3. **[관제·대응](docs/response/README.md)** — Splunk 경보와 원본 로그를 대조해 사고 흐름을 재구성했습니다. pfSense에서 차단 정책을 적용한 뒤 재접속으로 결과를 확인하고, 탐지 공백과 재발 방지 방안을 보고서에 정리했습니다.
