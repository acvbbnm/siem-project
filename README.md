# SIEM 공격 탐지·대응 실습

ESXi에 웹·DB·관리망을 분리해 가상 기업망을 만들고, 네트워크·웹·DB 로그를 Splunk에 모았습니다. 같은 시각대의 방화벽·IPS와 서버 기록을 대조해 모의 사고가 어디까지 이어졌는지 조사했습니다.

개인 프로젝트

## 최종 네트워크 구성

![최종 보고서의 네트워크 구성도. DMZ에는 WordPress와 Bee-box, 내부망에는 Splunk와 MySQL이 있습니다.](report/images/final-topology.png)

[가상 스위치와 VM 배치](docs/environment/README.md#가상-스위치와-vm-배치)

### Splunk 로그 수집

![pfSense·Snort, WordPress·WAF, MySQL에서 Splunk로 보내는 로그](report/images/log-collection.png)

## 최종 보고서

**[SIEM 구축 및 탐지 대응 보고서 PDF](report/siem-report.pdf)** · [Word](report/siem-report.docx)

웹 요청과 실행 응답을 대조해 DB 정보가 노출된 범위를 확인했습니다. pfSense 정책을 적용한 뒤 같은 출발지에서 다시 접속해 차단 결과를 확인했습니다.

## 실습 기록

| 작업 | 내용 |
| --- | --- |
| [환경 구축](docs/environment/README.md) | ESXi 가상망, 로그 수집과 초기 Bee-box 검증 |
| [탐지 설계](docs/detection/README.md) | Snort·ModSecurity 탐지와 Splunk 검색 및 경보 |
| [관제·대응](docs/response/README.md) | 사건 일지와 pfSense 정책 적용 전후의 관측 결과 |
