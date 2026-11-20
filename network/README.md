# 네트워크 구성

ESXi에서 실습망, 외부 경계망, DMZ, 내부망, 관리망을 나눴습니다. VyOS는 라우팅을 맡고, pfSense와 Snort는 망 경계에서 통신과 경보를 기록합니다.

## 최종 실습망

실선은 네트워크 연결, 점선은 Splunk로 보내는 로그를 표시합니다.

~~~mermaid
flowchart LR
    A["실습망의 Kali"] --> V["VyOS 라우터"]
    V -->|"rf-net"| F["pfSense·Snort"]
    F --> W["DMZ<br/>WordPress·ModSecurity"]
    F --> D["내부망 MySQL"]
    F --> S["내부망 Splunk"]
    F --> M["관리 단말"]
    W -. "웹·WAF·인증" .-> S
    F -. "방화벽·IDS" .-> S
    D -. "오류·느린 쿼리" .-> S
~~~

복구한 ESXi에는 VM 9대가 등록돼 있습니다. VM 목록에서 `ubuntu`의 호스트 이름이 `splunk`로 표시됩니다. ESXi 관리용 `Management Network`는 `vSwitch0`에 있고, 실습 관리 단말의 `mng-net`은 별도 vSwitch에 연결됩니다.

![복구한 ESXi의 VM 목록과 Splunk 호스트 이름](../report/images/recovered-esxi-vms.png)

![복구한 ESXi의 포트 그룹과 vSwitch 연결](../report/images/recovered-esxi-port-groups.png)

## 초기 Bee-box 환경

![Bee-box 기반 초기 가상망 구성도](../report/images/network.png)

Bee-box에서 탐지와 차단을 먼저 확인했습니다. 최종 실습에는 DMZ의 WordPress·ModSecurity와 내부망의 MySQL을 추가했습니다.

## 로그를 확인한 위치

| 구역 | 구성 | 관측 내용 |
| --- | --- | --- |
| 실습망 | att-mint, Kali | 실습에서 발생시킨 접근 |
| 경계망 | VyOS, pfSense, Snort | 라우팅, 방화벽 정책, 네트워크 경보 |
| DMZ | Bee-box, WordPress, Apache, ModSecurity | 웹 요청·오류, WAF 경보, 인증 시도 |
| 내부망 | MySQL, Splunk | DB 오류·느린 쿼리, 로그 통합 조회 |
| 관리망 | 관리 단말 | 정상 요청 비교와 관제 작업 |

pfSense syslog는 Splunk의 `pfsense`로, 웹·WAF·인증 로그는 `idx_web`로, MySQL 로그는 `idx_db`로 들어갔습니다. WAF용 `idx_waf`는 설정했으나 실제 관측은 `idx_web`에서 했습니다.

[최종 보고서](../report/README.md)
