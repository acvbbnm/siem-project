# ATT&CK 매핑과 관측 지표

최종 WordPress·MySQL 관제 실습의 단계와 당시 판단에 사용한 로그입니다. 각 항목의 확인 범위는 실습 기록을 따릅니다.

| 실습 단계 | ATT&CK | 확인 범위 |
| --- | --- | --- |
| 정찰 | T1595 Active Scanning | Snort 경보와 웹 요청에서 정찰 관련 기록 확인 |
| 외부 공개 서비스 공격 시도 | T1190 Exploit Public-Facing Application | Snort와 WAF에서 요청 시도 확인 |
| 반복 로그인 | T1110 Brute Force | Apache 요청과 Splunk 경보 확인 |
| 웹셸 | T1505.003 Web Shell | 웹 요청과 서버 응답 대조 |
| 내부 조사 | T1046 Network Service Discovery | 기존 시나리오 매핑. 내부 정보 조회 흔적은 확인했고 네트워크 서비스 스캔은 미확정 |
| DB 접근 | T1213 Data from Information Repositories | 웹 응답에서 정보 노출 확인. DB 로그의 가시성은 일부에 한정 |
| 외부 전송 시도 | T1041 Exfiltration Over C2 Channel | 기존 시나리오 매핑. 전송 실패 확인, 명령제어 채널과 외부 수신은 미확정 |

## 관측 지표

- 최종 회차 실습 출발지. `10.50.50.30`이 Snort와 웹 로그에 기록됐습니다.
- 웹 요청의 User-Agent. `WPScan`과 `Hydra`가 남아 있었습니다. 같은 시각대의 요청량과 출발지를 함께 대조했습니다.
- 웹셸 관련 요청. 웹 기록과 실행 결과가 포함된 응답을 함께 확인했습니다.

[관제와 대응](../response/README.md) · [최종 보고서](../../report/README.md)
