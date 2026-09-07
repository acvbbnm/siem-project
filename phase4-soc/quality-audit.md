# 문서 품질 점검 기록

점검일: 2026-09-07. 기준 커밋: 816b54d. 이번 변경은 기존 실습 기록과 캡처를 대조한 문서 수정이며, 실제 서버 설정 변경이나 공격 재시험은 수행하지 않았다.

## 문서 기준

- 통합 보고서: `report-draft-v2.md`. SOC 요약: `final-report.md`. 면접 자료: `interview-prep.md`.
- `siem_report_with_images.docx`는 본문·표를 수정했으나 렌더링 검증 대기 상태다. 제공된 런타임에 LibreOffice가 없어 페이지 넘침·표 배치를 확인하지 못했다. 제출 전 렌더링 검수가 필요하다.
- `project-summary-report.html`과 `project-summary-report.pdf`는 이번 정정 이전의 출력본이다. 최신 보고서로 사용하지 말고 수정된 원고에서 재생성해야 한다.
- 루트의 추적되지 않은 `projectsummaryreport.docx`는 사용자가 제공한 참고 원본이며 변경하지 않았다.
- `phase3-soc`는 이전 SOC 양식·증거 보관용이다. 완료 상태는 루트 README와 `phase4-soc`를 기준으로 확인한다.

## 확인한 사실

| 항목 | 정정 기준 | 근거 |
|---|---|---|
| Bee-box Stored XSS | 공격 성공, 해당 실습 Snort 미탐지 | `../phase1-attack/README.md`, 루트 체크리스트 |
| Bee-box 브루트포스 | Hydra 자동화 실패, 수동 로그인 성공, Snort 미탐지 | `../phase1-attack/README.md` |
| SOC 대시보드 | 8패널; db_approach 포함 | `images/soc-12-dashboard-fullscreen-overview.png` |
| Alert | 설정 5종, 발생 확인 4종, 합계 8회 | `images/soc-kc-25-triggered-alerts-final-8.png`, 2026-08-27 19:45 KST |
| 누락 경보 | 19:45:00 Webshell Detection, Medium | 위 최종 캡처; 검색 결과 상세 원인은 추가 확인 |
| 외부 전송 | Connection refused로 실패, 원인 미확정 | 킬체인 실행 기록. 웹쉘 응답을 통한 DB 정보 노출과 구분 |
| Scanner Alert | 최종 캡처에 없음, 원인 미확정 | 예약 검색 실행 이력·검색 구간·임계값·수집 지연 확인 필요 |
| 965건 | WordPress POST 로그 집계, 성공·실패 미구분 | Phase 4 기록. 요청 중복·수집 중복 여부도 검증 필요 |

## 실제 환경에서 확인할 작업

- [ ] 실제 pfSense Snort 룰을 내보내고 SID·메시지·검사 방향을 저장소와 일치시킨다. 매핑 표의 존재는 동기화 완료를 의미하지 않는다.
- [ ] 실제 rsyslog 설정, Splunk 입력·props·transforms·대시보드·saved searches를 백업한다. 기존 Forwarder 파일은 초기 설계 자료다.
- [ ] Scanner Alert 미발생 원인과 19:45 Webshell 경보의 검색 범위를 확인한다. 차단 후 경보 발생만으로 새 공격 성공을 판정하지 않는다.
- [ ] POST 집계를 로그인 실패 건수와 구분하고, IP별 집계·인증 결과·중복 로그를 검증한다. 보고서의 SPL은 당시 사용 쿼리로 보존했다.
- [ ] WAF DetectionOnly 탐지 시험과 차단 모드 시험을 분리한다.
- [ ] DB 감사 로그·단말 실행 로그를 추가한 뒤 실제 탐지 효과를 검증한다.
- [ ] 별도 외부 전송 실패 원인을 방화벽 로그와 수신 서비스 상태로 대조한다.
- [ ] DOCX 렌더링 검수 후 HTML·PDF 출력본을 다시 생성한다.

## 해석 기준

공격 시도 로그, 경보 종류·발생 횟수, 침해 성공, 대응 효과는 별도 지표다. 실행하지 않은 공격은 미시험이며 미탐지율에 포함하지 않는다. 프레임워크 매핑과 개선 제안은 실제 적용·검증 결과와 구분한다.
