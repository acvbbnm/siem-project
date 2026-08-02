---
name: update-progress
description: 실습 로그(명령 출력, Splunk/Snort 결과)를 붙여넣으면 해당 phase README의 "결과:" 블록을 채우고 루트 README의 진행 체크리스트를 갱신한다. "진행상황 반영", "결과 기록", "체크 갱신" 요청 시 사용.
---

# update-progress — 실습 결과를 문서에 반영

## 목적
회원님이 실습에서 얻은 실제 출력(터미널 로그, Splunk 쿼리 결과, Snort 경보)을 붙여주면,
그 내용을 올바른 위치에 기록하고 진행 체크리스트를 최신 상태로 유지한다.

## 절차
1. 붙여진 로그가 어느 항목인지 식별한다 (예: `nmap -sS` → Phase1 R-1, `sqlmap` → E-2, Splunk `top signature` → Phase2 분석).
2. 해당 phase README(`phase1-attack/README.md`, `phase2-detect/README.md`, `phase3-soc/README.md`)의 그 항목 **"결과:"** 블록 아래에 다음을 채운다:
   - 실행한 명령
   - 실제 출력(핵심만 발췌, 코드블록)
   - 이미지가 있으면 `images/<파일명>` 상대경로로 참조
   - Snort/Splunk 탐지 여부 (탐지됨/미탐지)
3. 루트 `README.md`에서 해당 `- [ ]` 항목을 `- [x]`로 바꾼다. **로그 근거가 있는 항목만** 완료 처리한다.
4. `phase3-soc/incident-log.md`에 해당하는 사건이면 `[INC-xxx]` 양식으로 추가한다.
5. 변경 요약을 한두 줄로 보고한다.

## 주의
- 근거(붙여진 로그)가 없는 항목은 절대 완료로 바꾸지 않는다.
- 기존 문서의 표/구조를 유지하고, 해당 블록만 최소 편집한다.
