# 클라우드 AI 개발 환경 셋업 가이드

레포 안의 뼈대(CLAUDE.md / GitHub Action / devcontainer / 스킬)는 이미 준비됨.
아래는 **회원님 계정 인증이 필요해 직접 하셔야 하는** 나머지 연결 단계다.

## A. GitHub Action 활성화 (스마트폰에서 @claude 쓰기)

1. GitHub의 Claude App 설치: https://github.com/apps/claude 에서 `sasumm25-lab/siem-project` 저장소에 설치.
2. 저장소 → **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `ANTHROPIC_API_KEY`
   - Value: (console.anthropic.com 에서 발급한 API 키)
   - 또는 CLI에서 `claude setup-token` 으로 만든 토큰을 `CLAUDE_CODE_OAUTH_TOKEN` 으로 등록 후 워크플로 입력값을 교체.
3. 확인: 이슈를 하나 만들고 본문에 `@claude 이 저장소 구조 요약해줘` 작성 → Actions 탭에서 실행 여부 확인.

## B. Codespaces (아이패드/브라우저에서 CLI)

1. 저장소 상단 **Code → Codespaces → Create codespace on main**.
2. 컨테이너가 뜨면 `.devcontainer`가 자동으로 Claude Code CLI를 설치함.
3. 터미널에서 `claude` 실행 → 최초 1회 브라우저 로그인.
4. (선택) API 키 자동주입: 저장소 **Settings → Secrets and variables → Codespaces**에 `ANTHROPIC_API_KEY` 등록.

## C. MCP 커넥터 연결 (Notion / Slack 등)

> 커넥터는 OAuth 로그인이 필요해 회원님이 직접 승인해야 한다.

- **로컬 Claude Code에서:** `claude mcp add` 명령 또는 설정에서 커넥터 추가 후 브라우저 인증.
  - Notion: 진행상황을 노션 대시보드에 자동 동기화
  - Slack: 백그라운드 작업 완료 알림 수신
- 연결 후 사용 예: "지금까지 phase1 진행상황을 노션 대시보드에 업데이트해줘", "테스트 끝나면 슬랙으로 알려줘"

## D. (선택) 스케줄 루틴 — 매일 자동 리포트

로컬 Claude Code에서 `/schedule` 스킬로 cron 루틴 등록.
예) 매일 정해진 시각에 "전날 변경사항 요약 + 미완료 체크리스트 리마인드" 생성.

---

### 요약 체크리스트
- [ ] A. Claude GitHub App 설치 + `ANTHROPIC_API_KEY` 시크릿 등록
- [ ] B. Codespace 1회 생성 및 `claude` 로그인
- [ ] C. Notion/Slack MCP 커넥터 인증
- [ ] D. (선택) 스케줄 루틴 등록
