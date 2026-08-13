# pfSense 방화벽 규칙 변경 사항

## 기존 규칙 유지

Phase 2에서 설정한 모든 규칙 유지:
- WAN: 10.50.50.17 Block (1차 대응, 현재 비활성)
- DMZNET: DMZ→내부(10.0.100.0/24) 차단
- DMZNET: DMZ 아웃바운드 전체 차단
- Snort: Block Offenders ON (3차 대응)

## 신규 NAT 규칙

### WAN → WordPress NAT
| 항목 | 설정 |
|------|------|
| Interface | WAN |
| Protocol | TCP |
| Source | any |
| Dest Port | 8080 |
| Redirect Target | 10.0.10.80 |
| Redirect Port | 80 |
| Description | WAN:8080 → WordPress HTTP |

→ 외부에서 `http://10.0.0.254:8080`으로 WordPress 접근

### WAN Firewall 규칙 (NAT 연동)
| 항목 | 설정 |
|------|------|
| Action | Pass |
| Interface | WAN |
| Protocol | TCP |
| Source | any |
| Destination | 10.0.10.80 |
| Dest Port | 80 |
| Description | Allow HTTP to WordPress (NAT) |

## 신규 DMZNET 규칙

### WordPress → MySQL 허용
| 항목 | 설정 |
|------|------|
| Action | Pass |
| Interface | DMZNET |
| Protocol | TCP |
| Source | 10.0.10.80 |
| Destination | 10.0.100.60 |
| Dest Port | 3306 |
| Description | WordPress → MySQL only |

**규칙 순서 (DMZNET):**
1. Pass: 10.0.10.80 → 10.0.100.60:3306 (WordPress→MySQL)
2. Block: DMZ → 10.0.100.0/24 (기존, 나머지 inner-net 차단)
3. Block: DMZ → any (기존, 아웃바운드 전체 차단)

## Snort 설정 추가

### WAN 인터페이스
- 커스텀 룰 추가: `local.rules` (SID 1000001~1000009)
- Categories: ET Open + GPLv2 + Local Rules 활성화

### pfSense > Services > Snort > WAN Rules
1. Custom Rules 탭 클릭
2. `configs/snort/local.rules` 내용 붙여넣기
3. Save → Apply
