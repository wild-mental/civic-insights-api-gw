# 04) API Gateway 기반 Auth/News 서비스 연동 테스트 가이드

목표: 게이트웨이(8000) 경유로 인증 서비스(8001)와 뉴스 서비스(8080)를 호출하여, 분산 인증 기반 보호 리소스(프리미엄 상세)를 끝까지 검증한다. 초보자도 따라할 수 있도록 단계별 테스트 흐름을 제공한다.

---

## 1. 사전 준비
- 실행 포트: Gateway 8000, Auth 8001, News 8080
- 기본 환경변수(선택)
```bash
export GATEWAY_SECRET_TOKEN=${GATEWAY_SECRET_TOKEN:-civic-insights-gateway-v1}
export FRONTEND_BASE_URL=${FRONTEND_BASE_URL:-http://localhost:9002}
```
- 애플리케이션 기동(각 모듈 루트에서)
```bash
# Auth
./gradlew :civic-insights-auth:bootRun
# News
./gradlew :civic-sights-main:bootRun
# Gateway
cd civic-insights-api-gw && ./gradlew bootRun
```

---

## 2. 게이트웨이 라우팅 확인 및 매핑 관계

### 2.1 라우팅 상태 확인
자동화된 스크립트로 라우팅 정보를 한번에 확인할 수 있습니다:
```bash
# 전체 라우팅 정보 조회 스크립트 실행
./scripts/gateway-routes-info.sh
```

또는 수동으로 확인:
```bash
# Gateway 상태 확인
curl http://localhost:8000/actuator/health | jq .

# 등록된 라우트 개수 확인
curl "http://localhost:8000/actuator/metrics/spring.cloud.gateway.routes.count" | jq .

# 라우트 ID 목록 확인
curl -s "http://localhost:8000/actuator/metrics/spring.cloud.gateway.requests" | \
  jq -r '.availableTags[] | select(.tag == "routeId") | .values[]'
```

### 2.2 라우팅 매핑 관계 (외부 API → 내부 서비스)
- **네임스페이스 명시 전략**: 외부 API는 서비스별 네임스페이스를 제공
- **버전리스 전략**: 백엔드 버전 정보를 내부에 숨김

| 외부 API | 내부 서비스 | 인증 | 설명 |
|------------|------------|------|------|
| `/.well-known/jwks.json` | `8001/.well-known/jwks.json` | ❌ | JWKS 공개키 |
| `/api/news/articles/premium` | `8080/api/articles/premium` | ❌ | 프리미엄 목록 |
| `/api/news/articles/premium/**` | `8080/api/articles/premium/**` | ✅ | 프리미엄 상세 |
| `/api/news/articles/**` | `8080/api/articles/**` | ❌ | 일반 뉴스 |
| `/api/auth/profile/**` | `8001/api/v1/profile/**` | ✅ | 사용자 프로필 |
| `/api/auth/**` | `8001/api/v1/auth/**` | ❌ | 인증 서비스 |

### 2.3 보호 정책
- **JWT 검증**: `AuthorizationHeaderFilter`가 수행
- **사용자 헤더 전달**: `X-User-Id`, `X-User-Roles`, `X-Token-Issuer`
- **보안 헤더**: `X-Gateway-Internal` (백엔드 직접 접근 차단)
- **권한 검사**: 뉴스 프리미엄 상세는 `PAID_USER` 역할 필요

---

## 2.4 라우팅 정보 스크립트 출력 예시
`./scripts/gateway-routes-info.sh` 실행 시 다음과 같은 정보를 확인할 수 있습니다:

```
=== Civic Insights API Gateway 라우팅 정보 ===

1. Gateway 상태: UP
2. 등록된 라우트 개수: 총 7개의 라우트가 등록되어 있습니다.
3. 라우트 ID와 대상 서비스:
  - Route ID: system-jwks, news-premium-list, news-premium-detail, 
             news-management, news-articles, auth-profile, auth-login
4. 대상 서비스 URI:
  - Target: http://localhost:8080 (뉴스 서비스)
  - Target: http://localhost:8001 (인증 서비스)
5. 실제 라우팅 매핑 테스트:
  시스템-JWKS: /.well-known/jwks.json → ✓ 라우팅 성공 (200)
  뉴스-프리미엄목록: /api/news/articles/premium → ✓ 라우팅 성공 (200)
  뉴스-프리미엄상세: /api/news/articles/premium/1 → ✓ 라우팅 성공, 인증 필요 (401)
  인증-로그인: /api/auth/google → ✓ 라우팅 성공 (302)
  인증-프로필: /api/auth/profile → ✓ 라우팅 성공, 인증 필요 (401)
```

> **💡 상태 코드 해석**:
> - `200/302`: 라우팅 성공, 백엔드 서비스 정상
> - `401`: 라우팅 성공, 인증 필요 (AuthorizationHeaderFilter 정상 동작)
> - `404`: 라우팅 규칙 문제 또는 경로 오류
> - `502`: 라우팅 성공, 백엔드 서비스 미실행

---

## 3. 인증 플로우(Next 없는 순수 테스트)
> 실제 프런트엔드는 BFF/세션 쿠키로 운용하나, 여기서는 curl 기반 간이 검증 흐름을 안내한다.

### 3.1 Google 로그인 시작(게이트웨이 경유)
```bash
open "http://localhost:8000/api/auth/google"
```
- Google 로그인 완료 후 게이트웨이→Auth 콜백으로 돌아간다.
- 현재 데모 구현: Auth 콜백이 자동 제출 HTML 폼으로 토큰을 프런트 `/api/session`에 POST(실서비스는 BFF 완전형 권장).

### 3.2 토큰 직접 발급(테스트용 백도어: Auth API)
> 프론트 없이 빠르게 토큰을 얻기 위한 테스트 방법. 실제 운영 흐름과는 다르다.
```bash
# OAuth 코드가 있다면 (게이트웨이 경유)
curl -s -X POST http://localhost:8000/api/auth/google/token \
  -H 'Content-Type: application/json' \
  -d '{"code":"<google_auth_code>"}' | jq .

# 직접 인증 서비스 호출 (개발/디버깅용)
curl -s -X POST http://localhost:8001/api/v1/auth/google/token \
  -H 'Content-Type: application/json' \
  -d '{"code":"<google_auth_code>"}' | jq .
```
- 응답의 `accessToken`을 `$TOKEN` 변수에 보관한다.

---

## 4. 뉴스 서비스 호출(게이트웨이 경유)

### 4.1 공개 엔드포인트(목록)
```bash
# 1. 프리미엄 뉴스 목록 (인증 불필요)
curl -i http://localhost:8000/api/news/articles/premium
# 기대: 200 OK 또는 502 Bad Gateway (백엔드 서비스 없음)

# 2. 일반 뉴스 목록
curl -i http://localhost:8000/api/news/articles
# 기대: 200 OK 또는 404 Not Found (라우팅 문제)

# 3. 무료 뉴스 목록
curl -i http://localhost:8000/api/news/articles/free
# 기대: 200 OK 또는 502 Bad Gateway

# 4. 네임스페이스 매핑 확인
echo "외부 API: /api/news/articles/premium → 내부: /api/articles/premium"
```

**응답 코드 분석**:
- `200 OK`: 라우팅 성공 + 백엔드 서비스 정상
- `404 Not Found`: 라우팅 규칙 오류 또는 경로 불일치
- `502 Bad Gateway`: 라우팅 성공, 백엔드 서비스 없음 (정상)

### 4.2 보호 엔드포인트(프리미엄 상세) – 실패 케이스
```bash
# 토큰 없이 프리미엄 상세 접근
curl -i http://localhost:8000/api/news/articles/premium/1
# 기대: 401 Unauthorized (JWT 검증 실패)

# 네임스페이스 체크 - /api/news 경로로 접근
curl -i http://localhost:8000/api/news/articles/premium/123
```

### 4.3 보호 엔드포인트 – 성공 케이스(유료 권한 필요)
- 전제: `$TOKEN`에 `PAID_USER` 권한이 인코딩되어 있어야 한다.
```bash
# 유효한 토큰으로 프리미엄 상세 접근
TOKEN="your_valid_jwt_token_here"
curl -i http://localhost:8000/api/news/articles/premium/1 \
  -H "Authorization: Bearer $TOKEN"
# 기대: 200 OK, 프리미엄 기사 상세

# 다른 프리미엄 콘텐츠 테스트
curl -i http://localhost:8000/api/news/articles/premium/123 \
  -H "Authorization: Bearer $TOKEN"
```
> 참고: 게이트웨이의 `AuthorizationHeaderFilter`가 JWT를 검증하고 `X-User-Id`, `X-User-Roles`, `X-Token-Issuer` 헤더를 뉴스 서비스로 전달합니다.

---

## 5. 게이트웨이/백엔드 보안 검증

### 5.1 백엔드 직접 접근 차단 확인
```bash
curl -i http://localhost:8080/api/articles
# 기대: 403 Forbidden (X-Gateway-Internal 헤더 없음)
```

### 5.2 게이트웨이 헤더 시뮬레이션(로컬 개발 편의)
```bash
export GATEWAY_SECRET_TOKEN=${GATEWAY_SECRET_TOKEN:-civic-insights-gateway-v1}
curl -i http://localhost:8080/api/articles \
  -H "X-Gateway-Internal: ${GATEWAY_SECRET_TOKEN}"
# 기대: 200 OK (개발 편의용 시뮬)

# 보안 헤더와 사용자 정보 헤더 함께 테스트
curl -i http://localhost:8080/api/articles \
  -H "X-Gateway-Internal: ${GATEWAY_SECRET_TOKEN}" \
  -H "X-User-Id: test-user" \
  -H "X-User-Roles: PAID_USER"
```
> 운영에서는 반드시 게이트웨이 경유 호출만 허용한다.

---

## 6. 문제해결(FAQ)

### 6.1 라우팅 관련 문제
- **Q: 404 Not Found 에러가 발생합니다**
  - A: 라우팅 규칙 확인. `./scripts/gateway-routes-info.sh` 실행하여 라우팅 상태 확인
  - 또는 수동 확인: `curl "http://localhost:8000/actuator/metrics/spring.cloud.gateway.routes.count"`

- **Q: 502 Bad Gateway 에러가 나옵니다**
  - A: 라우팅은 성공, 백엔드 서비스 미실행. 대상 서뺄 기동 확인:
    - 인증 서비스: `curl http://localhost:8001/actuator/health`
    - 뉴스 서비스: `curl http://localhost:8080/actuator/health`

### 6.2 인증 관련 문제
- **Q: 401 Unauthorized 에러가 발생합니다**
  - A1: `Authorization: Bearer <token>` 헤더 형식 확인
  - A2: JWT 토큰 만료/서명/발급자 확인
  - A3: 게이트웨이 로그에서 JWT 검증 실패 원인 확인
  - A4: JWKS 엔드포인트 동작 확인: `curl http://localhost:8000/.well-known/jwks.json`

- **Q: `PAID_USER` 권한인데 403 에러가 나옵니다**
  - A: JWT 토큰의 `roles` 클레임이 `X-User-Roles` 헤더로 제대로 전달되는지 확인
  - 역할 문자열이 `PAID_USER` 또는 `ROLE_PAID_USER`인지 확인

### 6.3 보안 관련 문제
- **Q: 백엔드 직접 호출 시 403 Forbidden**
  - A: GatewayOnlyFilter 정상 동작. 반드시 게이트웨이 경유로 호출
  - 개발 테스트용: `X-Gateway-Internal` 헤더 추가

### 6.4 디버깅 도구
```bash
# 전체 라우팅 상태 확인
./scripts/gateway-routes-info.sh

# Gateway 메트릭 확인
curl "http://localhost:8000/actuator/metrics/spring.cloud.gateway.requests" | jq .

# 실시간 로그 모니터링
tail -f logs/spring.log | grep -E "(JWT|Gateway|Filter)"
```

---

## 7. 실습 완료 후 다음 단계

### 7.1 보안 강화 (선택사항)
- **mTLS 적용**: 서비스 간 상호 인증
- **Rate Limiting**: API 호출량 제한
- **Circuit Breaker**: 장애 전파 방지

### 7.2 모니터링 및 로깅
```bash
# Gateway 메트릭 모니터링
curl "http://localhost:8000/actuator/metrics/spring.cloud.gateway.requests" | jq .

# 실시간 요청 통계
watch -n 2 "curl -s 'http://localhost:8000/actuator/metrics/spring.cloud.gateway.requests' | jq -r '.measurements[] | select(.statistic == \"COUNT\") | \"Total Requests: \" + (.value | tostring)'"
```

### 7.3 보안 메모
- **현재 구현**: 개발/테스트용 간단한 JWT 검증
- **운영 권장사항**: 
  - BFF 패턴으로 세션 기반 인증
  - `X-Gateway-Internal` 헤더를 환경변수로 관리
  - Actuator 엔드포인트 접근 제한
  - HTTPS 강제 적용

---

## 8. 체크리스트

### 8.1 기본 설정 및 서비스 상태
- [ ] **서비스 기동**: 게이트웨이 8000, 인증 8001, 뉴스 8080
- [ ] **Gateway 상태 확인**: `curl http://localhost:8000/actuator/health`
- [ ] **라우팅 정보 확인**: `./scripts/gateway-routes-info.sh` 실행
- [ ] **등록된 라우트 개수**: 7개 라우트 확인

### 8.2 공개 엔드포인트 테스트 (인증 불필요)
- [ ] **JWKS 엔드포인트**: `/.well-known/jwks.json` → 200 OK
- [ ] **프리미엄 목록**: `/api/news/articles/premium` → 200 OK
- [ ] **일반 뉴스 목록**: `/api/news/articles` → 200 OK (or 404 if backend down)
- [ ] **인증 서비스**: `/api/auth/google` → 302 Redirect

### 8.3 보호 엔드포인트 테스트 (인증 필요)
- [ ] **미인증 접근**: `/api/news/articles/premium/1` → 401 Unauthorized
- [ ] **인증된 접근**: JWT 토큰으로 `/api/news/articles/premium/1` → 200 OK
- [ ] **프로필 접근**: JWT 토큰으로 `/api/auth/profile` → 200 OK

### 8.4 보안 검증
- [ ] **백엔드 직접 접근 차단**: `http://localhost:8080/api/articles` → 403 Forbidden
- [ ] **보안 헤더 전달**: `X-Gateway-Internal` 헤더 유무로 접근 제어
- [ ] **사용자 헤더 전달**: JWT 검증 성공 시 `X-User-Id`, `X-User-Roles`, `X-Token-Issuer` 전달

### 8.5 라우팅 매핑 검증
- [ ] **네임스페이스 매핑**: `/api/news/*` → `8080/api/articles/*`
- [ ] **버전 매핑**: `/api/auth/*` → `8001/api/v1/auth/*`
- [ ] **라우팅 우선순위**: order 1-7 순서대로 정상 작동

> **💡 빠른 테스트 방법**: `./scripts/gateway-routes-info.sh` 스크립트를 실행하면 위 대부분의 항목을 자동으로 확인할 수 있습니다.