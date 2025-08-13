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

## 2. 게이트웨이 라우팅 한눈에 보기(요약)
- 뉴스 네임스페이스: 외부 `/api/news/**` → 내부 뉴스 `/api/articles/**`
- 인증 네임스페이스: 외부 `/api/auth/**` → 내부 인증 `/api/v1/auth/**`
- 보호 정책:
  - 게이트웨이는 JWT 검증 시 `X-User-Id`, `X-User-Roles`, `X-Token-Issuer`를 백엔드에 전달
  - 백엔드는 `X-Gateway-Internal` 헤더 없으면 403 (GatewayOnlyFilter)
  - 뉴스 프리미엄 상세는 컨트롤러에서 `X-User-Roles`에 `PAID_USER` 필요

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
# 프리미엄 뉴스 목록 (인증 불필요)
curl -i http://localhost:8000/api/news/articles/premium

# 일반 뉴스 목록
curl -i http://localhost:8000/api/news/articles

# 무료 뉴스 목록
curl -i http://localhost:8000/api/news/articles/free
```
- 모두 200 OK 뉴스 목록 응답 기대

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
- Q: 보호 엔드포인트가 401을 반환합니다
  - A: `Authorization: Bearer` 헤더 확인, 토큰 만료/서명/발급자 확인. 게이트웨이 로그에서 JWT 검증 실패 원인 확인.
- Q: 403 Forbidden이 나옵니다(백엔드 직접 호출 시)
  - A: GatewayOnlyFilter 동작 정상. 게이트웨이 경유로 호출하세요.
- Q: `PAID_USER`인데 403이 납니다
  - A: 토큰의 역할 클레임이 게이트웨이 `X-User-Roles`로 제대로 전달되는지 확인. 역할 문자열이 `PAID_USER` 혹은 `ROLE_PAID_USER`인지 확인.
- Q: 게이트웨이에서 JWT 파싱 오류가 발생합니다
  - A: 인증 서비스(8001)의 `/.well-known/jwks.json` 엔드포인트가 정상 동작하는지 확인. `curl http://localhost:8001/.well-known/jwks.json`

---

## 7. 보안 메모(요약)
- 현재 데모: Auth 콜백은 브라우저 자동 제출 폼으로 토큰을 프런트 `/api/session`에 POST(초보자 검증 용이). 운영은 BFF 완전형(세션 코드) 권장.
- 게이트웨이: JWT 검증(`AuthorizationHeaderFilter`) + `X-Gateway-Internal` 부여, 백엔드 직접 접근 차단.
- 뉴스: Spring Security는 permitAll, 컨트롤러에서 `X-User-Roles`로 `PAID_USER` 권한 검사.

---

## 8. 체크리스트
- [ ] 게이트웨이 8000, 인증 8001, 뉴스 8080 기동
- [ ] 게이트웨이 라우팅 확인: `curl http://localhost:8000/actuator/gateway/routes`
- [ ] 공개 엔드포인트(목록) 200: `/api/news/articles`, `/api/news/articles/premium`
- [ ] 보호 엔드포인트(미인증) 401: `/api/news/articles/premium/1`
- [ ] 보호 엔드포인트(인증 + PAID_USER) 200: 유효한 JWT로 접근
- [ ] 백엔드 직접 호출 403: `http://localhost:8080/api/articles`
- [ ] JWT 검증 시 사용자 헤더 전달: `X-User-Id`, `X-User-Roles`, `X-Token-Issuer`