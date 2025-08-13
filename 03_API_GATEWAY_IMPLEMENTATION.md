## MSA 시스템을 위한 API Gateway 구현

### 학습 목표
- Spring Cloud Gateway(Server WebFlux)로 API 게이트웨이를 구현
- 외부 API 네임스페이스와 내부 API 라우팅을 설계/설정
- JWT(JWS)와 JWK(JWKS)를 이해하고, 공개키 검증 기반의 인증 필터를 구현
- Gateway 보안 헤더(`X-Gateway-Internal`) 추가와 요청 리라이트(RewritePath)를 적용
- 최신 2025.0.0 버전대의 Spring Cloud Gateway 설정 스크립트 적용

### 사전 준비물
- JDK 17 이상
- Gradle 8.x (프로젝트에 Gradle Wrapper 포함)
- curl, jq(선택) 설치
- 터미널 환경(macOS, Linux, 또는 WSL 권장)

---

## 1. 프로젝트 개요와 아키텍처

API 게이트웨이는 클라이언트의 단일 진입점으로, 인증/인가와 라우팅을 담당합니다. 이 실습에서는 다음 두 서비스를 대상으로 라우팅합니다.
- 인증 서비스(Auth Service, 8001)
- 뉴스 서비스(News Service, 8080)

JWT는 인증 서비스가 개인키로 서명해서 발급하고, 게이트웨이는 인증 서비스의 공개키(JWKS)로 서명을 검증합니다.

아키텍처 개요(메인 README의 도식 참고):
- 클라이언트 → 게이트웨이 → (JWT 검증) → 각 백엔드 서비스로 라우팅
- 공개키는 게이트웨이가 인증 서비스의 `/.well-known/jwks.json`에서 가져와 캐싱

---

## 2. 프로젝트 구성과 의존성 설정

아래의 파일들을 그대로 생성/확인하세요.

### 2.1 Gradle 설정
```gradle:build.gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.5.4'
    id 'io.spring.dependency-management' version '1.1.7'
}

group = 'com.makersworld'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = '17'

repositories {
    mavenCentral()
}

// Spring Cloud 버전 관리를 위한 BOM
dependencyManagement {
    imports {
        mavenBom "org.springframework.cloud:spring-cloud-dependencies:2025.0.0" // Spring Boot 3.5.x 호환 버전
    }
}

dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway-server-webflux'
    implementation 'org.springframework.boot:spring-boot-starter-webflux'

    // JWT 검증용
    implementation 'io.jsonwebtoken:jjwt-api:0.12.6'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.6'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.6'
    implementation 'com.nimbusds:nimbus-jose-jwt:10.4'

    // JSON 처리를 위한 Jackson 의존성 추가
    implementation 'com.fasterxml.jackson.core:jackson-core'
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    
    // nimbusds가 사용하는 json-smart 의존성
    implementation 'net.minidev:json-smart:2.5.1'

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}

tasks.named('test') {
    useJUnitPlatform()
}
```

> 참고: 본 실습에서는 Spring Cloud Gateway의 설정 키가 2025.0.0 버전에서 `spring.cloud.gateway.server.webflux.*`로 변경되었음을 반영합니다.

---

## 3. 애플리케이션 시작 클래스

```java:src/main/java/com/makersworld/civic_insights_api_gw/CivicInsightsApiGwApplication.java
package com.makersworld.civic_insights_api_gw;

import com.makersworld.civic_insights_api_gw.config.JwtConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfigProperties.class)
public class CivicInsightsApiGwApplication {

    public static void main(String[] args) {
        SpringApplication.run(CivicInsightsApiGwApplication.class, args);
    }
}
```

---

## 4. 설정 바인딩: JWT 구성 프로퍼티

게이트웨이는 인증 서비스의 JWKS URI를 알기 위해 애플리케이션 설정을 바인딩합니다.

```java:src/main/java/com/makersworld/civic_insights_api_gw/config/JwtConfigProperties.java
package com.makersworld.civic_insights_api_gw.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT 관련 설정 프로퍼티
 * application.yaml의 jwt 설정을 바인딩합니다.
 */
@ConfigurationProperties(prefix = "jwt")
public class JwtConfigProperties {
    private AuthService authService = new AuthService();

    public AuthService getAuthService() {
        return authService;
    }

    public void setAuthService(AuthService authService) {
        this.authService = authService;
    }

    public static class AuthService {
        private String jwksUri;

        public String getJwksUri() {
            return jwksUri;
        }

        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }
    }
}
```

스프링 IDE 자동완성을 돕는 메타데이터(선택):
```json:src/main/resources/META-INF/additional-spring-configuration-metadata.json
{
  "properties": [
    {
      "name": "jwt.authService.jwksUri",
      "type": "java.lang.String",
      "description": "JWT 인증 서비스의 JWK(JSON Web Key) 공개키 조회 URI. JWT 토큰 검증을 위한 공개키를 가져오는 엔드포인트입니다.",
      "defaultValue": "http://localhost:8001/.well-known/jwks.json"
    }
  ]
}
```

---

## 5. JWT 인증 필터 구현(풀버전)

- 인증 헤더 검사 및 형식 검증
- JWT 서명 검증(JWKS 공개키 사용)
- 검증 성공 시 `X-User-Id`, `X-User-Roles`, `X-Token-Issuer` 헤더 추가
- RFC 7235 준수 에러 응답 제공(`WWW-Authenticate`)

```java:src/main/java/com/makersworld/civic_insights_api_gw/gateway/filter/AuthorizationHeaderFilter.java
package com.makersworld.civic_insights_api_gw.gateway.filter;

import com.makersworld.civic_insights_api_gw.config.JwtConfigProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtConfigProperties jwtConfigProperties;

    // JWKS를 캐싱하여 매번 요청하지 않도록 합니다.
    private final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final WebClient webClient = WebClient.create();

    public AuthorizationHeaderFilter(JwtConfigProperties jwtConfigProperties) {
        super(Config.class);
        this.jwtConfigProperties = jwtConfigProperties;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Authorization 헤더 존재 확인
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Missing Authorization header",
                             HttpStatus.UNAUTHORIZED, "missing_token");
            }

            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            
            // 2. Authorization 헤더 형식 검증
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization header format. Expected: Bearer <token>",
                             HttpStatus.UNAUTHORIZED, "invalid_request");
            }

            String jwt = authorizationHeader.substring(7); // "Bearer " 제거

            // 3. JWT 토큰 기본 형식 검증
            if (jwt.trim().isEmpty()) {
                return onError(exchange, "Empty JWT token",
                             HttpStatus.UNAUTHORIZED, "invalid_token");
            }

            try {
                // 4. JWT 검증 및 클레임 추출
                Claims claims = validateJwtAndGetClaims(jwt);
                String userId = claims.getSubject();

                // 5. 필수 클레임 검증
                if (userId == null || userId.trim().isEmpty()) {
                    return onError(exchange, "Invalid token: missing or empty subject claim",
                                 HttpStatus.UNAUTHORIZED, "invalid_token");
                }

                // 6. 토큰 만료 검증 (추가 안전장치)
                if (claims.getExpiration() != null && claims.getExpiration().before(new Date())) {
                    return onError(exchange, "Token has expired",
                                 HttpStatus.UNAUTHORIZED, "token_expired");
                }

                // 7. 사용자 정보를 헤더에 추가하여 백엔드로 전달
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Roles", extractRoles(claims))
                        .header("X-Token-Issuer", claims.getIssuer() != null ? claims.getIssuer() : "civic-insights")
                        .build();

                log.debug("JWT validation successful for user: {}", userId);
                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (JwtException e) {
                String errorType = determineJwtErrorType(e);
                return onError(exchange, "JWT validation failed: " + e.getMessage(),
                             HttpStatus.UNAUTHORIZED, errorType);
            } catch (Exception e) {
                log.error("Unexpected error during JWT validation", e);
                return onError(exchange, "Internal authentication error",
                             HttpStatus.INTERNAL_SERVER_ERROR, "server_error");
            }
        };
    }

    /**
     * JWT를 검증하고 클레임을 추출합니다.
     * jjwt 0.12.6의 최신 API를 사용하여 보안적으로 안전하게 구현합니다.
     */
    private Claims validateJwtAndGetClaims(String jwt) {
        try {
            // JWT를 base64 디코딩하여 헤더에서 kid를 추출
            String[] chunks = jwt.split("\\.");
            if (chunks.length != 3) {
                throw new JwtException("Invalid JWT format");
            }
            String header = new String(java.util.Base64.getUrlDecoder().decode(chunks[0]));
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode headerNode = mapper.readTree(header);
            String kid = headerNode.get("kid") != null ? headerNode.get("kid").asText() : "civic-insights-auth-key";
            
            log.debug("Extracted kid from JWT: {}", kid);

            // kid에 해당하는 공개키를 가져옵니다
            PublicKey key = getKey(kid);

            // JWT를 검증하고 클레임을 추출합니다
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(jwt)
                    .getPayload();
            
        } catch (Exception e) {
            log.error("Failed to validate JWT: {}", e.getMessage());
            throw new JwtException("JWT validation failed", e);
        }
    }

    // JWKS URI에서 공개키를 가져와 캐시에 저장하거나, 캐시에서 바로 반환합니다.
    private PublicKey getKey(String kid) {
        if (keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }
        JWKSet jwkSet = fetchJwkSet();
        JWK jwk = jwkSet.getKeyByKeyId(kid);

        if (jwk == null) {
            log.warn("Key with kid '{}' not found in JWKS, attempting to refresh.", kid);
            jwkSet = fetchJwkSet();
            jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null) {
                throw new JwtException("Cannot find matching key with kid '" + kid + "' in JWKS");
            }
        }

        try {
            PublicKey key = jwk.toRSAKey().toPublicKey();
            keyCache.put(kid, key);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert JWK to PublicKey", e);
        }
    }

    private JWKSet fetchJwkSet() {
        String jwksUri = jwtConfigProperties.getAuthService().getJwksUri();
        log.info("Fetching JWKS from {}", jwksUri);
        String jwksJson = webClient.get()
                .uri(jwksUri)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        try {
            return JWKSet.parse(jwksJson);
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse JWKS", e);
        }
    }

    // ---------- 에러 핸들링 및 유틸리티 ----------
    private Mono<Void> onError(ServerWebExchange exchange, String message,
                               HttpStatus status, String errorCode) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);

        if (status == HttpStatus.UNAUTHORIZED) {
            response.getHeaders().add("WWW-Authenticate",
                String.format("Bearer realm=\"civic-insights\", error=\"%s\", error_description=\"%s\"",
                             errorCode, sanitizeErrorMessage(message)));
        }
        response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        response.getHeaders().add("Access-Control-Allow-Origin", "*");

        String errorResponse = createErrorResponse(errorCode, message, status);
        DataBuffer buffer = response.bufferFactory().wrap(errorResponse.getBytes(StandardCharsets.UTF_8));

        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            log.error("Authentication system error: {} - {}", errorCode, message);
        } else {
            log.warn("Authentication failed: {} - {}", errorCode, message);
        }
        return response.writeWith(Mono.just(buffer));
    }

    private String createErrorResponse(String errorCode, String message, HttpStatus status) {
        String sanitizedMessage = sanitizeErrorMessage(message);
        return String.format(
            "{\"error\":\"%s\",\"error_description\":\"%s\",\"status\":%d,\"timestamp\":\"%s\",\"path\":\"%s\"}",
            errorCode,
            sanitizedMessage,
            status.value(),
            Instant.now().toString(),
            "API Gateway Authentication"
        );
    }

    private String sanitizeErrorMessage(String message) {
        if (message == null) return "Authentication failed";
        return message
            .replaceAll("\\b[A-Za-z0-9+/]{20,}={0,2}\\b", "[REDACTED]")
            .replaceAll("\\\"[^\\\"]{10,}\\\"", "\"[REDACTED]\"")
            .substring(0, Math.min(message.length(), 200));
    }

    private String determineJwtErrorType(JwtException e) {
        String message = e.getMessage().toLowerCase();
        if (message.contains("expired")) return "token_expired";
        if (message.contains("signature") || message.contains("verification")) return "invalid_signature";
        if (message.contains("malformed") || message.contains("invalid") || message.contains("format")) return "malformed_token";
        if (message.contains("algorithm") || message.contains("alg")) return "unsupported_algorithm";
        if (message.contains("key") || message.contains("kid")) return "invalid_key";
        if (message.contains("issuer") || message.contains("iss")) return "invalid_issuer";
        if (message.contains("audience") || message.contains("aud")) return "invalid_audience";
        if (message.contains("claims")) return "invalid_claims";
        return "invalid_token";
    }

    private String extractRoles(Claims claims) {
        try {
            Object roles = claims.get("roles");
            if (roles instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> roleList = (List<String>) roles;
                return String.join(",", roleList);
            } else if (roles instanceof String) {
                return (String) roles;
            } else {
                return "USER";
            }
        } catch (Exception e) {
            log.debug("Could not extract roles from JWT claims: {}", e.getMessage());
            return "USER";
        }
    }

    public static class Config {
        private String realm = "civic-insights";
        private boolean includeErrorDetails = true;
        private int maxErrorMessageLength = 200;
        public String getRealm() { return realm; }
        public void setRealm(String realm) { this.realm = realm; }
        public boolean isIncludeErrorDetails() { return includeErrorDetails; }
        public void setIncludeErrorDetails(boolean includeErrorDetails) { this.includeErrorDetails = includeErrorDetails; }
        public int getMaxErrorMessageLength() { return maxErrorMessageLength; }
        public void setMaxErrorMessageLength(int maxErrorMessageLength) { this.maxErrorMessageLength = maxErrorMessageLength; }
    }
}
```

> 중요: `HttpHeaders.getFirst()`로 Authorization 헤더를 안전하게 읽어 NPE를 방지합니다.

---

## 6. 라우팅 및 애플리케이션 설정

Spring Cloud Gateway 2025.0.0 설정 키 변경 사항을 반영했습니다.

```yaml:src/main/resources/application.yaml
# API Gateway Configuration - 실습용
server:
  port: 8000

spring:
  application:
    name: civic-insights-api-gw
  cloud:
    gateway:
      server:
        webflux:
          routes:
            # ========== 시스템 도메인 (버전리스) ==========
            # 1. JWK 공개키 엔드포인트 (JWT 검증 불필요, 최우선 순위)
            - id: system-jwks
              uri: http://localhost:8001
              predicates:
                - Path=/.well-known/jwks.json
              filters:
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 1

            # ========== 뉴스 도메인 (네임스페이스 명시: /api/news/*) ==========
            # 2. 뉴스 서비스 - 프리미엄 콘텐츠 리스트 조회 (JWT 검증 불필요)
            - id: news-premium-list
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/premium
              filters:
                - RewritePath=/api/news/articles/premium, /api/articles/premium
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 2

            # 3. 뉴스 서비스 - 프리미엄 콘텐츠 상세 조회 (JWT 검증 필요)
            - id: news-premium-detail
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/premium/**
              filters:
                - RewritePath=/api/news/articles/premium/(?<segment>.*), /api/articles/premium/$\{segment}
                - name: AuthorizationHeaderFilter
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 3
            
            # 4. 뉴스 서비스 - 관리 작업 (JWT 검증 필요)
            - id: news-management
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/**
                - Method=POST,PUT,DELETE
              filters:
                - RewritePath=/api/news/articles/(?<segment>.*), /api/articles/$\{segment}
                - name: AuthorizationHeaderFilter
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 4
            
            # 5. 뉴스 서비스 - 일반 조회 (JWT 검증 불필요)
            - id: news-articles
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/**
              filters:
                - RewritePath=/api/news/articles/(?<segment>.*), /api/articles/$\{segment}
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 5

            # ========== 인증 도메인 (네임스페이스 명시 및 버전 제거: /api/auth/*) ==========
            # 6. 인증 서비스 - 사용자 프로필 (JWT 검증 필요)
            - id: auth-profile
              uri: http://localhost:8001
              predicates:
                - Path=/api/auth/profile/**
              filters:
                - RewritePath=/api/auth/profile/(?<segment>.*), /api/v1/profile/$\{segment}
                - name: AuthorizationHeaderFilter
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 6
            
            # 7. 인증 서비스 - 로그인/회원가입 (JWT 검증 불필요)
            - id: auth-login
              uri: http://localhost:8001
              predicates:
                - Path=/api/auth/**
              filters:
                - RewritePath=/api/auth/(?<segment>.*), /api/v1/auth/$\{segment}
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 7

# JWT 설정
jwt:
  authService:
    jwksUri: http://localhost:8001/.well-known/jwks.json

# 로깅 설정
logging:
  level:
    "[com.makersworld.civic_insights_api_gw]": DEBUG
    "[org.springframework.cloud.gateway]": DEBUG
    "[org.springframework.web.reactive]": DEBUG
```

> 핵심: 설정 키 루트가 `spring.cloud.gateway.server.webflux.routes` 입니다.

---

## 7. 실행 및 테스트

### 7.1 빌드/실행
```bash
./gradlew clean build
./gradlew bootRun
```

### 7.2 사전 준비(백엔드)
- 인증 서비스(8001): `/.well-known/jwks.json` 엔드포인트 제공
- 뉴스 서비스(8080): `/api/articles/**` 엔드포인트 제공

참고: 인증/뉴스 서비스가 준비되지 않아도 다음 공개 엔드포인트는 테스트 가능합니다.
- `GET http://localhost:8000/.well-known/jwks.json` (백엔드가 있어야 200)
- `GET http://localhost:8000/api/news/articles` (뉴스 서비스 필요)

### 7.3 JWT 필요한 엔드포인트 테스트
토큰이 있을 때:
```bash
# 예: 프리미엄 상세(토큰 필요)
TOKEN="your_jwt_token_here"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/news/articles/premium/123 -i
```

### 7.4 인증 불필요 엔드포인트 테스트
```bash
curl http://localhost:8000/api/news/articles -i
curl http://localhost:8000/api/news/articles/premium -i
```

---

## 8. 트러블슈팅 하이라이트
- Authorization 헤더 NPE: `get(0)` 대신 `getFirst()` 사용
- 설정 키 경고: `server.webflux.routes` 구조로 마이그레이션
- 프로퍼티 바인딩 오류: `jwt.authService.jwksUri` 카멜케이스 확인
- JWKS 파싱/네트워크 오류: 인증 서비스 구동 여부와 URL 확인

자세한 내용은 프로젝트 `README.md`의 트러블슈팅 섹션을 참조하세요.

### 8.1 라우팅 확인
게이트웨이가 실행 중일 때 다음 명령어로 라우팅 상태를 확인할 수 있습니다:
```bash
# 게이트웨이 헬스체크
curl http://localhost:8000/actuator/health

# 등록된 라우트 목록 확인
curl http://localhost:8000/actuator/gateway/routes | jq .

# 글로벌 필터 목록 확인
curl http://localhost:8000/actuator/gateway/globalfilters | jq .
```

---

## 9. 보안 확장 실습 로드맵(선택)
`GATEWAY_SECURITY.md`에 상세 가이드가 포함되어 있습니다. 추천 순서:
1) 게이트웨이→백엔드 HMAC 서명
2) Service JWT 발급/검증
3) mTLS 적용

학습 포인트:
- 환경변수 비밀관리, 리플레이 공격 방지(타임스탬프), 서비스 간 상호 인증

---

## 10. 전체 소스 코드 목록(요약)
- `build.gradle`
- `src/main/java/com/makersworld/civic_insights_api_gw/CivicInsightsApiGwApplication.java`
- `src/main/java/com/makersworld/civic_insights_api_gw/config/JwtConfigProperties.java`
- `src/main/java/com/makersworld/civic_insights_api_gw/gateway/filter/AuthorizationHeaderFilter.java`
- `src/main/resources/application.yaml`
- `src/main/resources/META-INF/additional-spring-configuration-metadata.json`

본 교안의 코드 블록은 모두 실제 파일과 동일합니다. 그대로 복사/붙여넣기 하여 완전한 구현을 진행할 수 있습니다.

---

## 부록 C. End-to-End 테스트 가이드(요약)
초심자용 전체 테스트 흐름은 `04_API_GW_BASED_AUTH_AND_NEWS_SVC_FLOW_TEST.md`를 참고하세요. 요약:
- 공개 목록: `GET http://localhost:8000/api/news/articles/premium` → 200
- 보호 상세(미인증): `GET http://localhost:8000/api/news/articles/premium/1` → 401
- 보호 상세(인증+PAID_USER): `GET ... -H "Authorization: Bearer $TOKEN"` → 200
- 백엔드 직접 호출: `GET http://localhost:8080/api/articles` → 403 (GatewayOnlyFilter)

## 부록 A. 유용한 확인 명령어
```bash
# 라우트 목록
curl http://localhost:8000/actuator/gateway/routes | jq .

# 글로벌/로컬 필터 목록
curl http://localhost:8000/actuator/gateway/globalfilters | jq .

# 메트릭 확인
curl http://localhost:8000/actuator/metrics | jq .
```

## 부록 B. 학습 체크리스트
- [ ] Gateway가 8000 포트에서 실행되는가?
- [ ] 공개 엔드포인트(프리미엄 목록, 뉴스 조회)가 정상 동작하는가?
- [ ] JWT가 필요한 엔드포인트는 토큰 없이는 401을 응답하는가?
- [ ] `X-Gateway-Internal` 헤더가 백엔드로 전달되는가?
- [ ] 설정 키 경고가 사라졌는가?

행운을 빕니다! 🚀