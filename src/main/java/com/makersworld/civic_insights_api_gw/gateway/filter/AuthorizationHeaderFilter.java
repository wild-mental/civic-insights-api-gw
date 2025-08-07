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
            
            // 헤더 디코딩 후 kid 추출
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
        // 캐시된 키가 있으면 바로 반환
        if (keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        // 캐시에 없으면 JWKS 엔드포인트에서 가져옴
        JWKSet jwkSet = fetchJwkSet();
        JWK jwk = jwkSet.getKeyByKeyId(kid);

        if (jwk == null) {
            // JWKS에 해당 kid가 없는 경우, 캐시를 갱신하고 다시 시도
            log.warn("Key with kid '{}' not found in JWKS, attempting to refresh.", kid);
            jwkSet = fetchJwkSet(); // 강제로 JWKS 다시 로드
            jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null) {
                throw new JwtException("Cannot find matching key with kid '" + kid + "' in JWKS");
            }
        }

        try {
            // JWK를 Java의 PublicKey 객체로 변환
            PublicKey key = jwk.toRSAKey().toPublicKey();
            keyCache.put(kid, key); // 변환된 키를 캐시에 저장
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert JWK to PublicKey", e);
        }
    }

    // WebClient를 이용해 비동기적으로 JWKS를 가져옵니다.
    private JWKSet fetchJwkSet() {
        String jwksUri = jwtConfigProperties.getAuthService().getJwksUri();
        log.info("Fetching JWKS from {}", jwksUri);
        String jwksJson = webClient.get()
                .uri(jwksUri)
                .retrieve()
                .bodyToMono(String.class)
                .block(); // 실제 운영 코드에서는 block() 사용을 지양하고 비동기 체인을 유지해야 합니다.
        try {
            return JWKSet.parse(jwksJson);
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse JWKS", e);
        }
    }

    /**
     * RFC 7235 표준을 준수하여 인증 오류 응답을 생성합니다.
     * 401 Unauthorized 시 WWW-Authenticate 헤더를 포함하고, 
     * 구조화된 JSON 응답을 제공합니다.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, 
                              HttpStatus status, String errorCode) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        
        // RFC 7235 준수: 401 응답 시 WWW-Authenticate 헤더 필수
        if (status == HttpStatus.UNAUTHORIZED) {
            response.getHeaders().add("WWW-Authenticate", 
                String.format("Bearer realm=\"civic-insights\", error=\"%s\", error_description=\"%s\"",
                             errorCode, sanitizeErrorMessage(message)));
        }
        
        // Content-Type 설정
        response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        
        // CORS 헤더 추가 (필요시)
        response.getHeaders().add("Access-Control-Allow-Origin", "*");
        
        // 구조화된 JSON 에러 응답 생성
        String errorResponse = createErrorResponse(errorCode, message, status);
        DataBuffer buffer = response.bufferFactory().wrap(errorResponse.getBytes(StandardCharsets.UTF_8));
        
        // 로그 레벨에 따른 구분 로깅
        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            log.error("Authentication system error: {} - {}", errorCode, message);
        } else {
            log.warn("Authentication failed: {} - {}", errorCode, message);
        }
        
        return response.writeWith(Mono.just(buffer));
    }

    /**
     * 구조화된 JSON 에러 응답을 생성합니다.
     */
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

    /**
     * 보안을 위해 에러 메시지에서 민감한 정보를 제거합니다.
     */
    private String sanitizeErrorMessage(String message) {
        if (message == null) return "Authentication failed";
        
        // 민감한 정보가 포함될 수 있는 패턴 제거
        return message
            .replaceAll("\\b[A-Za-z0-9+/]{20,}={0,2}\\b", "[REDACTED]") // Base64 패턴
            .replaceAll("\\\"[^\\\"]{10,}\\\"", "\"[REDACTED]\"")        // 긴 문자열
            .substring(0, Math.min(message.length(), 200));               // 길이 제한
    }

    /**
     * JWT 에러 유형을 세분화하여 적절한 에러 코드를 반환합니다.
     */
    private String determineJwtErrorType(JwtException e) {
        String message = e.getMessage().toLowerCase();
        
        if (message.contains("expired")) {
            return "token_expired";
        } else if (message.contains("signature") || message.contains("verification")) {
            return "invalid_signature";
        } else if (message.contains("malformed") || message.contains("invalid") || message.contains("format")) {
            return "malformed_token";
        } else if (message.contains("algorithm") || message.contains("alg")) {
            return "unsupported_algorithm";
        } else if (message.contains("key") || message.contains("kid")) {
            return "invalid_key";
        } else if (message.contains("issuer") || message.contains("iss")) {
            return "invalid_issuer";
        } else if (message.contains("audience") || message.contains("aud")) {
            return "invalid_audience";
        } else if (message.contains("claims")) {
            return "invalid_claims";
        }
        
        return "invalid_token";
    }

    /**
     * JWT 클레임에서 사용자 역할을 추출합니다.
     * 백엔드 서비스에서 권한 확인에 사용할 수 있습니다.
     */
    private String extractRoles(Claims claims) {
        try {
            // 'roles' 클레임에서 역할 정보 추출
            Object roles = claims.get("roles");
            
            if (roles instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> roleList = (List<String>) roles;
                return String.join(",", roleList);
            } else if (roles instanceof String) {
                return (String) roles;
            } else {
                // 기본 역할 설정
                return "USER";
            }
        } catch (Exception e) {
            log.debug("Could not extract roles from JWT claims: {}", e.getMessage());
            return "USER"; // 기본값
        }
    }

    public static class Config {
        // 필요시 JWT 검증 관련 설정을 추가할 수 있습니다.
        // 예: realm, custom error messages, timeout 등
        private String realm = "civic-insights";
        private boolean includeErrorDetails = true;
        private int maxErrorMessageLength = 200;

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public boolean isIncludeErrorDetails() {
            return includeErrorDetails;
        }

        public void setIncludeErrorDetails(boolean includeErrorDetails) {
            this.includeErrorDetails = includeErrorDetails;
        }

        public int getMaxErrorMessageLength() {
            return maxErrorMessageLength;
        }

        public void setMaxErrorMessageLength(int maxErrorMessageLength) {
            this.maxErrorMessageLength = maxErrorMessageLength;
        }
    }
}
