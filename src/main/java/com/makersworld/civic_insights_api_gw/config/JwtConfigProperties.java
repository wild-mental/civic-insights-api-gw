package com.makersworld.civic_insights_api_gw.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT 관련 설정 프로퍼티
 * application.yaml의 jwt 설정을 바인딩하여 린터 경고를 해결합니다.
 */
@ConfigurationProperties(prefix = "jwt")
public class JwtConfigProperties {
    
    /**
     * 인증 서비스 관련 설정
     */
    private AuthService authService = new AuthService();
    
    public AuthService getAuthService() {
        return authService;
    }
    
    public void setAuthService(AuthService authService) {
        this.authService = authService;
    }
    
    /**
     * 인증 서비스 설정 클래스
     */
    public static class AuthService {
        /**
         * JWK 공개키 조회 URI
         */
        private String jwksUri;
        
        public String getJwksUri() {
            return jwksUri;
        }
        
        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }
    }
}