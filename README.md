# Civic Insights API Gateway

> **마이크로서비스 아키텍처를 위한 Spring Cloud Gateway 기반 API 게이트웨이**

## 📚 목차

- [개요](#-개요)
- [아키텍처](#-아키텍처)
- [JWT와 JWK 이해하기](#-jwt와-jwk-이해하기)
- [라우팅 스펙](#-라우팅-스펙)
- [인증 메커니즘](#-인증-메커니즘)
- [설정 가이드](#-설정-가이드)
- [개발자 가이드](#-개발자-가이드)
- [트러블슈팅](#-트러블슈팅)

---

## 🌟 개요

Civic Insights API Gateway는 마이크로서비스 환경에서 단일 진입점(Single Entry Point) 역할을 수행하는 Spring Cloud Gateway 기반의 서비스입니다.

### 주요 기능 및 설계 원칙
- ✅ **네임스페이스 명시 라우팅**: 외부 API에 서비스별 네임스페이스 제공
- ✅ **버전리스 API 설계**: 백엔드 버전 정보를 내부에 숨김
- ✅ **스마트 라우팅**: 클라이언트 요청을 적절한 백엔드 서비스로 전달
- ✅ **JWT 인증**: 토큰 기반 사용자 인증 및 권한 관리
- ✅ **보안 필터링**: 공개/보호 엔드포인트 구분 관리
- ✅ **로드밸런싱**: 백엔드 서비스 간 트래픽 분산
- ✅ **모니터링**: 요청/응답 로깅 및 디버깅 지원

### **네임스페이스 명시 전략**

**외부 API (클라이언트용)** → **내부 API (백엔드)**
```
/api/news/articles/**      → /api/articles/**        (뉴스 서비스)
```

**장점**:
- 🎯 **압도적 명확성**: 서비스별 도메인 구분이 즉시 가능
- 🚀 **무한 확장성**: 새로운 서비스 추가 시 네임스페이스 충돌 없음
  ```
  향후 확장 가능한 네임스페이스 예시:
  /api/payment/**        # 결제 서비스
  /api/analytics/**      # 분석 서비스  
  /api/notification/**   # 알림 서비스
  ```
- 📚 **자체 문서화**: URL만 봐도 어떤 서비스인지 명확

### **버전리스 API 전략**

**외부 API (클라이언트용)** → **내부 API (백엔드)**
```
/api/auth/profile/**       → /api/v1/profile/**      (인증 서비스)
/api/auth/**               → /api/v1/auth/**         (인증 서비스)
```

**장점**:
- 🔧 **버전리스 설계**: 백엔드 버전 변경이 외부 API에 영향 없음

### 기술 스택
- **Spring Cloud Gateway** 2025.0.0
- **Spring Boot** 3.5.4
- **WebFlux** (비동기 리액티브 프로그래밍)
- **JWT** (JSON Web Tokens) - jjwt 0.12.6
- **JWK** (JSON Web Key) - nimbus-jose-jwt 10.4

---

## 🏗️ 아키텍처

```mermaid
graph TD
    subgraph SvcUser["서비스 유저"]
	    Client[🌐 클라이언트<br/>Frontend/Mobile]
    end

    subgraph APIGateway["API 게이트웨이 서버<br>(토큰 검증 및 라우팅)"]
        Gateway[API 통합 엔드포인트<br/>Port: 8000]
		    subgraph JWTFilter["JWT 필터 클래스"]
		        Filter[공개 키 활용 토큰 검사<br>및 유저 헤더로 변환]
		    end
		    subgraph APIRouter["API 라우터 클래스"]
		        Router[요청별 MSA 서비스 라우팅]
		    end		        
		end
		
    subgraph AuthSvc["Auth Service<br>(인증 수행 및 토큰 발급)"]
        Auth[인증 서비스<br/>Port: 8001]
        AuthDB[(사용자 DB)]
    end
    
    subgraph NewsSvc["News Service<br>(검증된 헤더 신뢰)"]
        News[뉴스 서비스<br/>Port: 8080]
        NewsDB[(뉴스 DB)]
    end
    
    Client -->|로그인 요청<br>-OAuth, ID/PW 등-| Gateway
    Client -->|뉴스 콘텐츠 요청<br>-JWT token 포함-| Gateway

    Gateway -->|/news/premium<br>JWT 포함 요청| Filter 
    --> Router -->|뉴스 요청<br>-인증된 헤더 전달-| News --> NewsDB

    Gateway -->|/auth/google<br>인증정보 포함 요청| Router
     -->|인증 요청<br>-인증 정보 전달-| Auth --> AuthDB

    Filter <-->|공개키 요청 및 제공| Auth

    style Client fill:#e1f5fe
    style Gateway fill:#fff3e0
    style Auth fill:#f3e5f5
    style News fill:#e8f5e8
    style AuthDB fill:#fff8e1
    style NewsDB fill:#fff8e1
```

### 서비스 구성
| 서비스 | 포트 | 역할 | 인증 여부 |
|--------|------|------|----------|
| **API Gateway** | 8000 | 요청 라우팅 및 인증 | - |
| **인증 서비스** | 8001 | JWT 발급, 사용자 관리 | 부분적 |
| **뉴스 서비스** | 8080 | 뉴스 콘텐츠 관리 | 부분적 |

---

## 🔐 JWT와 JWK 이해하기

### JWT (JSON Web Token)란?

JWT는 사용자 인증 정보를 JSON 형태로 안전하게 전송하기 위한 개방형 표준입니다.

#### JWT 구조
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature
│                                      │                                              │
├─ Header (헤더)                        ├─ Payload (내용)                              └─ Signature (서명)
```

#### 1. **Header (헤더)**
```json
{
  "alg": "RS256",    // 암호화 알고리즘
  "typ": "JWT",      // 토큰 타입
  "kid": "civic-insights-auth-key"  // 키 식별자
}
```

#### 2. **Payload (페이로드)**
```json
{
  "sub": "user123",           // 사용자 ID
  "iss": "civic-insights",    // 발급자
  "exp": 1640995200,          // 만료 시간
  "iat": 1640908800           // 발급 시간
}
```

#### 3. **Signature (서명)**
서명은 헤더와 페이로드를 합쳐서 **개인키(Private Key)**로 암호화한 값입니다.

### 공개키/개인키 암호화 이해하기

#### 🔑 **개인키 (Private Key)**
- **위치**: 인증 서비스 (Port 8001)에만 보관
- **용도**: JWT 토큰에 **서명**할 때 사용
- **특징**: 절대 외부에 노출되어서는 안 됨

#### 🔓 **공개키 (Public Key)**
- **위치**: API Gateway와 모든 서비스에서 접근 가능
- **용도**: JWT 토큰의 **서명을 검증**할 때 사용
- **특징**: 공개되어도 안전함

### JWK (JSON Web Key)란?
JWK는 공개키를 JSON 형태로 표현한 표준 형식입니다.

#### JWK 예시
```json
{
  "keys": [
    {
      "kty": "RSA",                           // 키 타입
      "kid": "civic-insights-auth-key",       // 키 식별자
      "use": "sig",                           // 키 사용 목적 (서명)
      "alg": "RS256",                         // 알고리즘
      "n": "0vx7agoebGcQSuuPiLJXZp...",      // RSA 공개키 modulus
      "e": "AQAB"                             // RSA 공개키 exponent
    }
  ]
}
```

#### JWK 접근 방법
```bash
# 공개키 조회
curl http://localhost:8001/.well-known/jwks.json
```

---

## 🚏 라우팅 스펙

### 라우팅 우선순위 및 규칙

API Gateway는 **우선순위(order)** 기반으로 요청을 매칭합니다.

| 순위 | 라우트 ID | 외부 API (네임스페이스 명시) | 내부 API (실제 라우팅) | JWT 검증 | 보안 헤더 | 설명 |
|------|-----------|---------------------------|-------------------------|----------|----------|------|
| 1 | `system-jwks` | `/.well-known/jwks.json` | `/.well-known/jwks.json` | ❌ | ✅ | 공개키 조회 |
| 2 | `news-premium-list` | `/api/news/articles/premium` | `/api/articles/premium` | ❌ | ✅ | 프리미엄 뉴스 목록 |
| 3 | `news-premium-detail` | `/api/news/articles/premium/**` | `/api/articles/premium/**` | ✅ | ✅ | 프리미엄 뉴스 상세 |
| 4 | `news-management` | `/api/news/articles/**` (POST/PUT/DELETE) | `/api/articles/**` | ✅ | ✅ | 뉴스 관리 |
| 5 | `news-articles` | `/api/news/articles/**` | `/api/articles/**` | ❌ | ✅ | 일반 뉴스 조회 |
| 6 | `auth-profile` | `/api/auth/profile/**` | `/api/v1/profile/**` | ✅ | ✅ | 프로필 관리 |
| 7 | `auth-login` | `/api/auth/**` | `/api/v1/auth/**` | ❌ | ✅ | 인증 서비스 |

### 📝 상세 라우팅 명세

> **🎯 네임스페이스 명시 설계**: 외부 API는 서비스별 네임스페이스를 명시하여 명확성을 제공하고, 내부적으로는 기존 백엔드 API 구조를 유지합니다.

#### ========== 시스템 도메인 ==========

#### 1. **JWK 공개키 엔드포인트**
```yaml
- id: system-jwks
  uri: http://localhost:8001
  predicates:
    - Path=/.well-known/jwks.json
  order: 1
```
- **외부 API**: `/.well-known/jwks.json`
- **내부 API**: `/.well-known/jwks.json` (변경 없음)
- **목적**: JWT 검증용 공개키 제공
- **인증**: 불필요 (공개 엔드포인트)
- **예시**: `GET http://localhost:8000/.well-known/jwks.json`

#### ========== 뉴스 도메인 (네임스페이스: /api/news/*) ==========

#### 2. **프리미엄 뉴스 목록 엔드포인트**
```yaml
- id: news-premium-list
  uri: http://localhost:8080
  predicates:
    - Path=/api/news/articles/premium
  filters:
    - RewritePath=/api/news/articles/premium, /api/articles/premium
    - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
  order: 2
```
- **외부 API**: `/api/news/articles/premium`
- **내부 API**: `/api/articles/premium`
- **목적**: 프리미엄 뉴스 목록 조회 (제목만)
- **인증**: 불필요 (목록은 누구나 볼 수 있음)
- **예시**: `GET http://localhost:8000/api/news/articles/premium`

#### 3. **프리미엄 뉴스 상세 엔드포인트**
```yaml
- id: news-premium-detail
  uri: http://localhost:8080
  predicates:
    - Path=/api/news/articles/premium/**
  filters:
    - RewritePath=/api/news/articles/premium/(?<segment>.*), /api/articles/premium/$\{segment}
    - name: AuthorizationHeaderFilter
    - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
  order: 3
```
- **외부 API**: `/api/news/articles/premium/**`
- **내부 API**: `/api/articles/premium/**`
- **목적**: 유료 구독자만 접근 가능한 프리미엄 콘텐츠 상세
- **인증**: 필수 (유료 구독 확인)
- **예시**: `GET http://localhost:8000/api/news/articles/premium/123`

#### 4. **뉴스 관리 엔드포인트**
```yaml
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
```
- **외부 API**: `/api/news/articles/**` (POST/PUT/DELETE)
- **내부 API**: `/api/articles/**`
- **목적**: 뉴스 콘텐츠 생성, 수정, 삭제
- **인증**: 필수 (관리자 권한 필요)
- **예시**:
  - `POST http://localhost:8000/api/news/articles`
  - `PUT http://localhost:8000/api/news/articles/123`
  - `DELETE http://localhost:8000/api/news/articles/123`

#### 5. **뉴스 조회 엔드포인트**
```yaml
- id: news-articles
  uri: http://localhost:8080
  predicates:
    - Path=/api/news/articles/**
  filters:
    - RewritePath=/api/news/articles/(?<segment>.*), /api/articles/$\{segment}
    - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
  order: 5
```
- **외부 API**: `/api/news/articles/**`
- **내부 API**: `/api/articles/**`
- **목적**: 뉴스 조회 (전체, 무료, 카테고리별, 개별, 헬스체크)
- **인증**: 불필요 (프리미엄 뉴스는 별도 라우트에서 처리)
- **예시**:
  - `GET http://localhost:8000/api/news/articles` → `/api/articles`
  - `GET http://localhost:8000/api/news/articles/premium` → `/api/articles/premium`
  - `GET http://localhost:8000/api/news/articles/free` → `/api/articles/free`
  - `GET http://localhost:8000/api/news/articles/category/tech` → `/api/articles/category/tech`
  - `GET http://localhost:8000/api/news/articles/123` → `/api/articles/123`
  - `GET http://localhost:8000/api/news/articles/health` → `/api/articles/health`

#### ========== 인증 도메인 (네임스페이스: /api/auth/*) ==========

#### 6. **사용자 프로필 서비스**
```yaml
- id: auth-profile
  uri: http://localhost:8001
  predicates:
    - Path=/api/auth/profile/**
  filters:
    - RewritePath=/api/auth/profile/(?<segment>.*), /api/v1/profile/$\{segment}
    - name: AuthorizationHeaderFilter
    - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
  order: 6
```
- **외부 API**: `/api/auth/profile/**`
- **내부 API**: `/api/v1/profile/**`
- **목적**: 인증된 사용자의 프로필 관리
- **인증**: 필수 (JWT 토큰 필요)
- **예시**: 
  - `GET http://localhost:8000/api/auth/profile`
  - `PUT http://localhost:8000/api/auth/profile`

#### 7. **인증 서비스**
```yaml
- id: auth-login
  uri: http://localhost:8001
  predicates:
    - Path=/api/auth/**
  filters:
    - RewritePath=/api/auth/(?<segment>.*), /api/v1/auth/$\{segment}
    - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
  order: 7
```
- **외부 API**: `/api/auth/**`
- **내부 API**: `/api/v1/auth/**`
- **목적**: 사용자 로그인, 회원가입, 토큰 발급
- **인증**: 불필요 (인증 과정 자체)
- **예시**:
  - `GET http://localhost:8000/api/auth/google`
  - `POST http://localhost:8000/api/auth/google/token`
  - `POST http://localhost:8000/api/auth/refresh`

---

## 🔒 인증 메커니즘

### JWT 검증 프로세스

1. 클라이언트 → API Gateway: Authorization: Bearer <JWT>
2. API Gateway: JWT 헤더에서 kid 추출
3. API Gateway → 인증 서비스: JWK 공개키 요청 (캐시 미스시)
4. 인증 서비스 → API Gateway: 공개키 반환
5. API Gateway: 공개키로 JWT 서명 검증

[JWT 검증 성공]
6. API Gateway: 사용자 ID를 X-User-Id 헤더에 추가
7. API Gateway → 백엔드 서비스: 요청 전달
8. 백엔드 서비스 → API Gateway: 응답
9. API Gateway → 클라이언트: 응답 전달

[JWT 검증 실패]
6. API Gateway → 클라이언트: 401 Unauthorized

```mermaid
sequenceDiagram
    participant Client as 📱 클라이언트
    participant Gateway as 🚪 API Gateway
    participant Auth as 🔐 인증 서비스
    participant Backend as 🏠 백엔드 서비스
    
    Client->>Gateway: 1. Authorization: Bearer <JWT>
    Gateway->>Gateway: 2. JWT 헤더에서 kid 추출
    
    alt 공개키 캐시 미스
        Gateway->>Auth: 3. JWK 공개키 요청
        Auth->>Gateway: 4. 공개키 반환
    end
    
    Gateway->>Gateway: 5. 공개키로 JWT 서명 검증
    
    alt JWT 검증 성공
        Gateway->>Gateway: 6. 사용자 ID를 X-User-Id 헤더에 추가
        Gateway->>Backend: 7. 요청 전달
        Backend->>Gateway: 8. 응답
        Gateway->>Client: 9. 응답 전달
        Note over Gateway,Client: ✅ 성공 (유효 토큰)
    else JWT 검증 실패
        Gateway->>Client: 6. 401 Unauthorized
        Note over Gateway,Client: ❌ 실패 (무효 토큰)
    end
```

### 인증 헤더 형식

#### 요청 헤더
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 백엔드 서비스로 전달되는 헤더
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
X-User-Id: user123
X-User-Roles: USER,ADMIN
X-Token-Issuer: civic-insights
X-Gateway-Internal: civic-insights-gateway-v1
```

> **보안 헤더**: 모든 요청에 `X-Gateway-Internal` 헤더가 자동 추가되어 백엔드 서비스에서 게이트웨이를 통한 요청임을 확인할 수 있습니다.

### 캐싱 메커니즘

```java
// AuthorizationHeaderFilter.java에서 구현된 공개키 캐싱
private final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
private final WebClient webClient = WebClient.create();

// JWKS URI에서 공개키를 가져와 캐시에 저장
private PublicKey getKey(String kid) {
    if (keyCache.containsKey(kid)) {
        return keyCache.get(kid); // 캐시된 키 반환
    }
    // JWKS 엔드포인트에서 새로 가져와서 캐시에 저장
    JWKSet jwkSet = fetchJwkSet();
    // ...
}
```

- **목적**: JWKS 엔드포인트 호출 횟수 최소화
- **전략**: kid(Key ID) 기반 캐싱
- **갱신**: 키를 찾을 수 없을 때 자동 갱신
- **구현 위치**: `AuthorizationHeaderFilter.java:37,148-176`

---

## ⚙️ 설정 가이드

### application.yaml 설정

```yaml
# API Gateway Configuration - 최신 Spring Cloud Gateway 2025.0.0 호환
server:
  port: 8000

spring:
  application:
    name: civic-insights-api-gw
  cloud:
    gateway:
      server:
        webflux:  # 새로운 Spring Cloud Gateway 설정 구조
          routes:
            # ========== 시스템 도메인 ==========
            - id: system-jwks
              uri: http://localhost:8001
              predicates:
                - Path=/.well-known/jwks.json
              filters:
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 1

            # ========== 뉴스 도메인 ==========
            - id: news-premium-detail
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/premium/**
              filters:
                - RewritePath=/api/news/articles/premium/(?<segment>.*), /api/articles/premium/$\{segment}
                - name: AuthorizationHeaderFilter
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 3
            
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
            
            - id: news-articles
              uri: http://localhost:8080
              predicates:
                - Path=/api/news/articles/**
              filters:
                - RewritePath=/api/news/articles/(?<segment>.*), /api/articles/$\{segment}
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 5

            # ========== 인증 도메인 ==========
            - id: auth-profile
              uri: http://localhost:8001
              predicates:
                - Path=/api/auth/profile/**
              filters:
                - RewritePath=/api/auth/profile/(?<segment>.*), /api/v1/profile/$\{segment}
                - name: AuthorizationHeaderFilter
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 6
            
            - id: auth-login
              uri: http://localhost:8001
              predicates:
                - Path=/api/auth/**
              filters:
                - RewritePath=/api/auth/(?<segment>.*), /api/v1/auth/$\{segment}
                - AddRequestHeader=X-Gateway-Internal, ${GATEWAY_SECRET_TOKEN:civic-insights-gateway-v1}
              order: 7

# JWT 설정 (JwtConfigProperties와 연동)
jwt:
  authService:  # 카멜케이스 변경 (기존: auth-service)
    jwksUri: http://localhost:8001/.well-known/jwks.json  # 카멜케이스 변경 (기존: jwks-uri)

# 로깅 설정
logging:
  level:
    "[com.makersworld.civic_insights_api_gw]": DEBUG
    "[org.springframework.cloud.gateway]": DEBUG
    "[org.springframework.web.reactive]": DEBUG
```

> **🚨 중요 변경사항**:
> - **Spring Cloud Gateway 2025.0.0**: `spring.cloud.gateway.routes` → `spring.cloud.gateway.server.webflux.routes`
> - **JWT 설정 구조**: `jwt.auth-service.jwks-uri` → `jwt.authService.jwksUri` (JwtConfigProperties 연동)
> - **보안 헤더**: 모든 라우트에 `X-Gateway-Internal` 헤더 자동 추가

### 환경별 설정

#### 개발 환경
```yaml
jwt:
  authService:
    jwksUri: http://localhost:8001/.well-known/jwks.json
```

#### 운영 환경
```yaml
jwt:
  authService:
    jwksUri: https://auth.civic-insights.com/.well-known/jwks.json
```

---

## 👨‍💻 개발자 가이드

### 프로젝트 실행

#### 1. 의존성 설치 및 빌드
```bash
./gradlew clean build
```

#### 2. 애플리케이션 실행
```bash
./gradlew bootRun
```

#### 3. 헬스체크
```bash
curl http://localhost:8000/actuator/health
```

### 개발 환경 설정

#### 필수 서비스 실행 순서
1. **인증 서비스** (Port 8001)
2. **뉴스 서비스** (Port 8080)
3. **API Gateway** (Port 8000)

#### 의존성
```gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway-server-webflux'
    implementation 'org.springframework.boot:spring-boot-starter-webflux'
    
    // JWT 검증용
    implementation 'io.jsonwebtoken:jjwt-api:0.12.6'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.6'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.6'
    implementation 'com.nimbusds:nimbus-jose-jwt:10.4'
    
    // JSON 처리를 위한 Jackson 의존성
    implementation 'com.fasterxml.jackson.core:jackson-core'
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    implementation 'net.minidev:json-smart:2.5.1'
    
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}
```

### 테스트 방법

#### 1. 공개 엔드포인트 테스트 (인증 불필요)
```bash
# 토큰 획득 (인증 서비스)
TOKEN=$(curl -s http://localhost:8000/api/auth/google/token \
  -d '{"code":"authorization_code"}' \
  -H "Content-Type: application/json" | jq -r '.accessToken')

# 뉴스 목록 조회
curl http://localhost:8000/api/news/articles

# 무료 뉴스 조회  
curl http://localhost:8000/api/news/articles/free

# 무료 뉴스 상세 조회
curl http://localhost:8000/api/news/articles/free/123

# 프리미엄 뉴스 목록 조회  
curl http://localhost:8000/api/news/articles/premium

# 카테고리별 뉴스 조회
curl http://localhost:8000/api/news/articles/category/basic-income
curl http://localhost:8000/api/news/articles/category/civic-engagement
curl http://localhost:8000/api/news/articles/category/megatrends

# 뉴스 서비스 헬스체크
curl http://localhost:8000/api/news/articles/health

# JWK 공개키 조회 (시스템)
curl http://localhost:8000/.well-known/jwks.json
```

#### 2. 인증 필요 엔드포인트 테스트
```bash

# 사용자 프로필 조회
curl http://localhost:8000/api/auth/profile \
  -H "Authorization: Bearer $TOKEN"

# 프리미엄 뉴스 상세 조회
curl http://localhost:8000/api/news/articles/premium/123

# 뉴스 생성 (관리자 권한 필요)
curl -X POST http://localhost:8000/api/news/articles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"New Article","content":"Article content","category":"tech"}'

# 뉴스 수정 (관리자 권한 필요)  
curl -X PUT http://localhost:8000/api/news/articles/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Updated Article","content":"Updated content"}'
```

#### 3. API 매핑 확인
```bash
# 외부 API → 내부 API 매핑 확인을 위한 로그 모니터링
tail -f logs/gateway.log | grep "Route matched"

# 또는 디버그 모드에서 확인
export LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_CLOUD_GATEWAY=DEBUG
./gradlew bootRun
```

### 커스텀 필터 개발

현재 구현된 **AuthorizationHeaderFilter**를 참고하여 새로운 필터를 추가할 수 있습니다:

```java
@Component
@Slf4j
public class CustomFilter extends AbstractGatewayFilterFactory<CustomFilter.Config> {
    
    public CustomFilter() {
        super(Config.class);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            // 필터 로직 구현
            return chain.filter(exchange);
        };
    }
    
    public static class Config {
        // 설정 프로퍼티 (AuthorizationHeaderFilter.Config 참고)
        private String realm = "civic-insights";
        private boolean includeErrorDetails = true;
        // getter/setter 메서드
    }
}
```

**참고**: `AuthorizationHeaderFilter.java`는 완전한 JWT 검증 필터 구현 예제를 제공합니다.

---

## 🔧 트러블슈팅

### 자주 발생하는 문제들

#### 1. **JWT 토큰 검증 오류**

**증상**: Authorization 헤더 관련 검증 실패
```
{"error":"invalid_request","error_description":"Invalid Authorization header format"}
```

**현재 구현된 검증 로직** (`AuthorizationHeaderFilter.java:50-70`):
```java
// 1. Authorization 헤더 존재 확인
if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
    return onError(exchange, "Missing Authorization header", 
                 HttpStatus.UNAUTHORIZED, "missing_token");
}

// 2. 안전한 헤더 접근
String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

// 3. Bearer 형식 검증
if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
    return onError(exchange, "Invalid Authorization header format", 
                 HttpStatus.UNAUTHORIZED, "invalid_request");
}
```

**해결방법**: 현재 구현은 이미 안전한 방식으로 되어 있으며, RFC 7235 표준을 준수하는 에러 응답을 제공합니다.

#### 2. **401 Unauthorized 에러**

**증상**: JWT 토큰이 있는데도 인증 실패
```json
{
  "error": "token_expired",
  "error_description": "Token has expired",
  "status": 401,
  "timestamp": "2024-01-01T12:00:00.000Z",
  "path": "API Gateway Authentication"
}
```

**현재 구현된 에러 분류** (`AuthorizationHeaderFilter.java:262-284`):
- `token_expired`: 토큰 만료
- `invalid_signature`: 서명 검증 실패
- `malformed_token`: 토큰 형식 오류
- `invalid_key`: 공개키 문제
- `invalid_issuer`: 발급자 불일치

**해결방법**:
```bash
# 1. JWKS 엔드포인트 확인
curl http://localhost:8001/.well-known/jwks.json

# 2. 새 토큰 발급
curl -X POST http://localhost:8000/api/auth/refresh

# 3. 토큰 디버깅 (jwt.io 사용)
echo $TOKEN | base64 -d
```

#### 2. **라우팅 실패 (404 Not Found)**

**증상**: API 호출이 라우팅되지 않음
```
{"timestamp":"2024-01-01T12:00:00.000Z","status":404,"error":"Not Found"}
```

**원인**:
- 잘못된 URL 패턴
- 라우트 순서 문제
- 백엔드 서비스 미실행

**해결방법**:
```bash
# 1. 라우팅 설정 확인
curl http://localhost:8000/actuator/gateway/routes

# 2. 백엔드 서비스 상태 확인
curl http://localhost:8001/actuator/health
curl http://localhost:8080/actuator/health

# 3. Gateway 로그 확인
tail -f logs/spring.log | grep "gateway"
```

#### 3. **Spring Cloud Gateway 설정 키 경고**

**증상**: 애플리케이션 시작 시 설정 키 변경 경고 발생
```
The use of configuration keys that have been renamed was found in the environment:
Key: spring.cloud.gateway.routes[0].id
Replacement: spring.cloud.gateway.server.webflux.routes[0].id
```

**원인**: 
- Spring Cloud Gateway 2025.0.0에서 설정 키 구조 변경

**해결방법**:
```yaml
# 기존 설정 (deprecated)
spring:
  cloud:
    gateway:
      routes:
        - id: example

# 새로운 설정 (권장)
spring:
  cloud:
    gateway:
      server:
        webflux:
          routes:
            - id: example
```

#### 4. **JWT 설정 프로퍼티 불일치**

**증상**: JWT 설정을 찾을 수 없다는 오류
```
Could not bind properties to 'JwtConfigProperties'
```

**원인**: 
- application.yaml의 JWT 설정과 JwtConfigProperties 클래스 구조 불일치

**해결방법**:
```yaml
# 올바른 설정 (JwtConfigProperties와 일치)
jwt:
  authService:         # 카멜케이스
    jwksUri: http://... # 카멜케이스
```

#### 5. **JWKS 연결 실패**

**증상**: 공개키를 가져올 수 없음
```
Failed to fetch JWKS from http://localhost:8001/.well-known/jwks.json
```

**해결방법**:
```bash
# 1. 인증 서비스 상태 확인
curl http://localhost:8001/.well-known/jwks.json

# 2. 네트워크 연결 확인
telnet localhost 8001

# 3. DNS 해석 확인
nslookup localhost
```

### 디버깅 팁

#### 로그 레벨 설정
```yaml
logging:
  level:
    com.makersworld.civic_insights_api_gw: DEBUG
    org.springframework.cloud.gateway.filter: TRACE
```

#### Gateway 정보 확인
```bash
# 현재 라우트 목록
curl http://localhost:8000/actuator/gateway/routes

# 필터 목록
curl http://localhost:8000/actuator/gateway/globalfilters
```

---

## 📊 모니터링

### 메트릭 확인

```bash
# Gateway 메트릭
curl http://localhost:8000/actuator/metrics

# 특정 라우트 메트릭
curl http://localhost:8000/actuator/metrics/spring.cloud.gateway.requests
```

### 로그 분석

```bash
# 실시간 로그 모니터링
tail -f logs/spring.log | grep -E "(JWT|Gateway|Filter)"

# 에러 로그만 필터링
tail -f logs/spring.log | grep ERROR
```

---

## 📚 참고 자료

### 공식 문서
- [Spring Cloud Gateway](https://spring.io/projects/spring-cloud-gateway)
- [JWT.io](https://jwt.io/) - JWT 디버깅 도구
- [RFC 7517 - JSON Web Key](https://tools.ietf.org/html/rfc7517)

### 관련 프로젝트
- [civic-insights-auth](../civic-insights-auth/README.md) - 인증 서비스
- [civic-sights-main](../civic-sights-main/README.md) - 뉴스 서비스

---

## 📝 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참조하세요.