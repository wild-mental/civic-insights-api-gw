#!/bin/bash

# Spring Cloud Gateway 라우팅 정보 조회 스크립트
# Spring Cloud Gateway 2025.0.0에서 actuator/gateway 엔드포인트가 비활성화된 경우의 대안

GATEWAY_URL="http://localhost:8000"
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Civic Insights API Gateway 라우팅 정보 ===${NC}"
echo ""

# 1. Gateway 상태 확인
echo -e "${GREEN}1. Gateway 상태:${NC}"
curl -s "${GATEWAY_URL}/actuator/health" | jq -r '.status'
echo ""

# 2. 총 라우트 개수
echo -e "${GREEN}2. 등록된 라우트 개수:${NC}"
ROUTE_COUNT=$(curl -s "${GATEWAY_URL}/actuator/metrics/spring.cloud.gateway.routes.count" | jq -r '.measurements[0].value')
echo "총 ${ROUTE_COUNT}개의 라우트가 등록되어 있습니다."
echo ""

# 3. 라우트 ID 목록과 대상 URI
echo -e "${GREEN}3. 라우트 ID와 대상 서비스:${NC}"
curl -s "${GATEWAY_URL}/actuator/metrics/spring.cloud.gateway.requests" | jq -r '.availableTags[] | select(.tag == "routeId") | .values[]' | while read route_id; do
    echo "  - Route ID: ${route_id}"
done
echo ""

echo -e "${GREEN}4. 대상 서비스 URI:${NC}"
curl -s "${GATEWAY_URL}/actuator/metrics/spring.cloud.gateway.requests" | jq -r '.availableTags[] | select(.tag == "routeUri") | .values[]' | while read route_uri; do
    echo "  - Target: ${route_uri}"
done
echo ""

# 4. 실제 라우팅 테스트로 매핑 확인
echo -e "${GREEN}5. 실제 라우팅 매핑 테스트:${NC}"
echo -e "${YELLOW}(백엔드 서비스가 실행 중이지 않으면 502/404 에러가 정상입니다)${NC}"
echo ""

routes=(
    "시스템-JWKS:/.well-known/jwks.json"
    "뉴스-일반목록(404):/api/news/articles"
    "뉴스-무료뉴스목록:/api/news/articles/free"
    "뉴스-무료뉴스상세:/api/news/articles/free/1"
    "뉴스-프리미엄목록:/api/news/articles/premium"
    "뉴스-프리미엄상세:/api/news/articles/premium/1"
    "인증-로그인:/api/auth/google"
    "인증-프로필:/api/auth/profile"
)

for route in "${routes[@]}"; do
    description="${route%%:*}"
    path="${route#*:}"
    echo -n "  ${description}: ${path} → "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}${path}")
    case $response in
        200|302) echo -e "${GREEN}✓ 라우팅 성공 (${response})${NC}" ;;
        401) echo -e "${YELLOW}✓ 라우팅 성공, 인증 필요 (${response})${NC}" ;;
        404) echo -e "${YELLOW}? 라우팅 규칙 확인 필요 (${response})${NC}" ;;
        502|503) echo -e "${BLUE}✓ 라우팅 성공, 백엔드 서비스 없음 (${response})${NC}" ;;
        *) echo -e "오류 (${response})" ;;
    esac
done

echo ""
echo -e "${GREEN}6. 요청 통계:${NC}"
curl -s "${GATEWAY_URL}/actuator/metrics/spring.cloud.gateway.requests" | jq -r '.measurements[] | select(.statistic == "COUNT") | "총 요청 수: " + (.value | tostring)'

echo ""
echo -e "${BLUE}=== 라우팅 정보 조회 완료 ===${NC}"
echo ""
echo -e "${YELLOW}💡 팁:${NC}"
echo "- 더 자세한 정보는 application.yaml 파일의 라우팅 설정을 확인하세요"
echo "- 백엔드 서비스(인증:8001, 뉴스:8080)가 실행 중이어야 완전한 테스트가 가능합니다"
echo "- 실시간 메트릭: curl ${GATEWAY_URL}/actuator/metrics/spring.cloud.gateway.requests | jq ."
