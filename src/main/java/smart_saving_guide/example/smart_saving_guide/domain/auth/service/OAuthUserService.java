package smart_saving_guide.example.smart_saving_guide.domain.auth.service;

import org.springframework.http.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class OAuthUserService extends DefaultOAuth2UserService {
    private static final String NAVER_REGISTRATION_ID = "naver";

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        String accessToken = userRequest.getAccessToken().getTokenValue();

        OAuth2User oAuth2User;
        // 기본 정보 먼저 로딩
        if (NAVER_REGISTRATION_ID.equals(registrationId)) {
            oAuth2User = loadNaverUser(userRequest);
        } else {
            oAuth2User = super.loadUser(userRequest);
        }

        Map<String, Object> attributes = oAuth2User.getAttributes();
        Set<GrantedAuthority> authorities = new HashSet<>(oAuth2User.getAuthorities());

        // ✅ 네이버만 별도 처리
        if (NAVER_REGISTRATION_ID.equals(registrationId)) {
            if (attributes.get("id") == null) {
                throw new OAuth2AuthenticationException("네이버 응답에 id 없음");
            }

            return new DefaultOAuth2User(
                    authorities,
                    attributes,  // 이제 평탄화된 attributes 그대로 사용
                    "id"
            );
        }

        // ✅ 나머지(Google, Kakao 등)는 그대로 사용
        return new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                attributes,
                userRequest.getClientRegistration()
                        .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName()
        );
    }

    private OAuth2User loadNaverUser(OAuth2UserRequest userRequest) {
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        String userInfoUri = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUri();

        // 2. 요청 헤더 생성
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken.getTokenValue()); // Authorization: Bearer ...
        headers.setContentType(MediaType.APPLICATION_JSON);

        // 3. 요청 전송
        HttpEntity<?> entity = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.exchange(
                userInfoUri,
                HttpMethod.GET,
                entity,
                Map.class
        );

        // 4. 응답 파싱
        Map<String, Object> responseBody = response.getBody();
        Map<String, Object> userAttributes = (Map<String, Object>)responseBody.get("response");

        if (userAttributes == null || userAttributes.get("id") == null) {
            throw new OAuth2AuthenticationException("네이버 응답에 id 없음");
        }

        // 5. 권한 설정
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        for (String scope : accessToken.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }

        // 6. OAuth2User 객체 생성
        return new DefaultOAuth2User(
                authorities,
                userAttributes,  // 변경된 변수명
                "id"
        );
    }
}
