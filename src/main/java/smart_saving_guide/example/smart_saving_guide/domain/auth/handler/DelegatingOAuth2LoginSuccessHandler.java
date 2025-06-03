package smart_saving_guide.example.smart_saving_guide.domain.auth.handler;



import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;



import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import smart_saving_guide.example.smart_saving_guide.domain.auth.exception.AuthException;
import smart_saving_guide.example.smart_saving_guide.domain.auth.repository.HttpCookieOAuth2AuthorizationRequestRepository;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.GoogleOAuth2UserService;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.KakaoOAuth2UserService;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.NaverOAuth2UserService;

import static smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode.INVALID_AUTHENTICATION_TYPE;
import static smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode.PROVIDER_NOT_FOUND;

@Component
public class DelegatingOAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

	private final Map<String, AuthenticationSuccessHandler> handlerMap;
	private final HttpCookieOAuth2AuthorizationRequestRepository authRequestRepository;

	public DelegatingOAuth2LoginSuccessHandler(
		GoogleOAuth2UserService googleHandler,
		NaverOAuth2UserService naverHandler,
		KakaoOAuth2UserService kakaoHandler,
		HttpCookieOAuth2AuthorizationRequestRepository authRequestRepository
	) {
		this.handlerMap = Map.of(
			"google", googleHandler,
			"naver", naverHandler,
			"kakao", kakaoHandler
		);
		this.authRequestRepository = authRequestRepository;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		if (!(authentication instanceof OAuth2AuthenticationToken oAuth2Token)) {
			throw new AuthException(INVALID_AUTHENTICATION_TYPE);
		}


		authRequestRepository.removeAuthorizationRequestCookies(request, response);

		String registrationId = oAuth2Token.getAuthorizedClientRegistrationId();
		AuthenticationSuccessHandler delegate = Optional.ofNullable(handlerMap)
			.map(v -> v.get(registrationId))
			.orElseThrow(() -> new AuthException(PROVIDER_NOT_FOUND));

		delegate.onAuthenticationSuccess(request, response, authentication);
	}
}
