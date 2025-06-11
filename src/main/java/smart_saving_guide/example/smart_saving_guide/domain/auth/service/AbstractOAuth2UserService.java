package smart_saving_guide.example.smart_saving_guide.domain.auth.service;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;



import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import smart_saving_guide.example.smart_saving_guide.domain.user.service.UserService;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.repository.RefreshTokenRepository;

@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Slf4j
public abstract class AbstractOAuth2UserService extends SimpleUrlAuthenticationSuccessHandler {
	private static final String FRONT_PORT = "5173";
	protected static final String FRONT_REDIRECT_URI = "http://localhost:5173";
	protected final JwtTokenProvider jwtTokenProvider;
	protected final RefreshTokenRepository refreshTokenRepository;
	protected final UserService userService;
	@Value("${token.access.header}")
	protected String accessTokenHeader;
	@Value("${token.access.expiration}")
	protected String accessTokenExpiresAt;
	@Value("${token.refresh.cookie.name}")
	protected String refreshTokenCookieName;
	@Value("${base-url}")
	protected String baseUrl;
	protected final ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public abstract void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException;

	public void addAccessTokenToCookie(String accessToken, HttpServletResponse response) {
		Cookie cookie = new Cookie("Authorization", accessToken);

		if (cookie.getValue() == null) {
			cookie.setMaxAge(0);
			log.debug("[Token] 리프레시 토큰 쿠키 삭제");
		}
		System.out.println("AccessTokenExpiresAt: " + accessTokenExpiresAt);
		cookie.setPath("/");
		ZonedDateTime seoulTime = ZonedDateTime.now(ZoneId.of("Asia/Seoul"));
		ZonedDateTime expirationTime = seoulTime.plusSeconds(Long.parseLong(accessTokenExpiresAt));
		cookie.setMaxAge((int)(expirationTime.toEpochSecond() - seoulTime.toEpochSecond()));
		cookie.setSecure(true);
		cookie.setHttpOnly(true);
		response.addCookie(cookie);
		log.debug("[Token] 엑세스 토큰 쿠키 생성 - name: {}, maxAge: {}", "accessToken", cookie.getMaxAge());
	}

	protected String determineRedirectUrl(HttpServletRequest request) {
		String sourceUrl = Optional
			.ofNullable(request.getHeader("Referer"))
			.orElse(request.getHeader("Origin"));

		log.debug("[OAuth2] Source URL: {}", sourceUrl);

		return (sourceUrl != null && sourceUrl.contains(FRONT_PORT))
			? FRONT_REDIRECT_URI
			: baseUrl;
	}
}
