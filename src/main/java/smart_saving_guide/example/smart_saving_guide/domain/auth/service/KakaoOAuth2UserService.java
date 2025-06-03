package smart_saving_guide.example.smart_saving_guide.domain.auth.service;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;



import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.Role;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.SocialType;
import smart_saving_guide.example.smart_saving_guide.domain.user.service.UserService;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.RefreshToken;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.Token;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.repository.RefreshTokenRepository;

@Slf4j
@Service
public class KakaoOAuth2UserService extends AbstractOAuth2UserService {

	protected KakaoOAuth2UserService(JwtTokenProvider jwtTokenProvider,
									 RefreshTokenRepository refreshTokenRepository,
									 UserService userService) {
		super(jwtTokenProvider, refreshTokenRepository, userService);
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws
		IOException,
		ServletException {

		//oauth 프로필 추출
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");
		Map<String, Object> profile = (Map<String, Object>)kakaoAccount.get("profile");

		String email = (String)kakaoAccount.get("email");
		String name = (String)profile.get("nickname");
		String profileImage = (String)profile.get("profile_image_url");

		User user = User.builder()
			.loginId(name)
			.email(email)
			.profile(profileImage)
				.role(Role.USER)
				.socialType(SocialType.KAKAO)
			.build();
		User newUser = userService.createUserForOAuth(user);

		//jwt 토큰 생성
		Token jwtToken = jwtTokenProvider.createToken(newUser.getId(), newUser.getRole());
		String newAccessToken = jwtToken.getAccessToken();
		String newRefreshToken = jwtToken.getRefreshToken();

		authentication = jwtTokenProvider.getAuthentication(newAccessToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		response.setHeader(accessTokenHeader, "Bearer " + newAccessToken);

		RefreshToken refreshToken = new RefreshToken(newRefreshToken, newUser.getId());
		refreshTokenRepository.save(refreshToken);
		addRefreshTokenToCookie(newRefreshToken, response);

		//String redirectUrl = determineRedirectUrl(request);
		//log.debug("[Kakao OAuth2] 리다이렉션 URL: {}", redirectUrl);
		//response.sendRedirect(redirectUrl);
	}
}
