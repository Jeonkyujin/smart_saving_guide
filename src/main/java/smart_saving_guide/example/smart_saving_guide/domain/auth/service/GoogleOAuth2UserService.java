package smart_saving_guide.example.smart_saving_guide.domain.auth.service;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;



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
public class GoogleOAuth2UserService extends AbstractOAuth2UserService {

	protected GoogleOAuth2UserService(JwtTokenProvider jwtTokenProvider,
									  RefreshTokenRepository refreshTokenRepository,
									  UserService userService) {
		super(jwtTokenProvider, refreshTokenRepository, userService);
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws
		IOException {

		//oauth 프로필 추출
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		String name = oAuth2User.getAttribute("name");
		String profile = oAuth2User.getAttribute("picture");
		String email = oAuth2User.getAttribute("email");
		User user = User.builder()
			.loginId(name)
			.email(email)
			.profile(profile)
				.role(Role.USER)
				.socialType(SocialType.GOOGLE)
			.build();
		User newUser = userService.createUserForOAuth(user);



		//jwt 토큰 생성
		Token jwtToken = jwtTokenProvider.createToken(newUser.getId(), newUser.getRole());
		String newAccessToken = jwtToken.getAccessToken();
		String newRefreshToken = jwtToken.getRefreshToken();

		//authentication = jwtTokenProvider.getAuthentication(newAccessToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		//response.setHeader(accessTokenHeader, "Bearer " + newAccessToken);
		addAccessTokenToCookie(newAccessToken, response);
		//RefreshToken refreshToken = new RefreshToken(newRefreshToken, newUser.getId());
		//refreshTokenRepository.save(refreshToken);
		//addRefreshTokenToCookie(newRefreshToken, response);

		//String redirectUrl = determineRedirectUrl(request);
		//log.debug("[Google OAuth2] 리다이렉션 URL: {}", redirectUrl);
//		String html = """
//            <html>
//            <body>
//                <script>
//                    localStorage.setItem("accessToken", "%s");
//                    window.location.href = "/main";
//                </script>
//            </body>
//            </html>
//            """.formatted(newAccessToken);

		//response.setContentType("text/html;charset=UTF-8");
		//response.getWriter().write(html);
		//response.sendRedirect(redirectUrl);
		response.sendRedirect("/main");
	}
}

