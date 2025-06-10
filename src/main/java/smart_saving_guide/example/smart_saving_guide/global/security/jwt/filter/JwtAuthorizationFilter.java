package smart_saving_guide.example.smart_saving_guide.global.security.jwt.filter;

//시큐리티가 filter를 가지고 있는데 그 필터중 BasicAuthenticationFilter 가 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어있음
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.PrincipalDetails;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.repository.UserRepository;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.enums.TokenStatus;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.exception.TokenException;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;

import java.io.IOException;
import java.util.Arrays;

import static smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode.ACCESS_TOKEN_EXPIRED;
import static smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode.INVALID_TOKEN;


@Slf4j


public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final String[] WHITE_LIST = {
            "/",
            "/loginForm",
            "/css/**",
            "/js/**",
            "/images/**",
            "/IDCheck",
            "/oauth2/**",
            "/login/**",
            "/oauth-success.html",
            "/normal-success.html",
            "/token/**"

    };

    private final JwtTokenProvider tokenProvider;

    public JwtAuthorizationFilter(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {


        // white list 또는 인증/로그인 관련 경로면 토큰 검증을 건너뜁니다.
        if (shouldNotFilter(request)) {

            filterChain.doFilter(request, response);
            return;
        }
        String accessToken = tokenProvider.extractAccessTokenFromCookie(request);




        log.debug("[Token] JwtAuthorizationFilter 토큰 검증 accessToken : {}", accessToken);
        TokenStatus tokenStatus = tokenProvider.validateAccessToken(accessToken);
        //시큐리티 컨텍스트에 인증 객체를 담는 것은 매 요청마다 필수적으로 해줘야함
        if (tokenStatus == TokenStatus.VALID) {
            setAuthentication(accessToken);
        } else if (tokenStatus == TokenStatus.EXPIRED) {
            throw new TokenException(ACCESS_TOKEN_EXPIRED);
        } else {
            throw new TokenException(INVALID_TOKEN);
        }
        System.out.println("not error");
        filterChain.doFilter(request, response);
    }

    private void setAuthentication(String accessToken) {

        try {
            Authentication authentication = tokenProvider.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            log.error("[Authentication] 사용자 인증 설정 실패", e);
            throw new TokenException(INVALID_TOKEN);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        log.trace("[Request] 요청 경로, 메서드: {} {}", uri, request.getMethod());

        return isWhiteList(request);
    }

    // HTTP 메서드에 상관없이 URL 패턴만으로 화이트리스트 적용
    private boolean isWhiteList(HttpServletRequest request) {
        AntPathMatcher matcher = new AntPathMatcher();
        return Arrays.stream(WHITE_LIST)
                .anyMatch(pattern -> matcher.match(pattern, request.getRequestURI()));
    }


}
