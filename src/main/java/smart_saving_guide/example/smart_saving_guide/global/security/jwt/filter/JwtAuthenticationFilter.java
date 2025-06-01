package smart_saving_guide.example.smart_saving_guide.global.security.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.PrincipalDetails;

import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면(post)
//usernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        //1.username, password를 받아서


        String username = request.getParameter("username");
        String password = request.getParameter("password");


        UsernamePasswordAuthenticationToken authRequestToken = new UsernamePasswordAuthenticationToken(username, password);
        //principalDetailsService 의 loadUserByName () 함수가 실행됨
        Authentication authentication = authenticationManager.authenticate(authRequestToken);

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println(principalDetails.getUser().getLoginId());
        //authentication 객체가 세션 영역에 저장됨
        return authentication;


    }
    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면, successfulAuthentication 함수 실행
    //jwt 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 하면됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 이 실행됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash암호방식
        String jwtToken = JWT.create() // pom.xml
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+ (60000 * 10))) //1분 * 10
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getLoginId())
                .sign(Algorithm.HMAC512("cos")); // HMAC512는 시크릿 키가 있어야 함.

        Cookie jwtCookie = new Cookie("Authorization", jwtToken);
        jwtCookie.setHttpOnly(true);     // JS에서 접근 못하도록 보안 강화
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(600);        // 초 단위
        response.addCookie(jwtCookie);

        response.sendRedirect("/main");

    }
}

