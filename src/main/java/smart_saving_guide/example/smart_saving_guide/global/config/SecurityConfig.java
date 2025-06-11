package smart_saving_guide.example.smart_saving_guide.global.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.*;
import smart_saving_guide.example.smart_saving_guide.domain.auth.handler.DelegatingOAuth2LoginSuccessHandler;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.OAuthUserService;
import smart_saving_guide.example.smart_saving_guide.domain.user.repository.UserRepository;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.filter.JwtAuthenticationFilter;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.filter.JwtAuthorizationFilter;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.repository.RefreshTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;



@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;
    private final OAuthUserService OAuth2UserService;
    private final DelegatingOAuth2LoginSuccessHandler delegatingOAuth2LoginSuccessHandler;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    @Value("${token.access.expiration}")
    private String accessTokenExpiresAt;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        JwtAuthenticationFilter jwtAuthFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenProvider, refreshTokenRepository, accessTokenExpiresAt);
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(jwtTokenProvider);
        //jwtAuthFilter.setFilterProcessesUrl("/login");
        // 이 부분이 핵심

        RequestMatcher loginRequestMatcher =
                request -> request.getMethod().equals("POST") && request.getServletPath().equals("/login");

        jwtAuthFilter.setRequiresAuthenticationRequestMatcher(loginRequestMatcher);

        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(request ->
                        request.requestMatchers("/", "/loginForm", "/css/**", "/js/**", "/images/**", "IDCheck", "/oauth2/**", "/login/**", "/oauth-success.html", "/normal-success.html", "/token/**").permitAll()
                                .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(OAuth2UserService))
                        .successHandler(delegatingOAuth2LoginSuccessHandler))

                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class) // 모든 요청
                .addFilterAt(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);             // /login 요청만

        return http.build();
    }
}
