//package smart_saving_guide.example.smart_saving_guide.global.security.jwt.service;
//
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Service;
//import smart_saving_guide.example.smart_saving_guide.domain.auth.service.PrincipalDetails;
//import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
//import smart_saving_guide.example.smart_saving_guide.domain.user.enums.Role;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.RefreshToken;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.Token;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.repository.RefreshTokenRepository;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.response.AuthTokenResponse;
//
//import java.time.ZoneId;
//import java.time.ZonedDateTime;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class TokenService {
//
//    private final JwtTokenProvider jwtTokenProvider;
//    private final RefreshTokenRepository refreshTokenRepository;
//
//    @Value("${token.refresh.expiration}")
//    protected String refreshTokenExpiresAt;
//    @Value("${token.refresh.cookie.name}")
//    protected String refreshTokenCookieName;
//
//    public AuthTokenResponse oauthLogin(HttpServletResponse response) {
//        System.out.println("--------호출 확인---------");
//        Authentication tempAuth = SecurityContextHolder.getContext().getAuthentication();
//        System.out.println("tempAuth의 클래스 확인" + tempAuth.getClass());
//
//        SecurityContextHolder.clearContext();
//
//        PrincipalDetails principalDetails = (PrincipalDetails) tempAuth.getPrincipal();
//        User OAUTHUser = principalDetails.getUser();
//
//        String accessToken = handleOauthLogin(OAUTHUser, response);
//
//
//        return new AuthTokenResponse(accessToken);
//
//    }
//
//
//    public void addRefreshTokenToCookie(String refreshToken, HttpServletResponse response) {
//        Cookie cookie = new Cookie(refreshTokenCookieName, refreshToken);
//
//        if (cookie.getValue() == null) {
//            cookie.setMaxAge(0);
//            log.debug("[Token] 리프레시 토큰 쿠키 삭제");
//        }
//        cookie.setPath("/");
//        ZonedDateTime seoulTime = ZonedDateTime.now(ZoneId.of("Asia/Seoul"));
//        ZonedDateTime expirationTime = seoulTime.plusSeconds(Long.parseLong(refreshTokenExpiresAt));
//        cookie.setMaxAge((int)(expirationTime.toEpochSecond() - seoulTime.toEpochSecond()));
//        cookie.setSecure(true);
//        cookie.setHttpOnly(true);
//        response.addCookie(cookie);
//        log.debug("[Token] 리프레시 토큰 쿠키 생성 - name: {}, maxAge: {}", refreshTokenCookieName, cookie.getMaxAge());
//    }
//
//
//
//    private String handleOauthLogin(User user, HttpServletResponse response) {
//        Token jwtToken = jwtTokenProvider.createToken(user.getId(), user.getRole());
//        String newAccessToken = jwtToken.getAccessToken();
//        String newRefreshToken = jwtToken.getRefreshToken();
//
//        Authentication authentication = jwtTokenProvider.getAuthentication(newAccessToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        //response.setHeader("Authorization", "Bearer " + newAccessToken);
//
//        RefreshToken refreshToken = new RefreshToken(newRefreshToken, user.getId());
//        refreshTokenRepository.save(refreshToken);
//        addRefreshTokenToCookie(newRefreshToken, response);
//
//        return newAccessToken;
//    }
//
//
//
//
//    public AuthTokenResponse normalLogin(HttpServletResponse response) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
//
//
//        Token jwtToken = jwtTokenProvider.createToken(principalDetails.getUser().getId(), principalDetails.getUser().getRole());
//        String newAccessToken = jwtToken.getAccessToken();
//        String newRefreshToken = jwtToken.getRefreshToken();
//
//        //response.setHeader("Authorization", "Bearer " + newAccessToken);
//
//        //리프레시 토큰은 redis로 구현한 refreshTokenRepository에 저장하는 코드 작성
//        RefreshToken refreshToken = new RefreshToken(newRefreshToken, principalDetails.getUser().getId());
//        refreshTokenRepository.save(refreshToken);
//        return new AuthTokenResponse(newAccessToken);
//
//    }
//}
