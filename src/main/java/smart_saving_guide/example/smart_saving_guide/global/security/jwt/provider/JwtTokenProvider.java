package smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider;


import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.crypto.SecretKey;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.PrincipalDetailService;
import smart_saving_guide.example.smart_saving_guide.domain.auth.service.PrincipalDetails;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.Role;
import smart_saving_guide.example.smart_saving_guide.domain.user.repository.UserRepository;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.Token;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.enums.TokenStatus;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.exception.TokenException;

import static smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode.*;

@Slf4j
@Component


public class JwtTokenProvider {

    private final PrincipalDetailService principalDetailsService;
    private final UserRepository userRepository;

    private static final String BEARER = "Bearer ";
    private static final String KEY_ROLE = "role";
	private SecretKey secretKey;

    //@Value("${token.key}")
    //private SecretKey secretKey;
    @Value("${token.access.expiration}")
    private Long accessTokenExpirationAt;
    @Value("${token.refresh.expiration}")
    private Long refreshTokenExpirationAt;
    @Value("${token.access.header}")
    private String accessTokenHeader;
    @Value("${token.refresh.cookie.name}")
    private String refreshCookieName;

	public JwtTokenProvider(@Value("${token.key}") String secret, PrincipalDetailService principalDetailsService,UserRepository userRepository ) {
		this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
		this.principalDetailsService = principalDetailsService;
		this.userRepository = userRepository;
	}

//	@PostConstruct
//	private void setSecretKey() {
//		byte[] keyBytes = Base64.getDecoder().decode(key);
//		secretKey = Keys.hmacShaKeyFor(keyBytes);
//		log.debug("[Token] Secret Key 초기화 완료");
//	}

    private String generateToken(Long userId, String role, long expireTime) {
        User user = userRepository.findById(userId).orElse(null);
        Date expiredDate = new Date(System.currentTimeMillis() + expireTime);
        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(user, role))
                .setSubject(String.valueOf(userId))
                .setExpiration(expiredDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    private Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "HS256");
        return header;
    }

    private Map<String, Object> createClaims(User user, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(KEY_ROLE, role);
        return claims;
    }

    public Token createToken(Long userId, Role role) {
        String accessToken = generateToken(userId, role.getKey(), accessTokenExpirationAt);
        String refreshToken = generateToken(userId, role.getKey(), refreshTokenExpirationAt);
        log.debug("[Token] 토큰 생성 완료 - userId: {}", userId);
        return Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


	private Claims parseClaims(String token) {
		log.debug("[Token] 토큰 파싱 시작: {}", token);
		if (!StringUtils.hasText(token)) {
			throw new TokenException(INVALID_TOKEN);
		}
		try {
			Claims claims = Jwts.parserBuilder()
					.setSigningKey(secretKey)
					.build()
					.parseClaimsJws(token)
					.getBody();
			return claims;
		} catch (ExpiredJwtException e) {
			log.warn("[Token] 만료된 토큰: {}", token);
			return e.getClaims();
		} catch (MalformedJwtException e) {
			log.error("[Token] 잘못된 형식의 토큰: {}", token);
			throw new TokenException(INVALID_TOKEN);
		} catch (SecurityException e) {
			log.error("[Token] 유효하지 않은 서명: {}", token);
			throw new TokenException(INVALID_JWT_SIGNATURE);
		}
	}

	public TokenStatus validateAccessToken(String accessToken) {
		if (!StringUtils.hasText(accessToken)) {
			log.warn("[Token] 액세스 토큰 없음");
			return TokenStatus.NOT_FOUND;
		}
		try {
			Claims claims = parseClaims(accessToken);
			if (claims.getExpiration().before(new Date())) {
				log.warn("[Token] 만료된 액세스 토큰");
				return TokenStatus.EXPIRED;
			}
			return TokenStatus.VALID;
		} catch (SecurityException | MalformedJwtException e) {
			log.error("[Token] 유효하지 않은 JWT 토큰", e);
			return TokenStatus.INVALID;
		} catch (UnsupportedJwtException e) {
			log.error("[Token] 지원되지 않는 JWT 토큰", e);
			return TokenStatus.INVALID;
		}
	}

	// refresh token 검증 시에도 예외 대신 명확한 예외 처리를 진행
	public boolean isRefreshTokenValid(String refreshToken) {
		try {
			Claims claims = parseClaims(refreshToken);
			if (!claims.getExpiration().after(new Date())) {
				log.warn("[Token] 리프레시 토큰 만료");
				throw new TokenException(REFRESH_TOKEN_EXPIRED);
			}
			return claims.getExpiration().after(new Date());
		} catch (ExpiredJwtException e) {
			log.warn("[Token] 리프레시 토큰 만료", e);
			throw new TokenException(REFRESH_TOKEN_EXPIRED);
		} catch (Exception e) {
			log.error("[Token] 리프레시 토큰 검증 실패", e);
			throw new TokenException(INVALID_TOKEN);
		}
	}



	public Authentication getAuthentication(String token) {
		try {
			Claims claims = parseClaims(token);
			return createAuthentication(claims, token);
		} catch (Exception e) {
			log.error("[Authentication] 인증 객체 생성 실패", e);
			throw new TokenException(ACCESS_TOKEN_EXPIRED);
		}
	}

	public Authentication getAuthenticationFromRefreshToken(String refreshToken) {
		Claims claims = parseClaims(refreshToken);
		return createAuthentication(claims, refreshToken);
	}

	private Authentication createAuthentication(Claims claims, String token) {
		List<SimpleGrantedAuthority> authorities = getAuthorities(claims);
		System.out.println("createAuthentication" + Long.valueOf(claims.getSubject()));
		User user = userRepository.findById(Long.valueOf(claims.getSubject()))
			.orElseThrow();
		if (user.getPassword() != null) {
			UserDetails principal = principalDetailsService.loadUserByUsername(user.getLoginId());
			return new UsernamePasswordAuthenticationToken(principal, token, authorities);
		}else{
			PrincipalDetails principal = new PrincipalDetails(user);
			return new UsernamePasswordAuthenticationToken(principal, token, authorities);
		}
	}

	private List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
		return Collections.singletonList(new SimpleGrantedAuthority(claims.get(KEY_ROLE).toString()));
	}

	public String extractAccessTokenFromHeader(HttpServletRequest request) {
		return Optional.ofNullable(request.getHeader(accessTokenHeader))
			.filter(token -> token.startsWith(BEARER))
			.map(token -> token.replace(BEARER, ""))
			.orElseThrow(() -> {
				log.warn("[Token] 헤더에서 액세스 토큰을 찾을 수 없음");
				return new TokenException(TOKEN_NOT_FOUND);
			});
	}

	public String extractAccessTokenFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();

		if (cookies == null) {
			log.warn("[Token] 쿠키가 비어있습니다.");
			throw new TokenException(TOKEN_NOT_FOUND);
		}

		return Arrays.stream(cookies)
				.filter(cookie -> "Authorization".equals(cookie.getName()))
				.map(Cookie::getValue)
				.findFirst()
				.orElseThrow(() -> {
					log.warn("[Token] Authorization 쿠키가 존재하지 않습니다.");
					return new TokenException(TOKEN_NOT_FOUND);
				});
	}



	public Optional<String> extractRefreshTokenFromCookie(HttpServletRequest request) {
		Optional<String> token = Optional.ofNullable(request.getCookies())
			.flatMap(cookies -> Arrays.stream(cookies)
				.filter(cookie -> cookie.getName().equals(refreshCookieName))
				.map(Cookie::getValue)
				.findFirst());
		if (token.isEmpty()) {
			log.warn("[Token] 쿠키에서 리프레시 토큰을 찾을 수 없음");
		}
		return token;
	}

	public Long getExpiration(String token) {
		Claims claims = parseClaims(token);
		return claims.getExpiration().getTime() - new Date().getTime();
	}

	public PrincipalDetails getUserDetails(Authentication authentication) {
		return (PrincipalDetails)authentication.getPrincipal();
	}
}
