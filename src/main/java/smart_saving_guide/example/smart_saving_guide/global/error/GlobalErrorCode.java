package smart_saving_guide.example.smart_saving_guide.global.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
@AllArgsConstructor
public enum GlobalErrorCode {

    //User 오류
    USER_NOT_FOUND(NOT_FOUND, "USR-001", "사용자를 찾지 못했습니다."),

    //Commodity 오류

    //Auth 오류
    PROVIDER_NOT_FOUND(NOT_FOUND, "AUTH-001", "provider 를 찾지 못했습니다."),
    INVALID_TOKEN(UNAUTHORIZED, "AUTH-002", "올바르지 않은 토큰입니다."),
    INVALID_JWT_SIGNATURE(UNAUTHORIZED, "AUTH-003", "잘못된 JWT 시그니처입니다."),
    REFRESH_TOKEN_EXPIRED(UNAUTHORIZED, "AUTH-007", "리프레쉬 토큰이 만료되었습니다."),
    TOKEN_NOT_FOUND(UNAUTHORIZED, "AUTH-005", "토큰을 찾지 못했습니다."),
    ACCESS_TOKEN_EXPIRED(UNAUTHORIZED, "AUTH-006", "토큰이 만료되었습니다."),
    INVALID_AUTHENTICATION_TYPE(UNAUTHORIZED, "AUTH-007", "Authentication 객체 타입이 올바르지 않습니다.");



    private final HttpStatus status;
    private final String code;
    private final String message;
}
