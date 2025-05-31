package smart_saving_guide.example.smart_saving_guide.global.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@Getter
@AllArgsConstructor
public enum GlobalErrorCode {

    //User 오류
    USER_NOT_FOUND(NOT_FOUND, "USR-001", "사용자를 찾지 못했습니다.");

    //Commodity 오류

    private final HttpStatus status;
    private final String code;
    private final String message;
}
