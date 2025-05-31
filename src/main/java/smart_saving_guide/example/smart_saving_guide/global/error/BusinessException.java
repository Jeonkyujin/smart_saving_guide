package smart_saving_guide.example.smart_saving_guide.global.error;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final GlobalErrorCode errorCode;

    public BusinessException(GlobalErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;

    }
}
