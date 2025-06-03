package smart_saving_guide.example.smart_saving_guide.domain.auth.exception;

import smart_saving_guide.example.smart_saving_guide.global.error.BusinessException;
import smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode;

public class AuthException extends BusinessException {
    public AuthException(GlobalErrorCode errorCode) {
        super(errorCode);
    }
}
