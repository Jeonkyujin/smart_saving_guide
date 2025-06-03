package smart_saving_guide.example.smart_saving_guide.global.security.jwt.exception;

import smart_saving_guide.example.smart_saving_guide.global.error.BusinessException;
import smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode;

public class TokenException extends BusinessException {
    public TokenException(GlobalErrorCode errorCode) {
        super(errorCode);
    }
}
