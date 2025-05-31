package smart_saving_guide.example.smart_saving_guide.domain.user.exception;

import smart_saving_guide.example.smart_saving_guide.global.error.BusinessException;
import smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode;

public class UserException extends BusinessException {
    public UserException(GlobalErrorCode errorCode) {
        super(errorCode);
    }
}
