package smart_saving_guide.example.smart_saving_guide.domain.commodity.exception;

import smart_saving_guide.example.smart_saving_guide.global.error.BusinessException;
import smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode;

public class CommodityException extends BusinessException {
    public CommodityException(GlobalErrorCode errorCode) {
        super(errorCode);
    }
}
