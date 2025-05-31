package smart_saving_guide.example.smart_saving_guide.global.error;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.ui.Model;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import smart_saving_guide.example.smart_saving_guide.domain.commodity.exception.CommodityException;
import smart_saving_guide.example.smart_saving_guide.domain.user.exception.UserException;

import java.io.IOException;

@ControllerAdvice
public class GlobalExceptionHandler {

    private String handleExceptionCommon(Exception ex, Model model, HttpServletRequest request) {

        model.addAttribute("message", ex.getMessage());
        String referer = request.getHeader("Referer");
        model.addAttribute("backUrl", referer != null ? referer : "/");
        return "error/error";
    }

    @ExceptionHandler({
            IllegalArgumentException.class,
            UserException.class,
            CommodityException.class,
            IOException.class,
            NullPointerException.class,
            MissingServletRequestParameterException.class,
            HttpMessageNotReadableException.class,
            MissingRequestHeaderException.class,
            MethodArgumentNotValidException.class,
            BusinessException.class,
    })
    public String handleAllCustomExceptions(Exception ex, Model model, HttpServletRequest request) {
        return handleExceptionCommon(ex, model, request);
    }

}
