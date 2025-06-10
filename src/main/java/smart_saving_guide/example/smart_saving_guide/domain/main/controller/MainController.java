package smart_saving_guide.example.smart_saving_guide.domain.main.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.enums.TokenStatus;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.provider.JwtTokenProvider;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping("/main")
    public String main(HttpServletRequest request, HttpServletResponse response) {

//        if(jwtTokenProvider.validateAccessToken(token) == TokenStatus.EXPIRED){
//            System.out.println("------------------------- check");
//            return "redirect:/?expired=true";
//        }
        return "main/main";
    }
}
