package smart_saving_guide.example.smart_saving_guide.domain.home;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import smart_saving_guide.example.smart_saving_guide.domain.home.dto.ResponseDto;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.UserForm;
import smart_saving_guide.example.smart_saving_guide.domain.user.service.UserService;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final UserService userService;

    @GetMapping("/")
    public String home(){
        return "home/home";
    }

    @GetMapping("/loginForm")
    public String loginForm(UserForm userForm){

        return "home/loginForm";
    }

    @PostMapping("/loginForm")
    public String loginFormSubmit(@Valid UserForm userForm, BindingResult bindingResult){
        if (bindingResult.hasErrors()){
            return "home/loginForm";
        }
        if (!userForm.getPassword1().equals(userForm.getPassword2())){
            return "home/loginForm";
        }
        userService.createUser(userForm);
        return "redirect:/";
    }

    @GetMapping("/IDCheck")
    @ResponseBody
    public ResponseDto<?> IDcheck(@RequestParam("userid") String id){
        if(id == null || id.isEmpty()){
            return new ResponseDto<>(-1,"아이디를 입력해주세요",null);
        }
        if (userService.IDcheck(id)){
            return new ResponseDto<>(1,"동일한 아이디가 존재합니다.", false);
        }else{
            return new ResponseDto<>(1,"사용가능한 아이디입니다.", true);
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response){
        SecurityContextHolder.clearContext();
        Cookie cookie = new Cookie("Authorization", null);  // 또는 "Authorization"
        cookie.setMaxAge(0);  // 즉시 만료
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        return "redirect:/";
    }
}
