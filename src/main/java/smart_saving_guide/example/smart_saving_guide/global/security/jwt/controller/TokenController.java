//package smart_saving_guide.example.smart_saving_guide.global.security.jwt.controller;
//
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.response.AuthTokenResponse;
//import smart_saving_guide.example.smart_saving_guide.global.security.jwt.service.TokenService;
//
//@RestController
//@RequiredArgsConstructor
//@RequestMapping("/token")
//public class TokenController {
//
//    private final TokenService tokenService;
//
//    @GetMapping("/oauth")
//    public ResponseEntity<AuthTokenResponse> oauthLogin(HttpServletResponse response){
//        return ResponseEntity.ok(tokenService.oauthLogin(response));
//    }
//
//    @GetMapping("/normal")
//    public ResponseEntity<AuthTokenResponse> normalLogin(HttpServletResponse response){
//       return ResponseEntity.ok(tokenService.normalLogin(response));
//    }
//}
