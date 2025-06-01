package smart_saving_guide.example.smart_saving_guide.domain.user.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;

@Data
public class UserForm {
    @NotEmpty(message = "사용자 ID는 필수 항목입니다")
    private String loginId;

    @NotEmpty(message = "비밀번호는 필수 항목입니다")
    private String password1;

    @NotEmpty(message = "비밀번호 확인은 필수 항목입니다")
    private String password2;

    public UserForm(){

    }
}
