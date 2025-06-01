package smart_saving_guide.example.smart_saving_guide.domain.user.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.UserForm;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.Role;
import smart_saving_guide.example.smart_saving_guide.domain.user.exception.UserException;
import smart_saving_guide.example.smart_saving_guide.domain.user.repository.UserRepository;
import smart_saving_guide.example.smart_saving_guide.global.error.GlobalErrorCode;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public boolean IDcheck(String id) {
        if(userRepository.findByLoginId(id) != null){
            return true;
        }else{
            return false;
        }
    }

    public void createUser(UserForm userForm){
        User user = User.builder()
                .loginId(userForm.getLoginId())
                .password(passwordEncoder.encode(userForm.getPassword1()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
    }
}
