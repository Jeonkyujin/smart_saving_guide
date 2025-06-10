package smart_saving_guide.example.smart_saving_guide.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByLoginId(username);
        if (user != null){
            return new PrincipalDetails(user);
        }
        return null;
    }

    public OAuth2User loadUserByEmail(String Email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(Email);
        if (user != null){
            return new PrincipalDetails(user);
        }
        return null;
    }
}
