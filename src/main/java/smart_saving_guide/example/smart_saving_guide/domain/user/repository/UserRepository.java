package smart_saving_guide.example.smart_saving_guide.domain.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByLoginId(String login_id);

}
