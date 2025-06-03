package smart_saving_guide.example.smart_saving_guide.domain.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.SocialType;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByLoginId(String login_id);

    @Query("select u From User u where u.socialType = :socialType AND u.email = :email")
    User findBySocialTypeAndEmail(@Param("socialType")SocialType socialType, @Param("email") String email);
}
