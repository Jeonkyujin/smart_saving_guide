package smart_saving_guide.example.smart_saving_guide.global.security.jwt.repository;


import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}