package smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity;

import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash(value = "refreshToken", timeToLive = 14400)
@AllArgsConstructor
@NoArgsConstructor
public class RefreshToken {

    @Id
    private String refreshToken;

    private Long userId;


}
