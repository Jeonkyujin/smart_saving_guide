package smart_saving_guide.example.smart_saving_guide.global.security.jwt.entity;

import lombok.Builder;
import lombok.Data;

@Data
public class Token {
    private String accessToken;
    private String refreshToken;

    @Builder
    public Token(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
