package smart_saving_guide.example.smart_saving_guide.domain.user.enums;


import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public enum SocialType {
    KAKAO,
    GOOGLE,
    NAVER
}
