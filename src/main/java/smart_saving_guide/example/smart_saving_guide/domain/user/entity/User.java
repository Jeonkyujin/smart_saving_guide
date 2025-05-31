package smart_saving_guide.example.smart_saving_guide.domain.user.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import smart_saving_guide.example.smart_saving_guide.domain.commodity.entity.UserCommodity;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.Role;
import smart_saving_guide.example.smart_saving_guide.domain.user.enums.SocialType;
import smart_saving_guide.example.smart_saving_guide.global.entity.BaseEntity;

import java.util.ArrayList;
import java.util.List;

@Entity
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Id@GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String login_id;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String profile;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SocialType socialType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserCommodity> userCommodityList = new ArrayList<>();


    @Builder
    public User(String login_id, String password, String email, SocialType socialType, Role role) {
        this.login_id = login_id;
        this.password = password;
        this.email = email;
        this.socialType = socialType;
        this.role = role;
    }

    public void addUserCommodity(UserCommodity userCommodity) {
        this.userCommodityList.add(userCommodity);
        userCommodity.setUser(this);
    }


}
