package smart_saving_guide.example.smart_saving_guide.domain.commodity.entity;

import jakarta.persistence.*;
import lombok.*;
import smart_saving_guide.example.smart_saving_guide.domain.user.entity.User;
import smart_saving_guide.example.smart_saving_guide.global.entity.BaseEntity;

@Entity
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserCommodity extends BaseEntity {

    @Id@GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "commodity_id", nullable = false)
    private Commodity commodity;

    @Builder
    public UserCommodity(Long id, User user, Commodity commodity) {
        this.id = id;
        this.user = user;
        this.commodity = commodity;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
