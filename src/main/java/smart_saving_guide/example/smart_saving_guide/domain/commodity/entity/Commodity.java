package smart_saving_guide.example.smart_saving_guide.domain.commodity.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import smart_saving_guide.example.smart_saving_guide.domain.commodity.enums.CommodityType;

@Entity
@Data
public class Commodity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String bankName;

    @Column(nullable = false)
    private String name;

    private String period;

    private String Amount;

    private String condition;

    private String category;

    private String interestRate;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CommodityType commodityType;


}
