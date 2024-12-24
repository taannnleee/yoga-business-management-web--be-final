package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EDiscountType;

import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "Promotion")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Promotion  extends AbstractEntity<Long> implements Serializable {
    @Column(name = "code")
    private String code;

    @Column(name = "discount")
    private Double discount; // Giá trị giảm giá, có thể là phần trăm hoặc số tiền

    @Enumerated(EnumType.STRING)
    @Column(name = "discount_type")
    private EDiscountType eDiscountType;

    int usage_limit;

    int used_count;

    @Column(name = "start_date")
    private Date startDate;

    @Column(name = "expiry_date")
    private Date expiryDate;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive;


}
