package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.Map;

@Entity
@Table(name = "CartItem")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartItem extends AbstractEntity<Long>{
    int quantity;

    BigDecimal totalPrice;

    @ManyToOne()
    @JoinColumn(name = "product_id")
    Product product;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "currentVariant", columnDefinition = "json")
    Map<String, Map<String, String>> currentVariant;

}
