package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EStatusOrder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Map;

@Entity
@Table(name = "OrderItem")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class OrderItem extends AbstractEntity<Long> implements Serializable {
    @Column(name = "title")
    String title;

    @Column(name = "quantity")
    int quantity;

    @OneToOne()
    @JoinColumn(name = "comment_id")
    Comment comment;

    @Column(name = "order_status")
    @Enumerated(EnumType.STRING) // Store enum as a string in the database
    EStatusOrder orderStatus;

    @Column(name = "total_price")
    BigDecimal totalPrice;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "product_id")
    Product product;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "currentVariant", columnDefinition = "json")
    Map<String, Map<String, String>> currentVariant;

}
