package org.example.yogabusinessmanagementweb.common.entities;

import io.hypersistence.utils.hibernate.type.json.JsonType;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
@Entity
@Table(name = "Product")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
@Convert(attributeName = "json", converter = JsonType.class)
public class Product extends AbstractEntity<Long> implements Serializable {

    @Column(name = "image_url")
    String imagePath;

    Boolean status;

    @Column(name = "price")
    BigDecimal price;

    @Column(name = "title")
    String title;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "subCategory_id")
    SubCategory subCategory;

    @Column(name = "average_rating")
    Double averageRating = (double) 0;
    @Column(name = "sold", nullable = false)
    Double sold = (double) 0;

    @Column(name = "code")
    String code;
    @Column(name = "brand")
    String brand;
    @Column(name = "description", columnDefinition = "TEXT")
    String description;
//    // Thuộc tính mới để lưu danh sách variants dưới dạng JSON
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "variants", columnDefinition = "json")
    Map<String, Map<String, String>> variants;
}
