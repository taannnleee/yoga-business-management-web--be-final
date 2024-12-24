package org.example.yogabusinessmanagementweb.common.entities;


import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EStatus;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.util.List;

@Entity
@Table(name = "Category")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Category extends AbstractEntity<Long> implements Serializable  {

    @Column(name = "url_image")
    String urlImage;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    EStatus status = EStatus.ACTIVE;

    @Column(name = "category_name")
    String name;
    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnore
    List<SubCategory> subCategories;
}

