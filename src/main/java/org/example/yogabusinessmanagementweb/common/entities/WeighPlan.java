package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.io.Serializable;

@Entity
@Table(name = "WeighPlan")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class WeighPlan extends AbstractEntity<Long>  implements Serializable {
    @Column(name = "name")
    String name;

    @Column(name = "description")
    String description;
}
