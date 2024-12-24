package org.example.yogabusinessmanagementweb.common.entities;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EHealthyGoal;

import java.io.Serializable;

@Entity
@Table(name = "HealthyInformation")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class HealthyInformation extends AbstractEntity<Long>  implements Serializable {

    @Column(name = "healthy_goal")
    @Enumerated(EnumType.STRING) // Store enum as a string in the database
    EHealthyGoal healthyGoal;
    @Column(name = "age")
    int age;
    @Column(name = "bmi")
    Double bmi;

    @Column(name = "bmr")
    Double bmr;

    @Column(name = "weight")
    Double weight;

    @Column(name = "height")
    Double height;

    @Column(name = "meal_per_day")
    int mealPerDay;

    @OneToOne()
    @JoinColumn(name = "user_id")
    User user;

    @OneToOne()
    WeighPlan weighPlan;

}
