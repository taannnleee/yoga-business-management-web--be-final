package org.example.yogabusinessmanagementweb.common.entities;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.print.attribute.standard.Media;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "YogaWorkout")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class YogaWorkout extends AbstractEntity<Long>  implements Serializable {
    String name;
    String description;
    int duration;
    String imagePath;
    String instruction;
    Integer level;
    String videoPath;

    @OneToMany(mappedBy = "yogaWorkout")
    List<UserHasYogaWorkout> yogaWorkouts;
}
