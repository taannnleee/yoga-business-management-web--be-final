package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Entity
@Table(name = "Sections")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Sections  extends AbstractEntity<Long>{
    String title;

    @OneToMany(cascade = CascadeType.ALL)
    @JoinColumn(name = "section_id")
    List<Lectures> lectures;
}
