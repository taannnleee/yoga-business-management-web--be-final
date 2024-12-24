package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Entity
@Table(name = "Teacher")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Teacher extends AbstractEntity<Long> {

    String fullName;

    String introduction;

    @Column(columnDefinition = "LONGTEXT")
    String description;

    String email;

    String phoneNumber;

    int experienceYears;

    String profilePicture;

}
