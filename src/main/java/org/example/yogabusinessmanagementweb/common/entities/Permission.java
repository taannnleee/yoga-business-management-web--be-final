package org.example.yogabusinessmanagementweb.common.entities;


import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Entity
@Table(name = "Permission")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Permission extends AbstractEntity<Integer> {
    String name;
    String description;
    String pCode;

    @OneToMany(mappedBy = "permission")
    List<GroupHasPermission> groupHasPermissions;
}
