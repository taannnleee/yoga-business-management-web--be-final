package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Entity
@Table(name = "`group`")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Group extends AbstractEntity <Long>{
    String name;
    String description;
    int kind;

    @OneToMany(mappedBy = "group")
    List<GroupHasUser> groupHasUsers;

    @OneToMany(mappedBy = "group")
    List<GroupHasPermission> groupHasPermissions;
}
