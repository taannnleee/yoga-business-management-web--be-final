package org.example.yogabusinessmanagementweb.common.entities;


import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EGender;
import org.example.yogabusinessmanagementweb.common.Enum.ERole;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.management.relation.Role;
import javax.print.attribute.standard.Media;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class User extends AbstractEntity<Long>  implements UserDetails, Serializable {
    String username;
    String password;
    String phone;
    @Enumerated(EnumType.STRING)
    EGender gender;
    String email;
    String fullname;
    String firstName;
    String lastName;

    @Temporal(TemporalType.DATE)
    Date dateOfBirth;
    String imagePath;
    String roles;
    String OTP;
    Date expired;
    boolean status;


    // User quản lý Address, một chiều
    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    List<Address> addresses;

    @OneToMany(mappedBy = "user")
    List<GroupHasUser> groupHasUsers;


    @OneToMany()
    List<UserHasYogaWorkout> yogaWorkouts;


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // Phương thức getAuthorities duy nhất
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(roles)); // Chuyển đổi Role thành GrantedAuthority
    }
}
