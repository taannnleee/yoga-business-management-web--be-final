package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EAddress;

@Entity
@Table(name = "Address")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Address extends AbstractEntity<Long> {
    String houseNumber;
    String street;
    String district ;
    String city;
    @Enumerated(EnumType.STRING)
    EAddress status;

    String nameDelivery;
    String phoneNumberDelivery;
}
