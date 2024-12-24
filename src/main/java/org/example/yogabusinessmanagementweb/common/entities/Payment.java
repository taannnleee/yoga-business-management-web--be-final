package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EPaymentStatus;

import java.io.Serializable;

@Entity
@Table(name = "Payment")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Payment extends AbstractEntity<Long> implements Serializable {
    @Column(name = "name_method")
    String nameMethod;

    @Enumerated(EnumType.STRING)
    EPaymentStatus ePaymentStatus;

}
