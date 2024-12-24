package org.example.yogabusinessmanagementweb.common.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Entity
@Table(name = "Notification")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Notification  extends AbstractEntity<Long>{

    @Column
    private String title;

    @Column
    private String message;

    @Column
    private boolean isRead;

    @ManyToOne()
    @JoinColumn(name = "user_id")
    private User user;

}