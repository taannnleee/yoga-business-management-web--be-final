package org.example.yogabusinessmanagementweb.dto.response.address;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EAddress;
@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class AddressResponse {
    Long id;
    String houseNumber;
    String street;
    String district ;
    String city;
    EAddress status;
    String nameDelivery;
    String phoneNumberDelivery;
}
