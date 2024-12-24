package org.example.yogabusinessmanagementweb.dto.request.address;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EAddress;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class AddressRequest {
    String houseNumber;
    String street;
    String district ;
    String city;
//    EAddress status;
    String nameDelivery;
    String phoneNumberDelivery;
}
