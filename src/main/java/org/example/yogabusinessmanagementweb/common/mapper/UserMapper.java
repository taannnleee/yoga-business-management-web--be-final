package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.dto.response.checkout.UserAddressDefaultResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(source = "user.phone", target = "phone")
    @Mapping(source = "user.fullname", target = "fullname")// Sử dụng AddressMapper để map Address sang AddressResponse
    UserAddressDefaultResponse toUserAddressDefaultResponse(User user, Address address);
}
