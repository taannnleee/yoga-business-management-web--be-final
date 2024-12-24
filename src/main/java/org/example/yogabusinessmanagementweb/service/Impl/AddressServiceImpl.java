package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EAddress;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.mapper.AddressMapper;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.AddressRepository;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.AddressService;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class AddressServiceImpl implements AddressService {
    AddressRepository addressRepository;
    JwtUtil jwtUtil;
    AddressMapper addressMapper;
    private final UserRepository userRepository;

    @Override
    public List<Address> getAddressOfUser(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        if(user.getAddresses()==null || user.getAddresses().isEmpty()){
            throw new AppException(ErrorCode.ADDRESS_NOT_FOUND);
        }
        return user.getAddresses();
    }

    @Override
    public AddressResponse updateAddress(String id, HttpServletRequest request, AddressRequest addressRequest) {
        User user =  jwtUtil.getUserFromRequest(request);

        List<Address> addresses = user.getAddresses();

        for(Address address : addresses) {
            if(address.getId().equals(Long.valueOf(id))) {

                addressMapper.updateAddress(address, addressRequest);
                addressRepository.save(address);

                return addressMapper.toAddressResponse(address);
            }
        }
        throw new AppException(ErrorCode.ADDRESS_NOT_FOUND);

    }

    @Override
    public AddressResponse createAddress(HttpServletRequest request, AddressRequest addressRequest) {
        User user =  jwtUtil.getUserFromRequest(request);
        Address addressSave =  addressMapper.toAddress(addressRequest);
        if (user.getAddresses() == null || user.getAddresses().isEmpty()) {
            addressSave.setStatus(EAddress.DEFAULT);
        } else {
            addressSave.setStatus(EAddress.NOTDEFAULT);
        }

        user.getAddresses().add(addressSave);
        userRepository.save(user);
        return addressMapper.toAddressResponse(addressSave);
    }

    @Override
    public AddressResponse deleteAddress(String id, HttpServletRequest request) {
        User user =  jwtUtil.getUserFromRequest(request);

        List<Address> addresses = user.getAddresses();

        for(Address address : addresses) {
            if(address.getId().equals(Long.valueOf(id))) {
                user.getAddresses().remove(address);
                addressRepository.delete(address);
                return addressMapper.toAddressResponse(address);
            }
        }
        throw new AppException(ErrorCode.ADDRESS_NOT_FOUND);
    }

    @Override
    public AddressResponse setDefault(String id, HttpServletRequest request) {
        User user =  jwtUtil.getUserFromRequest(request);

        List<Address> addresses = user.getAddresses();

        for(Address address : addresses) {
            if(address.getId().equals(Long.valueOf(id))) {

                for(Address address_default : addresses) {
                    if(address_default.getStatus() == EAddress.DEFAULT) {
                        address_default.setStatus(EAddress.NOTDEFAULT);
                        addressRepository.save(address_default);
                    }
                }

                address.setStatus(EAddress.DEFAULT);
                addressRepository.save(address);
                return addressMapper.toAddressResponse(address);
            }
        }
        throw new AppException(ErrorCode.ADDRESS_NOT_FOUND);
    }

    @Override
    public Address getAddressByid(String id) {
        return addressRepository.findById(Long.valueOf(id)).orElseThrow(()-> new AppException(ErrorCode.ADDRESS_NOT_FOUND));
    }

//
//    @Override
//    public Address findAddressByUser(User user) {
//        return addressRepository.findAddressByUser(user)
//                .orElseThrow(() -> new AppException(ErrorCode.ADDRESS_NOT_FOUND));
//    }
}
