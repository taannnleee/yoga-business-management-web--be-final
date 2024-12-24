package org.example.yogabusinessmanagementweb.service;


import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;

import java.util.List;

public interface AddressService {
    List<Address> getAddressOfUser(HttpServletRequest request);

    AddressResponse updateAddress(String id, HttpServletRequest request, AddressRequest addressRequest);

    AddressResponse createAddress(HttpServletRequest request, AddressRequest addressRequest);

    AddressResponse deleteAddress(String id, HttpServletRequest request);

    AddressResponse setDefault(String id, HttpServletRequest request);
    Address getAddressByid(String id);
}
