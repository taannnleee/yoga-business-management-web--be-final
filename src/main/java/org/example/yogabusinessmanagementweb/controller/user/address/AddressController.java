package org.example.yogabusinessmanagementweb.controller.user.address;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartResponse;
import org.example.yogabusinessmanagementweb.service.AddressService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/address")
@Slf4j
public class AddressController {
    AddressService addressService;

    //trả về list address
    @GetMapping("/get-address")
    public ApiResponse<?> getAddress(HttpServletRequest request) {
        List<Address > addresses = addressService.getAddressOfUser(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "Get address success",addresses);
    }

    @PutMapping("/update/{id}")
    public ApiResponse<?> updateAddress(@PathVariable String id, HttpServletRequest request,@RequestBody AddressRequest addressRequest) {
        AddressResponse addressResponse =  addressService.updateAddress(id,request,addressRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "Update address success",addressResponse);
    }

    @PostMapping("/create")
    public ApiResponse<?> createAddress(HttpServletRequest request,@RequestBody AddressRequest addressRequest) {
        AddressResponse addressResponse =  addressService.createAddress(request,addressRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "Create address success",addressResponse);
    }

    @DeleteMapping("/delete/{id}")
    public ApiResponse<?> deleteAddress(@PathVariable String id, HttpServletRequest request) {
        AddressResponse addressResponse =  addressService.deleteAddress(id,request);
        return new ApiResponse<>(HttpStatus.OK.value(), "Delete address success",addressResponse);
    }

    @PostMapping("/set-default/{id}")
    public ApiResponse<?> setDefault(@PathVariable String id, HttpServletRequest request) {
        AddressResponse addressResponse =  addressService.setDefault(id,request);
        return new ApiResponse<>(HttpStatus.OK.value(), "set default address success",addressResponse);
    }


}
