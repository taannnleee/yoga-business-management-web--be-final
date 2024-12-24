package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.example.yogabusinessmanagementweb.common.Enum.EAddress;
import org.example.yogabusinessmanagementweb.common.Enum.EGender;
import org.example.yogabusinessmanagementweb.common.entities.Wishlist;
import org.example.yogabusinessmanagementweb.common.mapper.AddressMapper;
import org.example.yogabusinessmanagementweb.common.mapper.UserMapper;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.user.RegistrationRequest;
import org.example.yogabusinessmanagementweb.dto.request.user.UpdateProfileRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.checkout.UserAddressDefaultResponse;
import org.example.yogabusinessmanagementweb.dto.response.user.ProfileResponse;
import org.example.yogabusinessmanagementweb.dto.response.user.RegistrationResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.AddressRepository;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.AddressService;
import org.example.yogabusinessmanagementweb.service.JwtService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.common.Enum.ERole;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.mapper.Mappers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.example.yogabusinessmanagementweb.common.Enum.ETokenType.ACCESSTOKEN;


@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    @Autowired
    AddressMapper addressMapper;

    @Autowired
    UserMapper userMapper;

    @Autowired
    private final JwtUtil jwtUtil;

    @Autowired
    @Lazy
    private AuthencationService authencationService;

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AddressService addressService;

    @Autowired
    private JwtService jwtService;;

    @Autowired
    private AddressRepository addressRepository;

    @Override
    public List<User> getAllUser() {
        return userRepository.findAll();
    }

    @Override
    public User findUserById(String id) {
        return userRepository.findById(Long.valueOf(id))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public User findUserByUserName(String userName) {
        return userRepository.findByUsername(userName)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public UserDetailsService userDetailsService() {
        return username ->
                userRepository.findByUsername(username)
                        .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public RegistrationResponse registerUser(RegistrationRequest registrationRequest) {
        ArrayList arrayList = new ArrayList();
        Address address = new Address();
        address.setStatus(EAddress.DEFAULT);
        address.setCity("");
        address.setDistrict("");
        address.setStreet("");
        address.setHouseNumber("");
        address.setNameDelivery(registrationRequest.getFullName());
        address.setPhoneNumberDelivery(registrationRequest.getPhone());

        arrayList.add(address);

        String encodedPassword = passwordEncoder.encode(registrationRequest.getPassword());
        User user = Mappers.convertToEntity(registrationRequest, User.class);
        user.setPassword(encodedPassword);
        user.setStatus(false);
        user.setRoles(ERole.USER.name() );

        user.setAddresses(arrayList);

        //tạo ra một wish list cho người dùng
//        Wishlist wishlist = new Wishlist();
//        user.setWishlist(wishlist);
        userRepository.save(user);
        authencationService.sendOTP(registrationRequest.getEmail());

        RegistrationResponse registrationResponse = Mappers.convertToDto(user, RegistrationResponse.class);
        return registrationResponse;
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public long saveUser(User user) {
        userRepository.save(user);
        return user.getId();
    }

    @Override
    public ProfileResponse getProfile(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);

        List<Address> list_address = getUserAddresses(user.getId());

        ProfileResponse profileResponse = Mappers.convertToDto(user, ProfileResponse.class);
        profileResponse.setCity(list_address.get(0).getCity());
        profileResponse.setStreet(list_address.get(0).getStreet());
        profileResponse.setState(list_address.get(0).getDistrict());
        return profileResponse;
    }

    @Override
    public List<Address> getUserAddresses(Long userId) {
        // Lấy User theo userId
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        // Trả về danh sách Address
        return user.getAddresses();
    }

    @Override
    public void updateProfile(UpdateProfileRequest updateProfileRequest, HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);

        // Cập nhật thông tin người dùng từ request
//        user.setUsername(updateProfileRequest.getUsername());
//        user.setFullname(updateProfileRequest.getFullname());

        user.setFirstName(updateProfileRequest.getFirstName());
        user.setLastName(updateProfileRequest.getLastName());
        user.setEmail(updateProfileRequest.getEmail());
        user.setPhone(updateProfileRequest.getPhone());
        user.setImagePath(updateProfileRequest.getImagePath());

        String genderString = updateProfileRequest.getGender();
        if (genderString != null) {
            try {
                user.setGender(EGender.valueOf(genderString)); // Sử dụng giá trị của enum nếu hợp lệ
            } catch (IllegalArgumentException e) {
                // Nếu không có giá trị hợp lệ, bạn có thể chọn thiết lập giá trị mặc định
                System.err.println("Invalid gender value: " + genderString + ". Setting to default.");
//                user.setGender(EGender.OTHER);
            }
        }

        // Chuyển đổi String dateOfBirth thành Date
        if (updateProfileRequest.getDateOfBirth() != null && !updateProfileRequest.getDateOfBirth().isEmpty()) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            try {
                Date dateOfBirth = sdf.parse(updateProfileRequest.getDateOfBirth());
                user.setDateOfBirth(dateOfBirth);
            } catch (ParseException e) {
                // Xử lý lỗi nếu chuỗi ngày tháng không hợp lệ
                System.err.println("Error parsing date: " + e.getMessage());
                // Bạn có thể chọn tiếp tục xử lý hoặc ném lỗi tùy theo yêu cầu
                return; // Không trả về gì vì phương thức có kiểu trả về void
            }
            userRepository.save(user);
        }
    }


    @Override
    public User findByPhone(String phoneNumber) {
        return userRepository.findByPhone(phoneNumber).orElseThrow(()-> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public User findByUserName(String username) {
        return userRepository.findByUsername(username).orElseThrow(()-> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public boolean checkUserNotExist(RegistrationRequest registrationRequest) {
        // Kiểm tra xem mật khẩu và xác nhận mật khẩu có khớp không
        if (!registrationRequest.getPassword().equals(registrationRequest.getConfirmPassword())) {
            throw new AppException(ErrorCode.PASS_WORD_NOT_MATCHED);
        }

        // Kiểm tra xem username đã tồn tại chưa
        if (userRepository.findByUsername(registrationRequest.getUsername()).isPresent()) {
            throw new AppException(ErrorCode.USERNAME_ALREADY_EXISTS);
        }

        // Kiểm tra xem phone đã tồn tại chưa
        if (userRepository.findByPhone(registrationRequest.getPhone()).isPresent()) {
            throw new AppException(ErrorCode.PHONE_ALREADY_EXISTS);
        }

        // Kiểm tra xem email đã tồn tại chưa
        if (userRepository.findByEmail(registrationRequest.getEmail()).isPresent()) {
            throw new AppException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        return true;
    }

    @Override
    public AddressResponse getUserAddressDefault(HttpServletRequest request) {
        User user =  jwtUtil.getUserFromRequest(request);

        List<Address> addresses = user.getAddresses();


        for(Address address : addresses) {
            if(address.getStatus() == EAddress.DEFAULT) {
                return addressMapper.toAddressResponse(address);
            }
        }

        throw new AppException(ErrorCode.ADDRESS_NOT_FOUND);
    }

    @Override
    public String getEmailByUserName(String userName, HttpServletRequest request) {
        User user =  findUserByUserName(userName);
        return user.getEmail();
    }

}
