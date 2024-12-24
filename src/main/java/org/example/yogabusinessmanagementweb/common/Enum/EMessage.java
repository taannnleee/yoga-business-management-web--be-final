package org.example.yogabusinessmanagementweb.common.Enum;

import lombok.Getter;

@Getter
public enum EMessage {
    CONFIRM_PASSWORD_NOT_MATCH("Mật khẩu không khớp!"),
    TITLE_OTP("Your OTP is sent"),
    TEXT_EMAIL_OTP("Your OTP is: "),
    OTP_NOT_MATCH("Mã OTP không khớp"),
    CHANGE_PASS_WORD_SUCCESS("Thay đổi mật khẩu thành công!!"),
    OLD_PASS_NOT_MATCH("Mật khẩu không đúng!!"),
    CHANGE_PASS_WORD_NOT_SUCCESS("Thay đổi mật khẩu thất bại!!"),
    CUSTOMER_NOT_EXIST("Khách hàng không tồn tại!!"),
    REGISTER_FAIL("Đăng kí thất bại"),
    REGISTER_SUCCESS("Đăng kí thành công"),
    LOGIN_SUCCESS("Đăng nhập thành công"),
    CUSTOMER_EXIST("Khách hàng đã tồn tại!!");
    private final String value;

    EMessage(String value) {
        this.value = value;
    }
}