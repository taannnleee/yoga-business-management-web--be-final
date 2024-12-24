package org.example.yogabusinessmanagementweb.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error",HttpStatus.INTERNAL_SERVER_ERROR),
    UNAUTHENTICATED(9000, "Authentication required. Please log in.", HttpStatus.UNAUTHORIZED),

    UNAUTHORIZED(9001, "You do not have permission to access this resource", HttpStatus.FORBIDDEN),
    MISSING_FIELD_REQUIRED(1002, "Missing required field",HttpStatus.BAD_REQUEST),
    INVAlID_KEY(1003, "Invalid message key",HttpStatus.BAD_REQUEST),
    USER_NOT_FOUND(1009, "User not found",HttpStatus.NOT_FOUND),

    TOKEN_INVALID(1010, "Token is invalid",HttpStatus.BAD_REQUEST),
    PASS_WORD_NOT_MATCHED(1011, "Password word not matched",HttpStatus.BAD_REQUEST),
    TOKEN_EMPTY(1012, "Token is empty",HttpStatus.NOT_FOUND),
    USER_NOT_ACTIVE(1013, "User is not active",HttpStatus.BAD_REQUEST),
    TOKEN_NOT_FOUND(1014, "Token not found",HttpStatus.NOT_FOUND),
    OTP_INVALID(1015, "OTP is invalid",HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_FOUND(1016, "Product not found",HttpStatus.NOT_FOUND),
    USERNAME_ALREADY_EXISTS(1017, "Username already exists",HttpStatus.BAD_REQUEST),
    PHONE_ALREADY_EXISTS(1018, "Phone already exists",HttpStatus.BAD_REQUEST),
    EMAIL_ALREADY_EXISTS(1019, "Email already exists",HttpStatus.BAD_REQUEST),

    CART_NOT_FOUND(1020, "Cart not found",HttpStatus.NOT_FOUND),
    PRODUCT_NOT_EXISTS(1021, "Product not exists",HttpStatus.NOT_FOUND),
    SUBCATEGORY_NOT_FOUND(1022, "Subcategory not found",HttpStatus.NOT_FOUND),


    CATEGORY_EXISTS(1023, "Category already exists",HttpStatus.BAD_REQUEST),
    CATEGORY_NOT_FOUND(1024, "Category not found",HttpStatus.NOT_FOUND),


    ADDRESS_NOT_FOUND(1025, "Address not found",HttpStatus.NOT_FOUND),

    INVALID_CREDENTIALS(1026,"Invalid credentials",HttpStatus.BAD_REQUEST ),
    CART_ITEM_EMPTY(1027, "Cart item is empty",HttpStatus.NOT_FOUND),

    TEACHER_NOT_FOUND(1028, "Teacher not found",HttpStatus.NOT_FOUND),
    TOPIC_NOT_FOUND(1029, "Topic not found",HttpStatus.NOT_FOUND),
    COURSE_NOT_FOUND(1030, "Course not found",HttpStatus.NOT_FOUND),
    SECTION_NOT_FOUND(1031, "section not found",HttpStatus.NOT_FOUND),

    LECTURE_NOT_FOUND(1032, "lecture not found",HttpStatus.NOT_FOUND),

    ORDER_NOT_FOUND(1032, "order not found",HttpStatus.NOT_FOUND),


    CART_ITEM_NOT_FOUND(1033, "Cart item not found",HttpStatus.NOT_FOUND),

    WISHLIST_NOT_FOUND(1034, "Wishlist not found",HttpStatus.NOT_FOUND),
    PRODUCT_EXISTS_WISHLIST(1035, "The product already exists in the wishlist",HttpStatus.NOT_FOUND),
    COMMENT_NOT_FOUND(1036, "Comment not found",HttpStatus.NOT_FOUND),
    NOTIFICATION_NOT_FOUND(1037, "Comment not found",HttpStatus.NOT_FOUND),

    PASS_WORD_INCORRECT(1038, "Pass word incorrect",HttpStatus.BAD_REQUEST);
    // MODULE ERROR

    // CLASS ERROR

    // TRAINING PROGRAM ERROR
    int code;
    String message;
    HttpStatus statusCode;
}
