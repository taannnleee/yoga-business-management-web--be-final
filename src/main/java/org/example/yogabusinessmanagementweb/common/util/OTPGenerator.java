package org.example.yogabusinessmanagementweb.common.util;

import java.security.SecureRandom;

public class OTPGenerator {
    public static String generateOTP(){
        String NUMBERS = "0123456789";
        int OTP_LENGTH = 6;
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder(OTP_LENGTH);

        for (int i = 0; i < OTP_LENGTH; i++) {
            int randomIndex = random.nextInt(NUMBERS.length());
            otp.append(NUMBERS.charAt(randomIndex));
        }

        return otp.toString();
    }
}
