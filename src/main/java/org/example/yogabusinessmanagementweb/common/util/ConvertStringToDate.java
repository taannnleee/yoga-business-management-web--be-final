package org.example.yogabusinessmanagementweb.common.util;

import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.Date;

@Component
public class ConvertStringToDate {
    public Date convertStringToDate(String dateStr) {
        try {
            // Sử dụng định dạng ngày tháng bạn muốn
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd"); // Hoặc "yyyy-MM-dd'T'HH:mm:ss" nếu có giờ
            return dateFormat.parse(dateStr);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid date format", e);
        }
    }
}
