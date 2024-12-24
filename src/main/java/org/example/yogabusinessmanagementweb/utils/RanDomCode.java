package org.example.yogabusinessmanagementweb.utils;

import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.repositories.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;
@Component
public class RanDomCode {
    private final ProductRepository productRepository;

    // Constructor injection của ProductRepository
    @Autowired
    public RanDomCode(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }
    // Tạo đối tượng Random để sinh số ngẫu nhiên
    public String generateRandomCode() {
        // Tạo đối tượng Random để sinh số ngẫu nhiên
        Random random = new Random();

        // Sinh ra một số ngẫu nhiên trong khoảng 0 đến 9999
        int randomNumber = random.nextInt(10000);

        // Tạo chuỗi mã sản phẩm với tiền tố "SRT" và 4 chữ số
        return "SRT" + String.format("%04d", randomNumber);  // Đảm bảo mã có 4 chữ số
    }

    // Kiểm tra xem mã sản phẩm có tồn tại trong cơ sở dữ liệu hay không
    public boolean isCodeExist(String code) {
        // Lấy tất cả sản phẩm trong cơ sở dữ liệu
        List<Product> products = productRepository.findAll();

        // Duyệt qua danh sách sản phẩm để kiểm tra mã sản phẩm có trùng không
        for (Product product : products) {
            if (product.getCode().equals(code)) {
                return true;  // Nếu mã trùng, trả về true
            }
        }

        return false;  // Nếu không có mã trùng, trả về false
    }

    // Tạo mã sản phẩm duy nhất
    public String generateUniqueCode() {
        String code;
        boolean exists;

        do {
            // Tạo mã ngẫu nhiên
            code = generateRandomCode();

            // Kiểm tra xem mã đã tồn tại trong bảng product hay chưa
            exists = isCodeExist(code);
        } while (exists);  // Nếu mã đã tồn tại, tạo mã mới

        return code;  // Trả về mã duy nhất không bị trùng
    }
}
