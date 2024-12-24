package org.example.yogabusinessmanagementweb.service.Impl;

import com.cloudinary.Cloudinary;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.CloudinaryResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.service.CloudinaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Service
@Slf4j
public class CloudinaryServiceImpl implements CloudinaryService {
    @Autowired
    private Cloudinary cloudinary;

    @Transactional
    @Override
    public CloudinaryResponse uploadFile(MultipartFile file, String fileName)  {
        try {
            //tải tệp lên cloudinary
            final Map result = cloudinary.uploader().upload(
                    file.getBytes(), Map.of("public_id", "yoga/" + fileName));

            final String url = (String) result.get("secure_url");
            final String publicId = (String) result.get("public_id");
            return CloudinaryResponse.builder()
                    .publicId(publicId)
                    .url(url)
                    .build();

        } catch (Exception e) {
            throw new AppException(ErrorCode.CATEGORY_EXISTS);
        }
    }

    @Transactional
    @Override
    public boolean deleteFileById(String publicId) {
        try {
            Map result = cloudinary.uploader().destroy(publicId, Map.of());

            // Kiểm tra xem ảnh đã bị xóa thành công chưa
            String resultStatus = (String) result.get("result");
            return "ok".equals(resultStatus);

        } catch (Exception e) {
            throw new AppException(ErrorCode.CATEGORY_EXISTS);
        }
    }

    @Override
    public void deleteByUrl(String url) throws IOException {
        // lấy publicId từ URL
        String[] parts = url.split("/");

        // kiểm tra định dạng URL hợp lệ
        if (parts.length == 0) {
            throw new AppException(ErrorCode.CATEGORY_EXISTS);
        }

        // lấy phần tên tệp từ URL
        String fileNameWithExtension = parts[parts.length - 1]; // ví dụ: logo.png_20241020191959.png

        // lấy phần tên tệp mà không có đuôi mở rộng
        String fileNameWithoutExtension = fileNameWithExtension.substring(0, fileNameWithExtension.lastIndexOf('.')); // ví dụ: logo.png_20241020191959

        // xác định public_id
        String publicId = "yoga/" + fileNameWithoutExtension; // publicId: sportcenter/logo.png_20241020191959

        log.info("Deleting image with publicId: " + publicId); // Kiểm tra lại publicId ở đây

        // xóa ảnh từ Cloudinary
        try {
            Map<String, Object> result = cloudinary.uploader().destroy(publicId, null);

            // kiểm tra kết quả xóa
            String resultStatus = (String) result.get("result");
            if (!"ok".equals(resultStatus)) {
                throw new AppException(ErrorCode.CATEGORY_EXISTS);
            }

            log.info("Deleted image with publicId: " + publicId);
        } catch (Exception e) {
            throw new AppException(ErrorCode.CATEGORY_EXISTS);
        }
    }

}
