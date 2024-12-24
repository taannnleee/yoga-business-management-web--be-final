package org.example.yogabusinessmanagementweb.controller.uploadfile;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.CloudinaryResponse;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.service.CloudinaryService;
import org.example.yogabusinessmanagementweb.utils.FileUploadUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api")
@Slf4j
public class FileController {
    @Autowired
    private CloudinaryService cloudinaryService;

    @PostMapping("/image/upload")
    public ApiResponse<?> uploadImage(@RequestParam(name = "file", required = true)
                                      MultipartFile file) {  // Đảm bảo dùng đúng tên trường 'file'
        FileUploadUtil.assertAllowed(file, FileUploadUtil.IMAGE_PATTERN);
        final String fileName = FileUploadUtil.getFileName(file.getOriginalFilename());
        final CloudinaryResponse response = cloudinaryService.uploadFile(file, fileName);
        return new ApiResponse<>(HttpStatus.OK.value(), "Tải ảnh lên Coudinary thành công.", response);
    }


    @DeleteMapping("/image/delete")
    public ApiResponse<?> deleteImage(@RequestParam("url") String url) throws IOException {
        try {
            cloudinaryService.deleteByUrl(url);
            return new ApiResponse<>(HttpStatus.OK.value(), "Xóa ảnh thành công.",null);
//        } catch (CustomException e) {
//            return ResponseEntity.status(e.getStatusCode()).body(new BaseResponse(e.getMessage(), e.getStatusCode(), null));
        } catch (IOException e) {
            return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Lỗi hệ thống. Vui lòng thử lại.",null);

        }
    }

}


