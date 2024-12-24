package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.dto.CloudinaryResponse;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface CloudinaryService {
    public CloudinaryResponse uploadFile(MultipartFile file, String fileName) ;
    public boolean deleteFileById(String publicId) ;
    public void deleteByUrl(String url) throws IOException;
}
