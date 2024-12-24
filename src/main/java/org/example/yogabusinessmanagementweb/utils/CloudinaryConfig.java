package org.example.yogabusinessmanagementweb.utils;

import com.cloudinary.Cloudinary;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class CloudinaryConfig {
    @Bean
    public Cloudinary cloudinary(){
        final Map<String, String> config = new HashMap<>();
        config.put("cloud_name", "dagkur7gg");
        config.put("api_key", "236965367342656");
        config.put("api_secret", "WvCnzVxcxz4UGOAJ8EKdeig3yrM");
        return new Cloudinary(config);
    }
}
