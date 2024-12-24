package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Comment;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.dto.request.comment.CommentCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.product.ProductCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentOrderResponse;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface CommentService {
    List<CommentResponse> all(Pageable pageable);
    ListDto<List<CommentResponse>> byProduct(Pageable pageable, String id, int ratePoint);
    Comment findById(String id);
    CommentResponse getById(String id);
//    Comment addProduct(ProductCreationRequest productCreationRequest);
    public CommentOrderResponse addComment(CommentCreationRequest commentRequest, User user);
    boolean delete(String id);
    public Double caculateAverageRating(Product product);
}
