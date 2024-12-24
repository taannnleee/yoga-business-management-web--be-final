package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Comment;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.dto.request.product.ProductCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.util.List;

@Mapper(componentModel = "spring", nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE, uses = {UserMapper.class})
public interface ProductMapper{

    // Ignore the variantList field in the Product entity when mapping
    Product toProduct(ProductCreationRequest productDTO);

    ProductResponse toProductResponse(Product product);
    List<ProductResponse> productsToProductResponses(List<Product> products);
    @Mapping(target = "replies", ignore = true) // Prevent recursion by ignoring replies in CommentResponse
    @Mapping(target = "parentComment", ignore = true) // Prevent recursion by ignoring parentComment in CommentResponse
    CommentResponse commentToCommentResponse(Comment comment);

    List<CommentResponse> commentListToCommentResponseList(List<Comment> comments);

}
