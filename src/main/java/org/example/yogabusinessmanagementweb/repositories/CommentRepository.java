package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Comment;

import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {
    Optional<Comment> findById(Long id);
    Page<Comment> findAll(Pageable pageable);
    @Query("SELECT c FROM Comment c WHERE c.product = :product AND c.parentComment IS NULL AND c.ratePoint = :ratePoint")
    Page<Comment> findByProductAndRatePoint(Pageable pageable, Product product, int ratePoint);
    List<Comment> findByParentCommentId(Long parentCommentId);
    @Query("SELECT c FROM Comment c WHERE c.product = :product AND c.parentComment IS NULL AND c.ratePoint IS NULL")
    Page<Comment> findByProductAndRatePointIsNull(Pageable pageable, Product product);
    List<Comment> findByProduct(Product product);
    @Query("SELECT c FROM Comment c WHERE c.product = :product AND c.parentComment IS NULL")
    Page<Comment> findByProduct(Product product, Pageable pageable);

}
