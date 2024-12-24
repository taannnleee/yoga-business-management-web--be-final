package org.example.yogabusinessmanagementweb.repositories;


import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.common.entities.SubCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
    Optional<Product> findProductById(Long id);
    Page<Product> findByTitleContainingIgnoreCase(String keyword, Pageable pageable);

    // Phương thức tìm sản phẩm theo subCategory
    Page<Product> findBySubCategory(SubCategory subCategory, Pageable pageable);
    @Query("SELECT p FROM Product p WHERE p.subCategory.id = :subCategoryId " +
            "AND (:keyword IS NULL OR LOWER(p.title) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Product> filterBySubCategory(@Param("subCategoryId") Long subCategoryId,
                                      @Param("keyword") String keyword,
                                      Pageable pageable);

    @Query("SELECT p FROM Product p " +
            "LEFT JOIN p.subCategory sc " +
            "LEFT JOIN sc.category c " +
            "WHERE (:subCategoryId IS NULL OR sc.id = :subCategoryId) " +
            "AND (:categoryId IS NULL OR c.id = :categoryId) " +
            "AND (:keyword IS NULL OR LOWER(p.title) LIKE LOWER(CONCAT('%', CAST(:keyword AS string), '%'))) ")
    Page<Product> filterProducts(@Param("subCategoryId") Long subCategoryId,
                                 @Param("categoryId") Long categoryId,
                                 @Param("keyword") String keyword,
                                 Pageable pageable);

    @Query(value = "SELECT * FROM product ORDER BY sold DESC LIMIT 10", nativeQuery = true)
    List<Product> findTop10BestSellingProducts();

    @Query("SELECT p FROM Product p WHERE p.status = true")
    Page<Product> findProductsWithStatusTrue(Pageable pageable);
}
