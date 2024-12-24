package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.Enum.EStatus;
import org.example.yogabusinessmanagementweb.common.entities.Category;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {
    Optional<Category> findById(Long id);
    Optional<Category> findByNameAndStatus(String name, EStatus status);
    Optional<Category> findByIdAndStatus(Long id, EStatus status);
    @Query("SELECT new org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse(c.name, sc.name, p.id, p.title, p.price, p.imagePath) " +
            "FROM Category c " +
            "JOIN c.subCategories sc " +
            "JOIN sc.products p " +
            "WHERE c.status = 'ACTIVE' AND sc.status = 'ACTIVE'")
    List<CategoryResponse> findCategoriesWithProducts();

    List<Category> getAllByStatus(EStatus status);
}
