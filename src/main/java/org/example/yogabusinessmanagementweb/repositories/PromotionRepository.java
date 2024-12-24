package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PromotionRepository extends JpaRepository<Promotion, Long> {
    default List<Promotion> findTop4ByDiscount() {
        // Sử dụng Pageable để lấy 4 kết quả đầu tiên
        Pageable pageable = PageRequest.of(0, 4);  // 0: trang đầu tiên, 4: số lượng kết quả
        return findAllByOrderByDiscountDesc(pageable);  // Sắp xếp theo discount giảm dần
    }
    // Truy vấn để lấy tất cả Promotion, sắp xếp theo discount giảm dần
    List<Promotion> findAllByOrderByDiscountDesc(Pageable pageable);
}
