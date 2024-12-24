package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.Enum.EStatusOrder;
import org.example.yogabusinessmanagementweb.common.entities.Order;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    Page<Order> findAll(Pageable pageable);
    Page<Order> findAllByUser(User user, Pageable pageable);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status AND o.user = :user")
    Page<Order> findAllByStatusAndUser(@Param("status") EStatusOrder status,
                                       @Param("user") User user, Pageable pageable);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status AND o.user = :user")
    List<Order> findAllByStatusAndUser(@Param("status") EStatusOrder status,
                                       @Param("user") User user);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status")
    List<Order> findAllByStatus(@Param("status") EStatusOrder status, Pageable pageable);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status")
    List<Order> findAllByStatus(@Param("status") EStatusOrder status);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status AND FUNCTION('DATE', o.updatedAt) = FUNCTION('DATE', :updatedAt)")
    List<Order> findAllByStatusAndUpdatedAt(@Param("status") EStatusOrder status,
                                            @Param("updatedAt") Date updatedAt,
                                            Pageable pageable);

    @Query("SELECT o FROM Order o WHERE o.eStatusOrder = :status AND FUNCTION('DATE_FORMAT', o.updatedAt, '%Y-%m') = FUNCTION('DATE_FORMAT', :updatedAt, '%Y-%m')")
    List<Order> findAllByStatusAndYearMonth(@Param("status") EStatusOrder status,
                                            @Param("updatedAt") Date updatedAt,
                                            Pageable pageable);

}

