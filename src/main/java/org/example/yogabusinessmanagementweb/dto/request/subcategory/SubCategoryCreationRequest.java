package org.example.yogabusinessmanagementweb.dto.request.subcategory;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class SubCategoryCreationRequest {
    @NotNull(message = "Name is required")
    String name;

    @NotNull(message = "Category id is required")
    Long categoryId;
}
