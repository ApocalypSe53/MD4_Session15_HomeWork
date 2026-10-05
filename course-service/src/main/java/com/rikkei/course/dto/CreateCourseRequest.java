package com.rikkei.course.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateCourseRequest(
        @NotBlank(message = "title không được để trống") String title,
        String description
) {
}
