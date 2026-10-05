package com.rikkei.course.controller;

import com.rikkei.course.dto.Course;
import com.rikkei.course.dto.CreateCourseRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    // Không dùng DB: lưu tạm trong List tĩnh (thread-safe)
    private static final AtomicLong ID_SEQ = new AtomicLong();
    private static final List<Course> COURSES = new CopyOnWriteArrayList<>(List.of(
            new Course(ID_SEQ.incrementAndGet(), "Spring Boot Microservices", "Xây dựng hệ thống microservice"),
            new Course(ID_SEQ.incrementAndGet(), "Spring Security & JWT", "Xác thực và phân quyền với JWT")
    ));

    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public List<Course> getCourses() {
        return COURSES;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public Course createCourse(@Valid @RequestBody CreateCourseRequest request) {
        Course course = new Course(ID_SEQ.incrementAndGet(), request.title(), request.description());
        COURSES.add(course);
        return course;
    }
}
