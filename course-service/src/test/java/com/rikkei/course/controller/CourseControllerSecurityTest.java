package com.rikkei.course.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CourseControllerSecurityTest {

    private static final String ROLE = "X-User-Role";
    private static final String NEW_COURSE = """
            {"title":"Docker cơ bản","description":"Container hoá ứng dụng"}""";

    @Autowired
    private MockMvc mvc;

    @Test
    void getWithoutHeader_returns401() throws Exception {
        mvc.perform(get("/api/courses")).andExpect(status().isUnauthorized());
    }

    @Test
    void getAsStudent_returns200() throws Exception {
        mvc.perform(get("/api/courses").header(ROLE, "STUDENT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").exists());
    }

    @Test
    void getAsInstructor_returns200() throws Exception {
        mvc.perform(get("/api/courses").header(ROLE, "INSTRUCTOR")).andExpect(status().isOk());
    }

    @Test
    void getAsUnknownRole_returns403() throws Exception {
        mvc.perform(get("/api/courses").header(ROLE, "GUEST")).andExpect(status().isForbidden());
    }

    @Test
    void postAsStudent_returns403() throws Exception {
        mvc.perform(post("/api/courses").header(ROLE, "STUDENT")
                        .contentType(MediaType.APPLICATION_JSON).content(NEW_COURSE))
                .andExpect(status().isForbidden());
    }

    @Test
    void postAsInstructor_returns201() throws Exception {
        mvc.perform(post("/api/courses").header(ROLE, "INSTRUCTOR")
                        .contentType(MediaType.APPLICATION_JSON).content(NEW_COURSE))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.title").value("Docker cơ bản"));
    }

    @Test
    void postAsInstructorWithBlankTitle_returns400() throws Exception {
        mvc.perform(post("/api/courses").header(ROLE, "INSTRUCTOR")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"title\":\"\"}"))
                .andExpect(status().isBadRequest());
    }
}
