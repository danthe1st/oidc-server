package io.github.danthe1st.oidcserver.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.repository.UserRepository;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase
@Transactional // tests should be independent
class ManageUsersTest {
	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	// region get users
	@Test
	@WithMockUser(roles = "ADMIN")
	void testGetUsers() throws Exception {
		mockMvc.perform(get("/admin/users"))
			.andExpect(status().isOk())
			.andExpect(content().json("""
				[
					{
						"username": "admin",
						"type": "ADMIN"
					}
				]
				"""));
		
	}
	// endregion
	
	// region create user
	
	@Test
	void testCreateUserUnauthenticated() throws Exception {
		mockMvc.perform(post("/admin/users").with(csrf()))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("http://localhost/login"));
		assertEquals(1, userRepo.count());
	}
	
	@Test
	@WithMockUser(roles = "USER")
	void testCreateUserAsNonAdmin() throws Exception {
		mockMvc.perform(post("/admin/users").with(csrf()))
			.andExpect(status().isForbidden());
		assertEquals(1, userRepo.count());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testCreateExistingUser() throws Exception {
		mockMvc.perform(
			post("/admin/users")
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"username": "admin",
						"password": "test"
					}
					""")
		)
			.andExpect(status().isConflict())
			.andExpect(content().json("""
				{
					"message": "This user exists already."
				}
				"""));
		assertEquals(1, userRepo.count());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testCreateUserMissingData() throws Exception {
		mockMvc.perform(
			post("/admin/users")
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"username": "test"
					}
					""")
		).andExpect(status().isBadRequest());
		assertEquals(1, userRepo.count());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testCreateUser() throws Exception {
		mockMvc.perform(
			post("/admin/users")
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"username": "test",
						"password": "testpwd"
					}
					""")
		)
			.andExpect(status().isOk())
			.andExpect(content().json("""
				{
					"username": "test",
					"type": "USER"
				}
				"""));
		assertEquals(2, userRepo.count());
		User user = userService.getUser("test").orElseGet(() -> fail("user not found"));
		assertEquals("test", user.username());
		assertEquals(UserType.USER, user.userType());
		assertTrue(passwordEncoder.matches("testpwd", user.passwordHash()));
	}
	
	@ParameterizedTest
	@CsvSource({ "USER", "ADMIN" })
	@WithMockUser(roles = "ADMIN")
	void testCreateUserWithType(UserType type) throws Exception {
		mockMvc.perform(
			post("/admin/users")
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"username": "test",
						"password": "testpwd",
						"type": "%s"
					}
					""".formatted(type))
		)
			.andExpect(status().isOk())
			.andExpect(content().json("""
				{
					"username": "test",
					"type": "%s"
				}
				""".formatted(type.name())));
		assertEquals(2, userRepo.count());
		User user = userService.getUser("test").orElseGet(() -> fail("user not found"));
		assertEquals("test", user.username());
		assertEquals(type, user.userType());
		assertTrue(passwordEncoder.matches("testpwd", user.passwordHash()));
	}
	
	// endregion
	
	// region delete user
	
	@Test
	@WithMockUser(username = "admin", roles = "ADMIN")
	void testDeleteSelfUser() throws Exception {
		mockMvc.perform(delete("/admin/users/admin").with(csrf()))
			.andExpect(status().isConflict())
			.andExpect(content().json("""
				{
					"message": "It is not possible to delete the current user."
				}
				"""));
		assertEquals(1, userRepo.count());
		assertTrue(userService.getUser("admin").isPresent());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testDeleteNonexistentUser() throws Exception {
		mockMvc.perform(delete("/admin/users/test").with(csrf()))
			.andExpect(status().isNotFound())
			.andExpect(content().json("""
				{
					"message": "This user was not found."
				}
				"""));
		assertEquals(1, userRepo.count());
		assertTrue(userService.getUser("admin").isPresent());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testDeleteUser() throws Exception {
		mockMvc.perform(delete("/admin/users/admin").with(csrf()))
			.andExpect(status().isNoContent());
		assertEquals(0, userRepo.count());
	}
	
	// endregion
	
	// region update password
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testUpdatePasswordNonexistentUser() throws Exception {
		mockMvc.perform(
			put("/admin/users/test/password").with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"password": "test123"
					}
					""")
		)
			.andExpect(status().isNotFound())
			.andExpect(content().json("""
				{
					"message": "This user was not found."
				}
				"""));
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testUpdatePasswordNoPassword() throws Exception {
		mockMvc.perform(
			put("/admin/users/test/password").with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("{}")
		).andExpect(status().isBadRequest());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testUpdatePasswordEmptyPassword() throws Exception {
		mockMvc.perform(
			put("/admin/users/test/password").with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					"password": ""
					""")
		).andExpect(status().isBadRequest());
	}
	
	@Test
	@WithMockUser(roles = "ADMIN")
	void testUpdatePassword() throws Exception {
		mockMvc.perform(
			put("/admin/users/admin/password").with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
						"password": "test123"
					}
					""")
		)
			.andExpect(status().isOk())
			.andExpect(content().json("""
				{
					"username": "admin",
					"type": "ADMIN"
				}
				"""));
		User user = userService.getUser("admin").orElseGet(() -> fail("user not found"));
		assertTrue(passwordEncoder.matches("test123", user.passwordHash()));
	}
	
	// endregion
}
