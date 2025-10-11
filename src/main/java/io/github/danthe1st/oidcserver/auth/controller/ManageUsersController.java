package io.github.danthe1st.oidcserver.auth.controller;

import java.util.List;

import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.service.MissingUserException;
import io.github.danthe1st.oidcserver.auth.service.UserAlreadyExistsException;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/users")
public class ManageUsersController {
	private final UserService userService;
	
	public ManageUsersController(UserService userService) {
		this.userService = userService;
	}
	
	@GetMapping
	List<UserDTO> getUsers() {
		return userService.getUsers()
			.stream()
			.map(UserDTO::new)
			.toList();
	}
	
	@PostMapping
	UserDTO createUser(@RequestBody @Valid CreateUserDTO userInformation) throws UserAlreadyExistsException {
		User user = userService.createUser(userInformation.username(), userInformation.password(), userInformation.type());
		return new UserDTO(user);
	}
	
	@DeleteMapping("/{username}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	void deleteUser(Authentication authentication, @PathVariable("username") String username) throws MissingUserException, CannotDeleteSelfUserException {
		if(authentication.getName().equals(username)){
			throw new CannotDeleteSelfUserException();
		}
		userService.deleteUser(username);
	}
	
	@PutMapping("/{username}/password")
	UserDTO updatePassword(@PathVariable("username") String username, @RequestBody @Valid UpdatePasswordRequest passwordRequest) throws MissingUserException {
		User user = userService.setPassword(username, passwordRequest.password());
		return new UserDTO(user);
	}
	
	// region DTOs
	
	record CreateUserDTO(@NotNull @NotBlank String username, @NotNull @NotBlank String password, UserType type) {
		public CreateUserDTO(String username, String password, @Nullable UserType type) {
			this.username = username;
			this.password = password;
			if(type == null){
				type = UserType.USER;
			}
			this.type = type;
		}
	}
	
	record UserDTO(String username, UserType type) {
		public UserDTO(User user) {
			this(user.username(), user.userType());
		}
	}
	
	record UpdatePasswordRequest(@NotNull String password) {
		
	}
	
	record ErrorResponse(String message) {
	}
	
	// endregion
	
	// region exception handling
	
	@ExceptionHandler(exception = UserAlreadyExistsException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	ErrorResponse onUserAlreadyExists() {
		return new ErrorResponse("This user exists already.");
	}
	
	@ExceptionHandler(exception = MissingUserException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	ErrorResponse userNotFound() {
		return new ErrorResponse("This user was not found.");
	}
	
	@ExceptionHandler(exception = CannotDeleteSelfUserException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	ErrorResponse failDeleteSelfUser() {
		return new ErrorResponse("It is not possible to delete the current user.");
	}
	
	// endregion
	
}
