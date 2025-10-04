package io.github.danthe1st.oidcserver.auth.model;

import java.util.Objects;

import org.springframework.data.annotation.Id;

public record User(
	@Id long id,
	String username,
	String passwordHash,
	UserType userType) {
	public User {
		Objects.requireNonNull(username);
		Objects.requireNonNull(passwordHash);
		Objects.requireNonNull(userType);
	}
}
