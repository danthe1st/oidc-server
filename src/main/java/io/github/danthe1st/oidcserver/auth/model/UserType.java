package io.github.danthe1st.oidcserver.auth.model;

import java.util.List;

public enum UserType {
	USER("USER"), ADMIN("USER", "ADMIN");
	
	private final List<String> roles;
	
	UserType(String... roles) {
		this.roles = List.of(roles);
	}
	
	public List<String> getRoles() {
		return roles;
	}
}
