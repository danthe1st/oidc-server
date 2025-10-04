package io.github.danthe1st.oidcserver.auth.service;

import java.util.Optional;

import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class UserService {
	private final UserRepository userRepo;
	
	public UserService(UserRepository userRepo) {
		this.userRepo = userRepo;
	}
	
	public Optional<User> getUser(String username) {
		return userRepo.findByUsername(username);
	}
	
	public User getCurrentUser(Authentication auth) {
		return getUser(auth.getName()).orElseThrow(() -> new IllegalStateException("user not found"));
	}
	
}
