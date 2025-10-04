package io.github.danthe1st.oidcserver.auth.service;

import java.util.Optional;

import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.repository.UserRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
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
	
	@Bean
	ApplicationListener<ApplicationReadyEvent> readyListener(PasswordEncoder passwordEncoder) {
		return _ -> {
			getUser("admin").orElseGet(
				() -> userRepo.save(new User(0, "admin", passwordEncoder.encode("admin"), UserType.ADMIN))
			);
			
		};
	}
}
