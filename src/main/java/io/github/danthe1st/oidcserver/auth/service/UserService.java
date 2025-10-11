package io.github.danthe1st.oidcserver.auth.service;

import java.util.List;
import java.util.Optional;

import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
	private final UserRepository userRepo;
	private final PasswordEncoder passwordEncoder;
	
	public UserService(UserRepository userRepo, PasswordEncoder passwordEncoder) {
		this.userRepo = userRepo;
		this.passwordEncoder = passwordEncoder;
	}
	
	public Optional<User> getUser(String username) {
		return userRepo.findByUsername(username);
	}
	
	public User getCurrentUser(Authentication auth) {
		return getUser(auth.getName()).orElseThrow(() -> new IllegalStateException("user not found"));
	}
	
	public User createUser(String username, String password, UserType type) throws UserAlreadyExistsException {
		if(userRepo.findByUsername(username).isPresent()){
			throw new UserAlreadyExistsException();
		}
		return userRepo.save(new User(0, username, passwordEncoder.encode(password), type));
	}
	
	public void deleteUser(String username) throws MissingUserException {
		long rowsChanged = userRepo.deleteByUsername(username);
		if(rowsChanged != 1){
			throw new MissingUserException();
		}
	}
	
	public User setPassword(String username, String password) throws MissingUserException {
		User user = getUser(username).orElseThrow(MissingUserException::new);
		user = new User(user.id(), user.username(), passwordEncoder.encode(password), user.userType());
		return userRepo.save(user);
	}
	
	public List<User> getUsers() {
		return userRepo.findAll();
	}
	
}
