package io.github.danthe1st.oidcserver.auth.service;

import java.util.Collection;

import io.github.danthe1st.oidcserver.auth.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class OIDCUserDetailService implements UserDetailsService {
	
	private final UserService userService;
	
	public OIDCUserDetailService(UserService userService) {
		this.userService = userService;
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return new OIDCUserDetails(
			userService.getUser(username)
				.orElseThrow(() -> new UsernameNotFoundException("username not found"))
		);
	}
}

class OIDCUserDetails implements UserDetails {
	private final User user;
	
	public OIDCUserDetails(User user) {
		this.user = user;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.userType().getRoles().stream()
			.map(role -> "ROLE_" + role)
			.map(SimpleGrantedAuthority::new)
			.toList();
	}
	
	@Override
	public String getPassword() {
		return user.passwordHash();
	}
	
	@Override
	public String getUsername() {
		return user.username();
	}
}