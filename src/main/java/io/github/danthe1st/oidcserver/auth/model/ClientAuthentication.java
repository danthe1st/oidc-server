package io.github.danthe1st.oidcserver.auth.model;

import java.util.List;

import io.github.danthe1st.oidcserver.apps.model.Client;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class ClientAuthentication extends AbstractAuthenticationToken {
	
	private final Client client;
	
	public ClientAuthentication(Client client) {
		super(List.of(new SimpleGrantedAuthority("ROLE_CLIENT")));
		this.client = client;
	}
	
	@Override
	public Object getCredentials() {
		return new Object();
	}
	
	@Override
	public Client getPrincipal() {
		return client;
	}
	
	@Override
	public boolean isAuthenticated() {
		return true;
	}
	
	@Override
	public Object getDetails() {
		return client;
	}
}
