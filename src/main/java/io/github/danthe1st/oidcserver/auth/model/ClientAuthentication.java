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
		super.setDetails(client);
		super.setAuthenticated(true);
	}
	
	@Override
	public Object getCredentials() {
		return null;
	}
	
	@Override
	public Client getPrincipal() {
		return client;
	}
}
