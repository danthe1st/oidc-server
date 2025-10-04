package io.github.danthe1st.oidcserver.auth.service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.service.ClientDoesNotExistException;
import io.github.danthe1st.oidcserver.apps.service.ClientSecretIncorrectException;
import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.auth.model.ClientAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class BasicAuthManager implements AuthenticationManager {
	
	private final ClientService clientService;
	
	public BasicAuthManager(ClientService clientService) {
		this.clientService = clientService;
	}
	
	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		if(auth instanceof UsernamePasswordAuthenticationToken token){
			String clientId = token.getName();
			String clientSecret = URLDecoder.decode(token.getCredentials().toString(), StandardCharsets.UTF_8);
			try{
				Client client = clientService.authenticate(clientId, clientSecret);
				return new ClientAuthentication(client);
			}catch(ClientDoesNotExistException | ClientSecretIncorrectException e){
				throw new BadCredentialsException("incorrect credentials", e);
			}
		}
		throw new BadCredentialsException("unsupported authentication");
	}
}
