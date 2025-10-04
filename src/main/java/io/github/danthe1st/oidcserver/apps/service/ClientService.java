package io.github.danthe1st.oidcserver.apps.service;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.repository.ClientRepository;
import io.github.danthe1st.oidcserver.auth.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class ClientService {
	
	private static final Pattern REDIRECT_URL_PATTERN = Pattern.compile("^https?://[^?#&@]+$");
	
	private final ClientRepository clientRepo;
	private final PasswordEncoder passwordEncoder;
	private final SecureRandom secureRandom = new SecureRandom();
	
	public ClientService(ClientRepository clientRepo, PasswordEncoder passwordEncoder) {
		this.clientRepo = clientRepo;
		this.passwordEncoder = passwordEncoder;
	}
	
	public ClientWithSecret resetClientId(User user, String clientId) throws ClientDoesNotExistException {
		Client client = clientRepo.findById(clientId)
			.filter(cl -> cl.ownerId() == user.id())
			.orElseThrow(ClientDoesNotExistException::new);
		String secret = generateSecret();
		client = new Client(client.clientId(), passwordEncoder.encode(secret), client.appName(), client.ownerId(), client.redirectURLs());
		clientRepo.updateClientSecretHash(client);
		return new ClientWithSecret(client, secret);
	}
	
	public ClientWithSecret createClient(User user, String appName, List<String> redirectURLs) throws InvalidURLException {
		
		validateRedirectURLs(redirectURLs);
		
		String clientSecret = generateSecret();
		Client client = new Client(UUID.randomUUID().toString(), passwordEncoder.encode(clientSecret), appName, user.id(), new HashSet<>(redirectURLs));
		
		clientRepo.addClient(client);
		
		return new ClientWithSecret(client, clientSecret);
	}
	
	private void validateRedirectURLs(Collection<String> urls) throws InvalidURLException {
		for(String url : urls){
			validateRedirectURL(url);
		}
	}
	
	private void validateRedirectURL(String url) throws InvalidURLException {
		if(!REDIRECT_URL_PATTERN.matcher(url).matches()){
			throw new InvalidURLException(url);
		}
		try{
			new URI(url).toURL();
		}catch(MalformedURLException | URISyntaxException | IllegalArgumentException _){
			throw new InvalidURLException(url);
		}
	}
	
	public Client authenticate(String clientId, String clientSecret) throws ClientDoesNotExistException, ClientSecretIncorrectException {
		Client client = getClient(clientId);
		if(passwordEncoder.matches(clientSecret, client.clientSecretHash())){
			return client;
		}
		throw new ClientSecretIncorrectException();
	}
	
	public Client getClient(String clientId) throws ClientDoesNotExistException {
		return clientRepo.findById(clientId).orElseThrow(ClientDoesNotExistException::new);
	}
	
	public void deleteClient(User user, String clientId) throws ClientDoesNotExistException {
		if(!clientRepo.deleteByClientIdAndOwnerId(clientId, user.id())){
			throw new ClientDoesNotExistException();
		}
	}
	
	private String generateSecret() {
		byte[] bytes = new byte[64];
		secureRandom.nextBytes(bytes);
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	public List<Client> getClientsOfUser(User owner) {
		return clientRepo.findByOwner(owner.username());
	}
	
	public record ClientWithSecret(Client client, String clientSecret) {
		public ClientWithSecret {
			Objects.requireNonNull(client);
			Objects.requireNonNull(clientSecret);
		}
	}
}
