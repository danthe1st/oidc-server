package io.github.danthe1st.oidcserver.apps.controller;

import java.util.List;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.service.ClientDoesNotExistException;
import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.apps.service.ClientService.ClientWithSecret;
import io.github.danthe1st.oidcserver.apps.service.InvalidURLException;
import io.github.danthe1st.oidcserver.apps.service.RedirectURIDoesNotExistException;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller for managing applications and their credentials.
 */
@RestController
@RequestMapping("/apps/")
class ManageClientController {
	
	private final ClientService clientService;
	private final UserService userService;
	
	public ManageClientController(ClientService clientService, UserService userService) {
		this.clientService = clientService;
		this.userService = userService;
	}
	
	@PostMapping
	ClientCreationResponse createClient(Authentication auth, @RequestBody ClientCreationRequest request) throws InvalidURLException {
		ClientWithSecret client = clientService.createClient(userService.getCurrentUser(auth), request.appName(), request.requestURLs());
		return new ClientCreationResponse(new ClientDescription(client.client()), client.clientSecret());
	}
	
	@PostMapping("{clientId}/secret/reset")
	ClientCreationResponse resetClientSecret(Authentication auth, @PathVariable("clientId") String clientId) throws ClientDoesNotExistException {
		ClientWithSecret client = clientService.resetClientId(userService.getCurrentUser(auth), clientId);
		return new ClientCreationResponse(new ClientDescription(client.client()), client.clientSecret());
	}
	
	@DeleteMapping("{clientId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	void deleteClient(Authentication auth, @PathVariable("clientId") String clientId) throws ClientDoesNotExistException {
		clientService.deleteClient(userService.getCurrentUser(auth), clientId);
	}
	
	@GetMapping
	List<ClientDescription> getClients(Authentication auth) {
		return clientService.getClientsOfUser(userService.getCurrentUser(auth))
			.stream()
			.map(ClientDescription::new)
			.toList();
	}
	
	@PostMapping("{clientId}/redirectURIs")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	void addRedirectURI(Authentication auth, @PathVariable("clientId") String clientId, @RequestParam("redirectURI") String redirectURI) throws ClientDoesNotExistException, InvalidURLException {
		clientService.addRedirectURI(userService.getCurrentUser(auth), clientId, redirectURI);
	}
	
	@DeleteMapping("{clientId}/redirectURIs")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	void deleteRedirectURI(Authentication auth, @PathVariable("clientId") String clientId, @RequestParam("redirectURI") String redirectURI) throws ClientDoesNotExistException, RedirectURIDoesNotExistException {
		clientService.deleteRedirectURI(userService.getCurrentUser(auth), clientId, redirectURI);
	}
	
	// region exception handlers
	@ExceptionHandler(exception = ClientDoesNotExistException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public ErrorResponse handleClientNotExisting(ClientDoesNotExistException e) {
		return new ErrorResponse("The client with the specified client ID does not exist.");
	}
	
	@ExceptionHandler(exception = InvalidURLException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ErrorResponse handleInvalidURL(InvalidURLException e) {
		return new ErrorResponse(e.getMessage());
	}
	
	@ExceptionHandler(exception = RedirectURIDoesNotExistException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public ErrorResponse handleMissingRedirectURI(RedirectURIDoesNotExistException e) {
		return new ErrorResponse("The client ID is not associated with the provided redirect URI.");
	}
	// endregion
	
	// region DTOs
	record ClientCreationRequest(String appName, List<String> requestURLs) {
		
	}
	
	record ClientCreationResponse(ClientDescription client, String clientSecret) {
		
	}
	
	record ClientDescription(String clientId, String appName, List<String> redirectURLs) {
		
		public ClientDescription(Client client) {
			this(client.clientId(), client.appName(), List.copyOf(client.redirectURLs()));
		}
	}
	
	record ErrorResponse(@Nullable String message) {
	}
	// endregion
}
