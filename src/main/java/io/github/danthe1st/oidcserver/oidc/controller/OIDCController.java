package io.github.danthe1st.oidcserver.oidc.controller;

import java.net.URI;
import java.util.Set;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.service.ClientDoesNotExistException;
import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import io.github.danthe1st.oidcserver.oidc.service.JWTVerificationException;
import io.github.danthe1st.oidcserver.oidc.service.OIDCService;
import io.github.danthe1st.oidcserver.oidc.service.VerificationResult;
import io.github.danthe1st.oidcserver.oidc.service.VerifyAccessTokenResult;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.BindParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.util.DefaultUriBuilderFactory;

/**
 * Controller class handling the OIDC flow.
 * @see OIDCController#requestAuthorize(AuthorizeDTO, Model) GET /oidc/authorize
 * @see OIDCController#doAuthorize(AuthorizeDTO, Authentication) POST /oidc/authorize
 * @see OIDCController#verify(TokenRequest, Client) POST /oidc/token
 * @see OIDCController#userInfo(HttpServletRequest) GET /oidc/userinfo
 */
@Controller
@RequestMapping("/oidc/")
@Hidden // These endpoints should be called by an application capable of using OIDC and they are documented by /.well-known/openid-configuration
public class OIDCController {
	
	private static final String BEARER_PREFIX = "Bearer ";
	
	private final ClientService clientService;
	private final OIDCService oidcService;
	private final UserService userService;
	
	public OIDCController(ClientService clientService, OIDCService oidcService, UserService userService) {
		this.clientService = clientService;
		this.oidcService = oidcService;
		this.userService = userService;
	}
	
	/**
	 * This endpoint initiates the OIDC flow.
	 * The user can send a GET request to this endpoint with the client ID and redirect URL which prompts the user to authenticate
	 * @param authorizationInfo parameters from the request containing information about the relaying party (application initiating the authentication)
	 * @param model used to pass information to the frontend
	 * @return a {@link String} identifying the view to show
	 * @throws ClientDoesNotExistException if the client ID is invalid
	 */
	@GetMapping(value = "authorize")
	String requestAuthorize(@ModelAttribute @Valid AuthorizeDTO authorizationInfo, Model model) throws ClientDoesNotExistException {
		
		if(!authorizationInfo.getScopes().contains("openid")){
			throw new InvalidRequestException("This server only accepts openid requests");
		}
		
		Client client = clientService.getClient(authorizationInfo.clientId());
		
		checkRedirectURL(authorizationInfo, client);
		
		model.addAttribute("client", client);
		model.addAttribute("authorization_info", authorizationInfo);
		
		return "authorize";
	}
	
	/**
	 * This endpoint gets invoked when the user confirms the authorization.
	 * The user is redirected to the provided redirect URL with the authorization code.
	 * @param authorizationInfo parameters from the request containing information about the relaying party (application initiating the authentication)
	 * @param authentication identifies the current user
	 * @return A redirect to the set redirect URL including the authorization code
	 * @throws ClientDoesNotExistException if the client ID is invalid
	 */
	@PostMapping("authorize")
	String doAuthorize(@ModelAttribute @Valid AuthorizeDTO authorizationInfo, Authentication authentication) throws ClientDoesNotExistException {
		Client client = clientService.getClient(authorizationInfo.clientId());
		
		String baseRedirectURL = checkRedirectURL(authorizationInfo, client);
		
		String authorizationCode = oidcService.generateAuthorizationCode(client, userService.getCurrentUser(authentication));
		
		URI uri = new DefaultUriBuilderFactory()
			.uriString(baseRedirectURL)
			.queryParam("code", authorizationCode)
			.queryParam("state", authorizationInfo.state())
			.build();
		
		return "redirect:" + uri;
	}
	
	@PostMapping("deny")
	String denyAuthorization(@ModelAttribute AuthorizeDTO authorizationInfo) throws ClientDoesNotExistException {
		String baseRedirectURL = checkRedirectURL(authorizationInfo, clientService.getClient(authorizationInfo.clientId()));
		
		URI uri = new DefaultUriBuilderFactory()
			.uriString(baseRedirectURL)
			.queryParam("error", "invalid_request")
			.queryParam("error_description", "Login failed")
			.queryParam("state", authorizationInfo.state())
			.build();
		
		return "redirect:" + uri;
	}
	
	private String checkRedirectURL(AuthorizeDTO authorizationInfo, Client client) {
		String redirectURI = authorizationInfo.redirectURI();
		if(!client.redirectURLs().contains(redirectURI)){
			throw new InvalidRequestException("the redirect URI is invalid for this client.");
		}
		return redirectURI;
	}
	
	/**
	 * The relaying party (application initiating the authentication) requests this endpoint once it receives the authorization token.
	 * 
	 * This request needs to be authenticated with client ID and client secret
	 * @param tokenRequest Request parameters containing the authorization token and metadata
	 * @param authenticatedClient parameter proving that the client is authenticated using client ID and client secret
	 * @return The access token and ID token. The ID token proves that the user is authenticated and the access token can be used to obtain user information.
	 * @throws JWTVerificationException If there has been an issue with verifying the authorization token (e.g. the client ID does not match the authenticated client)
	 */
	@PostMapping(value = "token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	@ResponseBody
	VerificationSuccessResult verify(@ModelAttribute @Valid TokenRequest tokenRequest, @AuthenticationPrincipal Client authenticatedClient) throws JWTVerificationException {
		VerificationResult result = oidcService.verify(authenticatedClient, tokenRequest.code());
		return new VerificationSuccessResult(result.accessToken(), "Bearer", result.idToken());
	}
	
	/**
	 * This endpoint can be used with the access token from {@link OIDCController#verify /oidc/token} to obtain information about the authenticated user.
	 * The access token must be provided using Bearer authentication.
	 * @param req The request containing the access token
	 * @return information about the user the access token corresponds to
	 * @throws NotAuthenticationException if there is an issue with the access token
	 */
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST }, value = "userinfo")
	@ResponseBody
	UserInfoResponse userInfo(HttpServletRequest req) throws NotAuthenticationException {
		String authorizationHeader = req.getHeader("Authorization");
		
		if(authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)){
			throw new NotAuthenticationException();
		}
		String token = authorizationHeader.substring(BEARER_PREFIX.length());
		VerifyAccessTokenResult verificationResult;
		try{
			verificationResult = oidcService.verifyAccessToken(token);
		}catch(JWTVerificationException e){
			throw new NotAuthenticationException();
		}
		User user = verificationResult.user();
		return new UserInfoResponse(user.username(), user.username(), user.userType());
	}
	
	// region DTOs
	
	record UserInfoResponse(String sub, String name, UserType userType) {// TODO more meaningful data
	
	}
	
	record TokenRequest(
		@BindParam("grant_type") @NotNull String grantType,
		@BindParam("code") @NotNull String code,
		@BindParam("redirect_uri") String redirectURI) {
		
		public TokenRequest {
			if(!"authorization_code".equals(grantType)){
				throw new InvalidRequestException("This endpoint only supports the 'authorization_code' grant type");
			}
		}
	}
	
	record VerificationSuccessResult(String access_token, String token_type, String id_token) {
		
	}
	
	record AuthorizeDTO(
		@BindParam("response_type") @NotNull String responseType,
		@BindParam("client_id") @NotNull String clientId,
		@BindParam("redirect_uri") @NotNull String redirectURI,
		@BindParam("scope") String scope,
		@BindParam("state") String state) {
		// TODO handle nonce and other features that improve security
		public AuthorizeDTO {
			if(!"code".equals(responseType)){
				throw new InvalidRequestException("parameter 'response_type' must have value 'code'");
			}
			if(!getScopes(scope).contains("openid")){
				throw new InvalidRequestException("This server only accepts openid requests");
			}
		}
		
		public Set<String> getScopes() {
			return getScopes(scope);
		}
		
		private static Set<String> getScopes(String scope) {
			if(scope == null || scope.isEmpty()){
				return Set.of("openid");
			}
			return Set.of(scope.split(","));
		}
	}
	
	// endregion
	
	// region exception handlers
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ResponseBody
	@ExceptionHandler(exception = InvalidRequestException.class)
	@Nullable
	String handleInvalidRequest(InvalidRequestException e) {
		return e.getMessage();// TODO human error page
	}
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ResponseBody
	@ExceptionHandler(exception = ClientDoesNotExistException.class)
	@Nullable
	String handleNonexistingClient(ClientDoesNotExistException e) {
		return e.getMessage();// TODO human error page
	}
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(JWTVerificationException.class)
	@ResponseBody
	String handleJWTVerificationFailure(JWTVerificationException e) {
		return "The token could not be verified";
	}
	
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	@ExceptionHandler(NotAuthenticationException.class)
	@ResponseBody
	String handleNotAuthenticated(NotAuthenticationException e) {
		return "Unauthorized";
	}
	// endregion
}
