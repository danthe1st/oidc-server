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
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springdoc.core.annotations.ParameterObject;
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
	
	@GetMapping(value = "authorize")
	String requestAuthorize(@ParameterObject @ModelAttribute @Valid AuthorizeDTO authorizationInfo, Model model) throws ClientDoesNotExistException {
		
		if(!authorizationInfo.getScopes().contains("openid")){
			throw new InvalidRequestException("This server only accepts openid requests");
		}
		
		Client client = clientService.getClient(authorizationInfo.clientId());
		
		checkRedirectURL(authorizationInfo, client);
		
		model.addAttribute("client", client);
		model.addAttribute("authorization_info", authorizationInfo);
		
		return "authorize";
	}
	
	@PostMapping("authorize")
	String doAuthorize(@ParameterObject @ModelAttribute @Valid AuthorizeDTO authorizationInfo, Authentication authentication) throws ClientDoesNotExistException {
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
	
	private String checkRedirectURL(AuthorizeDTO authorizationInfo, Client client) {
		String redirectURI = authorizationInfo.redirectURI();
		if(!client.redirectURLs().contains(redirectURI)){
			throw new InvalidRequestException("the redirect URI is invalid for this client.");
		}
		return redirectURI;
	}
	
	// TODO exclude from normal authentication and ensure Basic auth is used with client ID and client secret -> handle with AuthorizationProvider and roles
	// also exclude from CSRF protection
	@PostMapping(value = "token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	@ResponseBody
	VerificationSuccessResult verify(@ModelAttribute @Valid TokenRequest tokenRequest, @AuthenticationPrincipal Client authenticatedClient) throws ClientDoesNotExistException, JWTVerificationException {
		VerificationResult result = oidcService.verify(authenticatedClient, tokenRequest.code());
		return new VerificationSuccessResult(result.accessToken(), "Bearer", result.idToken());
	}
	
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST }, value = "userinfo") // TODO exclude from Spring security auth and CSRF
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
		@BindParam("response_type") @Parameter(example = "code") @NotNull String responseType,
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
		
		private Set<String> getScopes(String scope) {
			if(scope == null || scope.isEmpty()){
				return Set.of("openid");
			}
			return Set.of(scope.split(","));
		}
	}
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ResponseBody
	@ExceptionHandler(exception = InvalidRequestException.class)
	String handleInvalidRequest(InvalidRequestException e) {
		return e.getMessage();// TODO human error page
	}
	
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ResponseBody
	@ExceptionHandler(exception = ClientDoesNotExistException.class)
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
	
}
