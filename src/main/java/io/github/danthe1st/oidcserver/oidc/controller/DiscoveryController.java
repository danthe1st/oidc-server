package io.github.danthe1st.oidcserver.oidc.controller;

import java.util.List;

import io.github.danthe1st.oidcserver.oidc.service.OIDCService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
public class DiscoveryController {
	private final OIDCService oidcService;
	
	private final String issuer;
	private final String basePath;
	private final String internalBasePath;
	private final String oidcPath;
	private final String internalOidcPath;
	
	public DiscoveryController(OIDCService oidcService,
		@Value("${jwt.issuer}") String issuer, @Value("${server.servlet.context-path:/}") String contextPath,
		@Value("${server.url:${jwt.issuer}}") String address, @Value("${server.int_address:${server.url}}") String internalAddress) {
		this.oidcService = oidcService;
		this.issuer = issuer;
		this.basePath = address + contextPath;
		this.internalBasePath = internalAddress + contextPath;
		this.oidcPath = basePath + "oidc/";
		this.internalOidcPath = internalBasePath + "oidc/";
	}
	
	@GetMapping("/.well-known/openid-configuration")
	OIDCConfiguration getOidcConfiguration() {
		return new OIDCConfiguration(
			issuer,
			oidcPath + "authorize", internalOidcPath + "token", internalOidcPath + "userinfo", internalBasePath + "jwks",
			List.of("code", "token", "id_token"),
			List.of("public"),
			List.of("ES512"), // TODO RS256
			List.of("sub")
		);
	}
	
	@GetMapping("/jwks")
	String jwks() {
		return oidcService.getJWK();
	}
	
	record OIDCConfiguration(String issuer,
		String authorization_endpoint,
		String token_endpoint,
		String userinfo_endpoint,
		String jwks_uri,
		List<String> response_types_supported,
		List<String> subject_types_supported, // TODO find out what that is
		List<String> id_token_signing_alg_values_supported,
		List<String> claims_supported) {
	}
}
