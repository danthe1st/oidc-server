package io.github.danthe1st.oidcserver.oidc.controller;

import java.util.List;

import io.github.danthe1st.oidcserver.oidc.service.OIDCService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiscoveryController {
	// TODO well known/discovery URL
	
	private final OIDCService oidcService;
	
	private final String issuer;
	private final String basePath;
	private final String oidcPath;
	
	public DiscoveryController(OIDCService oidcService,
		@Value("${jwt.issuer}") String issuer, @Value("${server.servlet.context-path:/}") String contextPath,
		@Value("${server.address:http://localhost:8080}") String address) {
		this.oidcService = oidcService;
		this.issuer = issuer;
		this.basePath = address + contextPath;
		this.oidcPath = basePath + "oidc/";
	}
	
	@GetMapping("/.well-known/openid-configuration")
	OIDCConfiguration getOidcConfiguration() {
		return new OIDCConfiguration(
			issuer,
			oidcPath + "authorize", oidcPath + "token", oidcPath + "userinfo", basePath + "jwks",
			List.of("code", "token", "id_token"),
			List.of("public"),
			List.of("ES512")// TODO RS256
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
		List<String> id_token_signing_alg_values_supported) {
	}
}
