package io.github.danthe1st.oidcserver.oidc.config;

import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties(prefix = "jwt", ignoreUnknownFields = false)
public record JWTConfig(String secret, String issuer) {
	
	// byte[] bytes = new byte[64];
	// new SecureRandom().nextBytes(bytes);
	// Base64.getEncoder().encodeToString(bytes)
	
	@ConstructorBinding
	public JWTConfig {
		Objects.requireNonNull(secret);
		Objects.requireNonNull(issuer);
	}
}
