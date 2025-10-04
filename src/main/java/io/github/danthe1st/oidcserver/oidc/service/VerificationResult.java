package io.github.danthe1st.oidcserver.oidc.service;

import java.util.Objects;

public record VerificationResult(String idToken, String accessToken) {
	public VerificationResult {
		Objects.requireNonNull(idToken);
		Objects.requireNonNull(accessToken);
	}
}
