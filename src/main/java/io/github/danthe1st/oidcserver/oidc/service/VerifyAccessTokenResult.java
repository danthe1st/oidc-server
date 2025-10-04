package io.github.danthe1st.oidcserver.oidc.service;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.auth.model.User;

public record VerifyAccessTokenResult(User user, Client client) {
	
}
