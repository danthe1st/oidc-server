package io.github.danthe1st.oidcserver.apps.model;

import java.util.Objects;
import java.util.Set;

import org.springframework.data.annotation.Id;

public record Client(@Id String clientId, String clientSecretHash, String appName, long ownerId, Set<String> redirectURLs) {
	public Client {
		Objects.requireNonNull(clientId);
		Objects.requireNonNull(appName);
		Objects.requireNonNull(redirectURLs);
		Objects.requireNonNull(clientSecretHash);
	}
}
