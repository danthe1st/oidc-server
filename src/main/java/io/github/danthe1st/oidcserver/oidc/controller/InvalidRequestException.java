package io.github.danthe1st.oidcserver.oidc.controller;

class InvalidRequestException extends RuntimeException {
	public InvalidRequestException(String message) {
		super(message);
	}
}
