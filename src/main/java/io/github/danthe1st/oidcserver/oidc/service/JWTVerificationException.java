package io.github.danthe1st.oidcserver.oidc.service;

public class JWTVerificationException extends Exception {
	JWTVerificationException() {
	}
	
	JWTVerificationException(String message) {
		super(message);
	}
}
