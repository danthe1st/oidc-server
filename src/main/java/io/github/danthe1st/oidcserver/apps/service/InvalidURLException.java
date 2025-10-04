package io.github.danthe1st.oidcserver.apps.service;

public class InvalidURLException extends Exception {
	public InvalidURLException(String url) {
		super("The URL '" + url + "' is not a valid redirect URL.");
	}
}
