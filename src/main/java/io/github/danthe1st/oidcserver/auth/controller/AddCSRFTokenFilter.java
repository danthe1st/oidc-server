package io.github.danthe1st.oidcserver.auth.controller;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

@Component
public class AddCSRFTokenFilter extends OncePerRequestFilter {
	
	private final CsrfTokenRepository tokenRepository;
	
	public AddCSRFTokenFilter(CsrfTokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if(new UrlPathHelper().getPathWithinApplication(request).startsWith("swagger-ui/")){
			DeferredCsrfToken deferredCsrfToken = tokenRepository.loadDeferredToken(request, response);
			deferredCsrfToken.get();
		}
		filterChain.doFilter(request, response);
	}
}
