package io.github.danthe1st.oidcserver.auth;

import java.util.Map;

import io.github.danthe1st.oidcserver.auth.service.BasicAuthManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
public class SecurityConfig {
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new DelegatingPasswordEncoder(
			"argon2",
			Map.of(
				"argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
			)
		);
	}
	
	@Bean
	SecurityFilterChain createFilterChain(HttpSecurity http, BasicAuthManager clientAuthManager, PersistentTokenRepository rememberMeRepo) throws Exception {
		return http
			.formLogin(l -> l.defaultSuccessUrl("/swagger-ui/index.html"))
			.authorizeHttpRequests(req -> req.requestMatchers("/admin/**").hasAnyRole("ADMIN"))
			.authorizeHttpRequests(req -> req.requestMatchers("/apps/**").hasAnyRole("USER"))
			.authorizeHttpRequests(req -> req.requestMatchers("/swagger-ui/**").authenticated())
			.authorizeHttpRequests(req -> req.requestMatchers("/v3/api-docs/**").authenticated())
			.authorizeHttpRequests(req -> req.requestMatchers("/error").permitAll())
			.authorizeHttpRequests(req -> req.requestMatchers("/login").permitAll())
			.authorizeHttpRequests(req -> req.requestMatchers("/.well-known/**").permitAll())
			.authorizeHttpRequests(req -> req.requestMatchers("/jwks").permitAll())
			.authorizeHttpRequests(req -> req.requestMatchers("/oidc/client").hasAnyRole("CLIENT"))
			.authorizeHttpRequests(req -> req.requestMatchers("/oidc/userinfo").permitAll())
			.authorizeHttpRequests(req -> req.anyRequest().authenticated())
			.csrf(
				csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
					.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
					.ignoringRequestMatchers("/oidc/token", "/oidc/userinfo")
			).rememberMe(
				r -> r
					.tokenRepository(rememberMeRepo)
			).addFilterBefore(new BasicAuthenticationFilter(clientAuthManager), AuthorizationFilter.class)
			.build();
	}
	
	@Bean
	PersistentTokenRepository rememberMeRepository(JdbcTemplate jdbcTemplate) {
		JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
		repo.setJdbcTemplate(jdbcTemplate);
		return repo;
	}
	
}
