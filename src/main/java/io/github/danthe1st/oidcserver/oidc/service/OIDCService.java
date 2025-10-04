package io.github.danthe1st.oidcserver.oidc.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.service.ClientDoesNotExistException;
import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import io.github.danthe1st.oidcserver.oidc.repository.JWTKeyRepository;
import io.github.danthe1st.oidcserver.oidc.repository.KeyRetrievalException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class OIDCService {
	
	private static final String CLIENT_ID_FIELD_NAME = "cid";
	private static final String TOKEN_TYPE_FIELD_NAME = "typ";
	
	// TODO type of token
	
	private final SecretKey secretKey;
	
	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	
	private final UserService userService;
	private final ClientService clientService;
	
	private final String issuer;
	
	public OIDCService(@Value("${jwt.issuer}") String issuer, JWTKeyRepository keyRepo, UserService userService, ClientService clientService) throws KeyRetrievalException {
		this.secretKey = keyRepo.getHS512Key();
		this.userService = userService;
		this.clientService = clientService;
		this.issuer = issuer;
		
		KeyPair eccKeyPair = keyRepo.getES512KeyPair();
		this.publicKey = eccKeyPair.getPublic();
		this.privateKey = eccKeyPair.getPrivate();
	}
	
	public String generateAuthorizationCode(Client client, User user) {
		Duration expirationDuration = Duration.ofMinutes(5);
		String subject = user.username();
		return preparePrivateJWTBuilder(expirationDuration, subject)
			.claim(CLIENT_ID_FIELD_NAME, client.clientId())
			.claim(TOKEN_TYPE_FIELD_NAME, "auth")
			.compact();
	}
	
	public VerificationResult verify(Client client, @NotNull String code) throws JWTVerificationException {
		Claims payload = parsePrivateJWT(code, "auth");
		
		String subject = payload.getSubject();
		String clientId = (String) payload.get(CLIENT_ID_FIELD_NAME);
		
		if(!client.clientId().equals(clientId)){
			throw new JWTVerificationException();
		}
		
		User user = userService.getUser(subject).orElseThrow(JWTVerificationException::new);
		return new VerificationResult(generateIDToken(client, user), generateAccessToken(client, user));
	}
	
	private String generateIDToken(Client client, User user) {// TODO use for verify
		return preparePublicJWTBuilder(Duration.ofMinutes(5), user.username())
			.audience().add(client.clientId()).and()
			// claims (more information about the user) could be added here
			.compact();
	}
	
	private String generateAccessToken(Client client, User user) {// TODO use for verify
		return preparePrivateJWTBuilder(Duration.ofMinutes(15), user.username())
			.claim(CLIENT_ID_FIELD_NAME, client.clientId())
			.claim(TOKEN_TYPE_FIELD_NAME, "access_token")
			// claims (more information about the user) could be added here
			.compact();
	}
	
	public VerifyAccessTokenResult verifyAccessToken(String jwt) throws JWTVerificationException {
		Claims claims = parsePrivateJWT(jwt, "access_token");
		
		String clientId = (String) claims.get(CLIENT_ID_FIELD_NAME);
		
		User user = userService.getUser(claims.getSubject()).orElseThrow(JWTVerificationException::new);
		
		try{
			return new VerifyAccessTokenResult(user, clientService.getClient(clientId));
		}catch(ClientDoesNotExistException e){
			throw new JWTVerificationException();
		}
	}
	
	private JwtBuilder preparePrivateJWTBuilder(Duration expirationDuration, String subject) {
		return Jwts.builder().signWith(secretKey, Jwts.SIG.HS512)
			.issuedAt(new Date())
			.subject(subject)// TODO replace with user ID in some cases?
			.expiration(Date.from(Instant.now().plus(expirationDuration)))
			.issuer(issuer);
	}
	
	private JwtBuilder preparePublicJWTBuilder(Duration expirationDuration, String subject) {
		return Jwts.builder().signWith(privateKey, Jwts.SIG.ES512)
			.issuedAt(new Date())
			.subject(subject)
			.expiration(Date.from(Instant.now().plus(expirationDuration)))
			.issuer(issuer);
	}
	
	private Claims parsePrivateJWT(String code, String expectedType) throws JWTVerificationException {
		JwtParser parser = Jwts.parser().verifyWith(secretKey).build();
		return parseJWT(code, expectedType, parser);
	}
	
//	private Claims parsePublicJWT(String code, String expectedType) throws JWTVerificationException {
//		JwtParser parser = Jwts.parser().verifyWith(publicKey).build();
//		return parseJWT(code, expectedType, parser);
//	}
	
	private Claims parseJWT(String code, String expectedType, JwtParser parser) throws JWTVerificationException {
		Claims payload;
		try{
			payload = parser.parseSignedClaims(code).getPayload();
		}catch(JwtException e){
			throw new JWTVerificationException();
		}
		
		if(!expectedType.equals(payload.get(TOKEN_TYPE_FIELD_NAME))){
			throw new JWTVerificationException();
		}
		
		return payload;
	}
	
	public String getJWK() {
		return Jwks.json(Jwks.builder().key(publicKey).idFromThumbprint().build());
	}
}
