package io.github.danthe1st.oidcserver.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.Set;

import io.github.danthe1st.oidcserver.apps.model.Client;
import io.github.danthe1st.oidcserver.apps.service.ClientDoesNotExistException;
import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import io.github.danthe1st.oidcserver.oidc.repository.JWTKeyRepository;
import io.github.danthe1st.oidcserver.oidc.repository.KeyRetrievalException;
import io.github.danthe1st.oidcserver.oidc.service.JWTVerificationException;
import io.github.danthe1st.oidcserver.oidc.service.OIDCService;
import io.github.danthe1st.oidcserver.oidc.service.VerificationResult;
import io.github.danthe1st.oidcserver.oidc.service.VerifyAccessTokenResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OIDCServiceTests {
	
	@Mock
	private ClientService clientService;
	@Mock
	private UserService userService;
	@TempDir
	private Path tempDir;
	
	private OIDCService oidcService;
	private JWTKeyRepository keyRepo;
	
	@BeforeEach
	void init() throws KeyRetrievalException, KeyStoreException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
		keyRepo = new JWTKeyRepository(tempDir + "/keystore.jks");
		keyRepo.loadKeyStore();
		oidcService = new OIDCService("", keyRepo, userService, clientService);
	}
	
	@Test
	void testNormalAuthorizationFlow() throws JWTVerificationException, KeyRetrievalException, ClientDoesNotExistException {
		User user = new User(0, "someUser", "pwdHash", UserType.USER);
		Client client = new Client("id", "hash", "app", 0, Set.of());
		String authorizationCode = oidcService.generateAuthorizationCode(client, user);
		
		when(userService.getUser(user.username())).thenReturn(Optional.of(user));
		VerificationResult idAndAccessToken = oidcService.verify(client, authorizationCode);
		
		Claims parsedIdToken = Jwts.parser().verifyWith(keyRepo.getES512KeyPair().getPublic()).build()
			.parseSignedClaims(idAndAccessToken.idToken()).getPayload();
		
		assertEquals(user.username(), parsedIdToken.getSubject());
		assertTrue(parsedIdToken.getAudience().contains(client.clientId()));
		
		when(clientService.getClient(client.clientId())).thenReturn(client);
		VerifyAccessTokenResult foundUserAndClient = oidcService.verifyAccessToken(idAndAccessToken.accessToken());
		assertEquals(user, foundUserAndClient.user());
		assertEquals(client, foundUserAndClient.client());
	}
	
	@Test
	void testInvalidAuthorizationCode() {
		Client client = new Client("id", "hash", "app", 0, Set.of());
		JWTVerificationException e = assertThrows(JWTVerificationException.class, () -> oidcService.verify(client, "invalid"));
		assertEquals("JWT parsing failed", e.getMessage());
	}
	
	@Test
	void testAuthorizationCodeFromIncorrectClient() {
		User user = new User(0, "someUser", "pwdHash", UserType.USER);
		Client client = new Client("id", "hash", "app", 0, Set.of());
		String authorizationCode = oidcService.generateAuthorizationCode(client, user);
		
		Client otherClient = new Client("otherId", "hash", "app", 0, Set.of());
		JWTVerificationException e = assertThrows(JWTVerificationException.class, () -> oidcService.verify(otherClient, authorizationCode));
		assertEquals("incorrect client", e.getMessage());
	}
	
	@Test
	void testIncorrectAccessToken() {
		JWTVerificationException e = assertThrows(JWTVerificationException.class, () -> oidcService.verifyAccessToken("invalid"));
		assertEquals("JWT parsing failed", e.getMessage());
	}
	
	@Test
	void testUseAuthorizationCodeAsAccessToken() {
		
		User user = new User(0, "someUser", "pwdHash", UserType.USER);
		Client client = new Client("id", "hash", "app", 0, Set.of());
		String authorizationCode = oidcService.generateAuthorizationCode(client, user);
		
		JWTVerificationException e = assertThrows(JWTVerificationException.class, () -> oidcService.verifyAccessToken(authorizationCode));
		assertEquals("incorrect token type", e.getMessage());
	}
	
	@Test
	void testUseAccessTokenAndIdTokenAsAuthorizationToken() throws JWTVerificationException {
		User user = new User(0, "someUser", "pwdHash", UserType.USER);
		Client client = new Client("id", "hash", "app", 0, Set.of());
		String authorizationCode = oidcService.generateAuthorizationCode(client, user);
		
		when(userService.getUser(user.username())).thenReturn(Optional.of(user));
		VerificationResult idAndAccessToken = oidcService.verify(client, authorizationCode);
		
		JWTVerificationException e = assertThrows(JWTVerificationException.class, () -> oidcService.verify(client, idAndAccessToken.accessToken()));
		assertEquals("incorrect token type", e.getMessage());
		
		e = assertThrows(JWTVerificationException.class, () -> oidcService.verify(client, idAndAccessToken.idToken()));
		assertEquals("JWT parsing failed", e.getMessage());
	}
	
	@Test
	void testGetJWK() throws KeyRetrievalException {
		String jwk = oidcService.getJWK();
		Jwk<?> parsed = Jwks.parser().build().parse(jwk);
		assertEquals("EC", parsed.getType());
		assertEquals(parsed.toKey(), keyRepo.getES512KeyPair().getPublic());
	}
}
