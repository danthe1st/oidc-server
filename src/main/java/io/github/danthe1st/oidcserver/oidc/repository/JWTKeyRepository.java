package io.github.danthe1st.oidcserver.oidc.repository;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

@Repository
public class JWTKeyRepository {
	
	private final Path keyStorePath;
	private @Nullable KeyStore keyStore;
	
	public JWTKeyRepository(@Value("${SERVER_DIRECTORY:.}/keys.jks") String keyStoreDirectory) {
		this.keyStorePath = Path.of(keyStoreDirectory);
	}
	
	public KeyPair getES512KeyPair() throws KeyRetrievalException {
		try{
			return getKeyPair(Jwts.SIG.ES512);
		}catch(NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e){
			throw new KeyRetrievalException(e);
		}
	}
	
	public SecretKey getHS512Key() throws KeyRetrievalException {
		try{
			return getSecretKey(Jwts.SIG.HS512);
		}catch(UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e){
			throw new KeyRetrievalException(e);
		}
	}
	
	@PostConstruct
	void loadKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		if(Files.exists(keyStorePath)){
			keyStore = KeyStore.getInstance(keyStorePath.toFile(), new char[0]);
		}else{
			generateKeyStore();
		}
	}
	
	private void generateKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
		KeyStore store = KeyStore.getInstance("JCEKS");
		store.load(null, null);
		
		addNewKeyPairToKeyStore(store, Jwts.SIG.ES512);
		addNewSingleKeyPairToKeyStore(store, Jwts.SIG.HS512);
		
		try(OutputStream os = new BufferedOutputStream(Files.newOutputStream(keyStorePath))){
			store.store(os, new char[0]);// TODO use password for keys
		}
		this.keyStore = store;
		
	}
	
	private void addNewKeyPairToKeyStore(KeyStore store, SignatureAlgorithm alg) throws KeyStoreException, CertificateException, OperatorCreationException, NoSuchAlgorithmException {
		KeyPair pair = alg.keyPair().build();
		
		// public key cannot be stored in key pair, only as a certificate
		// so we need to generate a mock cert holding the public key
		// https://stackoverflow.com/a/74782456/10871900
		KeyPairGenerator mockCertSigningKeyGen = KeyPairGenerator.getInstance("RSA");
		mockCertSigningKeyGen.initialize(2048);
		X509CertificateHolder mockCertHolder = new X509v3CertificateBuilder(
			new X500Name("CN=a"), BigInteger.ONE,
			new Date(), new Date(),
			new X500Name("CN=a"),
			SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
		).build(new JcaContentSignerBuilder("SHA256WithRSA").build(mockCertSigningKeyGen.generateKeyPair().getPrivate()));
		
		store.setKeyEntry(
			alg.getId(), pair.getPrivate(), new char[0],
			new Certificate[] { new JcaX509CertificateConverter().getCertificate(mockCertHolder) }
		);
	}
	
	private SecretKey getSecretKey(MacAlgorithm alg) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		if(keyStore != null && keyStore.getKey(alg.getId(), new char[0]) instanceof SecretKey key){
			return key;
		}
		throw new UnrecoverableKeyException("key not found");
	}
	
	private KeyPair getKeyPair(SignatureAlgorithm alg) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		if(keyStore != null && keyStore.getEntry(alg.getId(), new KeyStore.PasswordProtection(new char[0])) instanceof PrivateKeyEntry entry){
			return new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
		}
		throw new UnrecoverableEntryException("key pair not found");
	}
	
	private void addNewSingleKeyPairToKeyStore(KeyStore store, MacAlgorithm alg) throws KeyStoreException {
		SecretKey secretKey = alg.key().build();
		store.setEntry(alg.getId(), new SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(new char[0]));
//		store.setKeyEntry(alg.getId(), secretKey, new char[0], null);
	}
}
