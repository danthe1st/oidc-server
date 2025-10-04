package io.github.danthe1st.oidcserver.apps.repository;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Gatherer;

import io.github.danthe1st.oidcserver.apps.model.Client;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class ClientRepository {
	
	private final JdbcTemplate jdbcTemplate;
	
	private final RowMapper<Client> singleURLClientMapper = (rs, _) -> {
		String redirectURL = rs.getString(5);
		Set<String> redirectURLs = new HashSet<>();
		if(redirectURL != null){
			redirectURLs.add(redirectURL);
		}
		return new Client(notNull(rs.getString(1)), notNull(rs.getString(2)), notNull(rs.getString(3)), rs.getLong(4), redirectURLs);
	};
	
	private static <T> T notNull(@Nullable T element) {
		if(element == null){
			throw new NullPointerException();
		}
		return element;
	}
	
	public ClientRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}
	
	public List<Client> findByOwner(String ownerUsername) {
		
		List<Client> explodedClients = jdbcTemplate.query("""
			SELECT c.CLIENT_ID, c.CLIENT_SECRET_HASH, c.APP_NAME,
			    c.OWNER_ID,
			    url.URL
			FROM CLIENT c
			INNER JOIN `User` us ON c.owner_id = us.id
			LEFT OUTER JOIN CLIENT_REDIRECT_URL url ON url.CLIENT_ID=c.CLIENT_ID
			WHERE us.username = ?
			ORDER BY c.CLIENT_ID ASC
			""", singleURLClientMapper, ownerUsername);
		
		return explodedClients.stream().gather(
			mergingClients()
		).map(this::withUnmodifiableRedirectURLs)
			.toList();
	}
	
	private Client withUnmodifiableRedirectURLs(Client client) {
		return new Client(client.clientId(), client.clientSecretHash(), client.appName(), client.ownerId(), Collections.unmodifiableSet(client.redirectURLs()));
	}
	
	private Gatherer<Client, ?, Client> mergingClients() {
		return Gatherer.ofSequential(
			() -> new Object() {
				@Nullable
				Client cl;
			},
			(state, elem, ds) -> {
				if(state.cl == null){
					state.cl = elem;
				}else if(state.cl.clientId().equals(elem.clientId())){
					state.cl.redirectURLs().addAll(elem.redirectURLs());
				}else{
					boolean wantsMore = ds.push(state.cl);
					state.cl = elem;
					return wantsMore;
				}
				return !ds.isRejecting();
			},
			(state, ds) -> {
				if(state.cl != null){
					ds.push(state.cl);
				}
			}
		);
	}
	
	public void addClient(Client client) {
		// TODO transaction
		jdbcTemplate.update(
			"INSERT INTO Client (CLIENT_ID, CLIENT_SECRET_HASH, APP_NAME, `OWNER_ID`) VALUES (?,?,?,?)",
			client.clientId(), client.clientSecretHash(), client.appName(), client.ownerId()
		);
		jdbcTemplate.batchUpdate(
			"INSERT INTO CLIENT_REDIRECT_URL (CLIENT_ID, URL) VALUES (?,?)",
			client.redirectURLs().stream().map(url -> new Object[] { client.clientId(), url }).toList()
		);
	}
	
	public Optional<Client> findById(String clientID) {
		List<Client> urlClients = jdbcTemplate.query("""
			SELECT c.CLIENT_ID, c.CLIENT_SECRET_HASH, c.APP_NAME,
			    c.OWNER_ID,
			    url.URL
			FROM Client c
			LEFT JOIN CLIENT_REDIRECT_URL url ON c.CLIENT_ID=url.CLIENT_ID
			WHERE c.CLIENT_ID = ?
			""", singleURLClientMapper, clientID);
		
		if(urlClients.isEmpty()){
			return Optional.empty();
		}
		
		Optional<Client> ret = Optional.empty();
		
		for(Client client : urlClients){
			ret = ret.map(first -> {
				first.redirectURLs().addAll(client.redirectURLs());
				return first;
			}).or(() -> Optional.of(client));
		}
		return ret;
	}
	
	public boolean deleteByClientIdAndOwnerId(String clientId, long ownerId) {
		jdbcTemplate.update("DELETE FROM CLIENT_REDIRECT_URL WHERE CLIENT_ID = ? AND OWNER_ID = ?", clientId, ownerId);
		return jdbcTemplate.update("DELETE FROM CLIENT WHERE CLIENT_ID = ?", clientId) > 0;
	}
	
	public boolean updateClientSecretHash(Client client) {
		return jdbcTemplate.update("UPDATE CLIENT SET CLIENT_SECRET_HASH = ? WHERE CLIENT_ID = ?", client.clientSecretHash(), client.clientId()) > 0;
	}
}
