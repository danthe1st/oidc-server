package io.github.danthe1st.oidcserver.auth.repository;

import java.util.Optional;

import io.github.danthe1st.oidcserver.auth.model.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long> {
	Optional<User> findByUsername(String username);
}
