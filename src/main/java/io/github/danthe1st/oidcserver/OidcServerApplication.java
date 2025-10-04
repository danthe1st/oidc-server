package io.github.danthe1st.oidcserver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import io.github.danthe1st.oidcserver.apps.service.ClientService;
import io.github.danthe1st.oidcserver.apps.service.ClientService.ClientWithSecret;
import io.github.danthe1st.oidcserver.apps.service.InvalidURLException;
import io.github.danthe1st.oidcserver.auth.model.User;
import io.github.danthe1st.oidcserver.auth.model.UserType;
import io.github.danthe1st.oidcserver.auth.repository.UserRepository;
import io.github.danthe1st.oidcserver.auth.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
public class OidcServerApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(OidcServerApplication.class, args);
	}
	
	@Bean
	ApplicationListener<ApplicationReadyEvent> readyListener(UserService userService, UserRepository userRepo, PasswordEncoder passwordEncoder, ClientService clientService,
		@Value("${sample.app.credential_file:}") String sampleAppCredentialFile, @Value("${sample.app.redirect_url:}") String sampleAppRedirectURL) {
		return _ -> {
			if(userService.getUser("admin").isEmpty()){
				User admin = userRepo.save(new User(0, "admin", passwordEncoder.encode("admin"), UserType.ADMIN));
				if(sampleAppCredentialFile != null && !sampleAppCredentialFile.isEmpty()){
					try{
						ClientWithSecret clientWithSecret = clientService.createClient(admin, "sample-app", List.of(sampleAppRedirectURL));
						Files.writeString(
							Path.of(sampleAppCredentialFile),
							"""
								client.id=%s
								client.secret=%s
								""".formatted(clientWithSecret.client().clientId(), clientWithSecret.clientSecret())
						);
					}catch(InvalidURLException | IOException e){
						throw new RuntimeException(e);
					}
				}
			}
		};
	}
}
