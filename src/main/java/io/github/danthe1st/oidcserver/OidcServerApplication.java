package io.github.danthe1st.oidcserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
public class OidcServerApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(OidcServerApplication.class, args);
	}
	
}
