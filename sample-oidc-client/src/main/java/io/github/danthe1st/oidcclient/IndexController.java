package io.github.danthe1st.oidcclient;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
	@GetMapping("/username")
	String userInfo(Authentication authentication) {
		return authentication.getName();
	}
}
