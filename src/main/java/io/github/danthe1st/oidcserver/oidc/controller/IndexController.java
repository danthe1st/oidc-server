package io.github.danthe1st.oidcserver.oidc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
	@GetMapping
	String index() {
		return "redirect:/swagger-ui/index.html";
	}
}
