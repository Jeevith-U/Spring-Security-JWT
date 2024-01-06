package com.jeevith.springsecurity.JWTconfiguration;

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class JWTAuthenticationResource {
	
	private JwtEncoder encoder ;
	
	public JWTAuthenticationResource(JwtEncoder encoder) {
		this.encoder = encoder ;
	}
	
	@PostMapping("authenticate")
 	public JwtResponse authenticate(Authentication authentication) {
		
		return new JwtResponse(createToken(authentication)) ;
	}

	public String createToken(Authentication authentication) {
		var claims = JwtClaimsSet.builder()
						.issuer("self")
						.issuedAt(Instant.now())
						.expiresAt(Instant.now().plusSeconds(60 * 30))
						.subject(authentication.getName())
						.claim("scope", createScope(authentication))
						.build() ;
		
		JwtEncoderParameters paramters = JwtEncoderParameters.from(claims ) ;
						return encoder.encode(paramters).getTokenValue()	;
	}

	public String createScope(Authentication authentication) {
		
		return  authentication
				.getAuthorities().stream()
				.map(a -> a.getAuthority())
				.collect(Collectors.joining(" ")) ;
	}
}

record JwtResponse(String token) {}