package com.jeevith.springsecurity.JWTconfiguration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//@Configuration
public class JWT_Security_Configuration {
	
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
        )
            .sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf().disable()
            .httpBasic(); // .formLogin();
        
        http.headers().frameOptions().sameOrigin() ; 
        
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt) ;
        return http.build();
    }

    
    @Bean
    public DataSource dataSourceI() {
    	return new EmbeddedDatabaseBuilder()
    			.setType(EmbeddedDatabaseType.H2)
    			.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
    			.build() ;
    }
    
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
    	
    	var user = User.withUsername("user") 
    			   .password("user").passwordEncoder(str -> passwordEncoder().encode(str))
    			   .roles("USER") 
    			   .build();
    			  
    			  var admin = User.withUsername("admin")
    			  .password("admin").passwordEncoder(str -> passwordEncoder().encode(str))
    			  .roles("ADMIN") 
    			  .build();
    			  
    			  var manager = User.withUsername("manager")
    			  .password("manager").passwordEncoder(str -> passwordEncoder().encode(str))
    			  .roles("MANAGER")
    			  .build();
    			  
    			  var jdbcUserDetailsManager =  new JdbcUserDetailsManager(dataSource) ;
    			  jdbcUserDetailsManager.createUser(user);
    			  jdbcUserDetailsManager.createUser(admin);
    			  jdbcUserDetailsManager.createUser(manager);
    			  
    			  return jdbcUserDetailsManager ; 
    }
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
    	
    	return new BCryptPasswordEncoder() ;
    }
    
    
    
    
    /*
     * we are genarating the key pair 
     */
    
    @Bean
    public KeyPair keyPair()  {
    	
    	try {
	    	var keyPairGenarator = KeyPairGenerator.getInstance("RSA") ; // specfiying algo
	    	keyPairGenarator.initialize(2048);
	    	return keyPairGenarator.generateKeyPair() ;
    	} catch (Exception e) {
			throw new RuntimeException(e) ;
		}
    	
    }
    
    /*
     * creating RSA Key
     */
    
    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
    	
    	return new RSAKey
         .Builder((RSAPublicKey)keyPair.getPublic())
    	 .privateKey(keyPair.getPrivate())
    	 .keyID(UUID.randomUUID().toString())
    	 .build() ;
    }
    
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
    	var jwkSet = new JWKSet(rsaKey) ;
    	
    	/*var jwkSource = new JWKSource() {
    		
    		@Override
    		public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {

    			return jwkSelector.select(jwkSet);
    		}
		};
		* we can simplify all of these code using lamda Expression 
		*/
    	
    	return (jwkSelector,context ) -> jwkSelector.select(jwkSet);
    }
    
    /*
     * what we do is we will send the JWT token in headder by encoding it 
     * to understand that we need a decoder that's what we are defining here
     */
    @Bean
    public JwtDecoder jwtEncoder(RSAKey rsaKey) throws JOSEException {
    	return NimbusJwtDecoder
    			.withPublicKey(rsaKey.toRSAPublicKey())
    			.build() ;
    }
    
    @Bean
    public JwtEncoder encoder(JWKSource<SecurityContext> jwkSource) {
    	return new NimbusJwtEncoder(jwkSource) ;
    }
}
