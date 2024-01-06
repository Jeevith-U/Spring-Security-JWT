package com.jeevith.springsecurity.configuration;

import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class BasicAuthSecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests ->
                authorizeRequests
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/manager/**").hasRole("MANAGER")
                .anyRequest().authenticated()
        )
            .sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf().disable()
            .httpBasic(); // .formLogin();
        
        http.headers().frameOptions().sameOrigin() ; 
        
        return http.build();
    }

	/*
	 * Replaced all of these hard coded user details to the database 
	 * 
	 * @Bean public UserDetailsService userDetailsService() { PasswordEncoder
	 * encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	 * 
	 * var user = User.withUsername("user") .password(encoder.encode("password"))
	 * .roles("USER") .build();
	 * 
	 * var admin = User.withUsername("admin")
	 * .password(encoder.encode("adminPassword")) .roles("ADMIN") .build();
	 * 
	 * var manager = User.withUsername("manager")
	 * .password(encoder.encode("managerPassword")) .roles("MANAGER") .build();
	 * 
	 * return new InMemoryUserDetailsManager(user, admin, manager); }
	 */
    
    /*
     * creating our own data source
     */
    
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
//    			   .password("{noop}user")
    			   .password("user").passwordEncoder(str -> passwordEncoder().encode(str))
    			   .roles("USER") 
    			   .build();
    			  
    			  var admin = User.withUsername("admin")
//    			  .password(("{noop}admin"))
    			  .password("admin").passwordEncoder(str -> passwordEncoder().encode(str))
    			  .roles("ADMIN") 
    			  .build();
    			  
    			  var manager = User.withUsername("manager")
//    			  .password(("{noop}manager"))
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
}