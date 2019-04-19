package com.hunglp.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.hunglp.security.service.MyUserDetailsService;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private MyUserDetailsService userDetailsService;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder  = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		
		//AuthenticationManager setup service user la : userDetailService
		//Setup passwordEncoder la passwordEncode
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	
	protected void configure(HttpSecurity http) throws Exception {
		//Chỉ cho phép user có quyền ADMIN truy cập đường dẫn /admin/**
		http.authorizeRequests().antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')");
		
		//Chỉ cho phép user có quyền ADMIN hoặc USER truy cập đường dẫn này
		http.authorizeRequests().antMatchers("/user/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')");
		
		//Khi người dùng đã login với vai trò USER . Nhưng truy cập vào trang cần quyền ADMIN -> chặn
		http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");
		
		//cấu hình login form
		http.authorizeRequests().and().formLogin()
			.loginProcessingUrl("/j_spring_security_long")
			.loginPage("/login")
			.defaultSuccessUrl("/user")
			.failureUrl("/login?message=error")
			.usernameParameter("username")
			.passwordParameter("password")
			
			.and().logout().logoutUrl("/j_spring_security_logout").logoutSuccessUrl("/login?message=logout");
		
		
		
	}
}
