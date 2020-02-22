package com.ekam.spring.security.multiAuthSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import com.ekam.spring.security.multiAuthSecurityApp.services.UserService;

@Configuration
@EnableWebSecurity
@Order(3)
public class SsoSecurityConfig2 extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserService userService;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.config.annotation.web.configuration.
	 * WebSecurityConfigurerAdapter#configure(org.springframework.security.
	 * config.annotation.web.builders.HttpSecurity)
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.addFilterAfter(siteMinderFilter2(), RequestHeaderAuthenticationFilter.class)
				.authenticationProvider(preAuthProvider()).authorizeRequests()
				.antMatchers("/protected2/**").authenticated()
				.antMatchers("/**").denyAll()
				.and().exceptionHandling()
				.authenticationEntryPoint(new Http403ForbiddenEntryPoint());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.config.annotation.web.configuration.
	 * WebSecurityConfigurerAdapter#configure(org.springframework.security.
	 * config.annotation.authentication.builders.AuthenticationManagerBuilder)
	 */
	@Autowired
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
		auth.authenticationProvider(preAuthProvider());
		DaoAuthenticationProvider userDetailsBasedAuthenticationProvider = new DaoAuthenticationProvider();
		userDetailsBasedAuthenticationProvider.setUserDetailsService(userService);
		auth.authenticationProvider(userDetailsBasedAuthenticationProvider);
	}

	private AuthenticationProvider preAuthProvider() {
		PreAuthenticatedAuthenticationProvider preAuthProvider = new PreAuthenticatedAuthenticationProvider();
		preAuthProvider.setPreAuthenticatedUserDetailsService(
				new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(userService));
		return preAuthProvider;
	}

	//@Autowired
	protected GenericFilterBean siteMinderFilter2() throws Exception {
		RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
		filter.setPrincipalRequestHeader("cn2"); // Default value is
		// SM_USER
		filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
		filter.setExceptionIfHeaderMissing(false);
		filter.setAuthenticationManager(authenticationManager());
		return filter;
	}

}