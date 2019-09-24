package com.jendrix.udemy.facturacion.app.config.filter;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jendrix.udemy.facturacion.app.config.service.JWTService;
import com.jendrix.udemy.facturacion.app.config.service.impl.JWTServiceImpl;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	private JWTService jwtService;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

		String username = obtainUsername(request);
		String password = obtainPassword(request);

		if (username == null && password == null) {
			try {
				InputStream bodyJson = request.getInputStream();
				com.jendrix.udemy.facturacion.app.model.entity.User usr = null;
				if (bodyJson != null) {
					usr = new ObjectMapper().readValue(bodyJson, com.jendrix.udemy.facturacion.app.model.entity.User.class);
				}
				username = usr.getUsername();
				password = usr.getPassword();
			} catch (Exception e) {
				logger.error("Error: ", e);
				throw new BadCredentialsException("Username/Password Invalid");
			}
		}

		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

		return this.authenticationManager.authenticate(authToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		String token = this.jwtService.create(authResult);
		response.addHeader(JWTServiceImpl.HEADER_AUTHORIZATION, JWTServiceImpl.TOKEN_PREFIX.concat(token));

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("timestampt", new Date().getTime());
		body.put("user", (User) authResult.getPrincipal());
		body.put("token", token);
		body.put("message", "Login successfully, welcome ".concat(authResult.getName()));

		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType("application/json");
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
			throws IOException, ServletException {
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("message", "Username or password invalid!");
		body.put("error", failed.getMessage());
		logger.error(failed);
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
	}

}
