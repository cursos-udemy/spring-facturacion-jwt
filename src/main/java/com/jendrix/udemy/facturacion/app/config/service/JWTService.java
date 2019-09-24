package com.jendrix.udemy.facturacion.app.config.service;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;

public interface JWTService {

	public String create(Authentication authentication) throws IOException;

	public boolean validate(String token);

	// FIXME: depende de la interfaace de io.jsonwebtoken
	public Claims getClaims(String token);

	public String getUsername(String token);

	public Collection<? extends GrantedAuthority> getAuthorities(String token) throws IOException;

	public String resolveToken(String token);
}
