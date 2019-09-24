package com.jendrix.udemy.facturacion.app.config.service.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jendrix.udemy.facturacion.app.config.service.JWTService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JWTServiceImpl implements JWTService {

	private static final long TIME_EXPIRATION = (3600000 * 2);
	private static final String SECRET = Base64Utils.encodeToString("algunaLlaveSecreta11111111111111111111111".getBytes());
	private static final SecretKey SECRET_KEY = new SecretKeySpec(SECRET.getBytes(), SignatureAlgorithm.HS512.getJcaName());

	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_AUTHORIZATION = "Authorization";

	@Override
	public String create(Authentication authentication) throws IOException {
		User user = (User) authentication.getPrincipal();

		Claims claims = Jwts.claims();
		List<String> roles = new ArrayList<>();
		authentication.getAuthorities().forEach(rol -> {
			roles.add(rol.getAuthority());
		});

		claims.put("roles", new ObjectMapper().writeValueAsString(roles));

		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(user.getUsername())
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + TIME_EXPIRATION))
				.signWith(SECRET_KEY)
				.compact();
		return token;
	}

	@Override
	public boolean validate(String token) {
		try {
			return getClaims(token) != null ? true : false;
		} catch (JwtException | IllegalArgumentException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public Claims getClaims(String token) {
		return Jwts.parser()
				.setSigningKey(SECRET_KEY)
				.parseClaimsJws(resolveToken(token))
				.getBody();
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities(String token) throws IOException {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		String[] roles = new ObjectMapper().readValue(getClaims(token).get("roles").toString().getBytes(), String[].class);
		for (String rol : roles) {
			authorities.add(new SimpleGrantedAuthority(rol));
		}
		return authorities;
	}

	@Override
	public String resolveToken(String token) {
		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.substring(7);
		}
		return null;
	}

}
