package com.example.apigatewayservice.filter;

import java.nio.charset.StandardCharsets;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
	Environment env;
	
	public AuthorizationHeaderFilter(Environment env) {
		super(Config.class);
		this.env = env;
	}
	
	public static class Config {
		
	}

	// login -> token -> (with token) -> header(include token)
	@Override
	public GatewayFilter apply(Config config) { 
		return (exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest(); 
			
			if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
			}
			
			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer", "");
			
			if(!isJwtValid(jwt)) {
				return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
			}
			
			 return chain.filter(exchange);
		};
	}

	private boolean isJwtValid(String jwt) {
		boolean returnValue = true;
		
		String subject = null;
		
		try { 
			byte[] keyBytes = env.getProperty("token.secret").getBytes(StandardCharsets.UTF_8);
			subject = Jwts.parserBuilder()
			              .setSigningKey(Keys.hmacShaKeyFor(keyBytes))
			              .build()
			              .parseClaimsJws(jwt)
			              .getBody()
			              .getSubject();
		} catch (Exception e) {
			returnValue = false;
		}
		
		if(subject == null || subject.isEmpty()) {
			returnValue = false;
		}
		
		return returnValue;
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		
		log.error(err);
		return response.setComplete();
	}
	
	
	
}
