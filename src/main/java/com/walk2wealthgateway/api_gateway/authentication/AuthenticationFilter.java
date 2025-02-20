package com.walk2wealthgateway.api_gateway.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;



@Component("AuthenticationFilter")
public class AuthenticationFilter extends AbstractGatewayFilterFactory <AbstractGatewayFilterFactory.NameConfig>{


    public AuthenticationFilter() {
        super(NameConfig.class);
    }




    @Override
    public GatewayFilter apply(NameConfig config) {
        return (exchange, chain) -> {
            if (!exchange.getRequest().getHeaders().containsKey("Authorization")) {
                return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
            }

            String token = exchange.getRequest().getHeaders().getOrEmpty("Authorization").get(0);
            if (!token.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization Header", HttpStatus.UNAUTHORIZED);
            }
            token = token.replace("Bearer ", "");

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey("SECRET_KEYS")
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String userId = claims.getSubject();
                exchange = exchange.mutate().request(
                        exchange.getRequest().mutate()
                                .header("X-User-Id", userId)
                                .build()
                ).build();

            } catch (Exception e) {
                return onError(exchange, "Invalid JWT Token", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {

    }

    }


