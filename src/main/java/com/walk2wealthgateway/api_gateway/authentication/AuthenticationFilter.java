package com.walk2wealthgateway.api_gateway.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component("AuthenticationFilter")
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (!exchange.getRequest().getHeaders().containsKey("Authorization")) {
                return onError(exchange, config.getErrorMessage(), HttpStatus.UNAUTHORIZED);
            }

            String token = exchange.getRequest().getHeaders().getOrEmpty("Authorization").get(0);
            if (!token.startsWith("Bearer ")) {
                return onError(exchange, config.getErrorMessage(), HttpStatus.UNAUTHORIZED);
            }
            token = token.replace("Bearer ", "");

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(config.getSecretKey().getBytes())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String userId = claims.getSubject();
                exchange = exchange.mutate().request(
                        exchange.getRequest().mutate()
                                .header(config.getUserIdHeader(), userId)
                                .build()
                ).build();

            } catch (Exception e) {
                if (config.isLoggingEnabled()) {
                    e.printStackTrace();
                }
                return onError(exchange, config.getErrorMessage(), HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {

        @Value("${jwt.secretKey:secretKey}")
        private String secretKey;

        @Value("${jwt.userIdHeader:X-User-Id}")
        private String userIdHeader;

        @Value("${jwt.errorMessage:Invalid JWT Token}")
        private String errorMessage;

        @Value("${jwt.loggingEnabled:false}")
        private boolean loggingEnabled;

        public String getSecretKey() {
            return secretKey;
        }

        public Config setSecretKey(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public String getUserIdHeader() {
            return userIdHeader;
        }

        public Config setUserIdHeader(String userIdHeader) {
            this.userIdHeader = userIdHeader;
            return this;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public Config setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public boolean isLoggingEnabled() {
            return loggingEnabled;
        }

        public Config setLoggingEnabled(boolean loggingEnabled) {
            this.loggingEnabled = loggingEnabled;
            return this;
        }
    }
}
