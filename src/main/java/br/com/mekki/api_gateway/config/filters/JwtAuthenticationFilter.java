package br.com.mekki.api_gateway.config.filters;

import br.com.mekki.api_gateway.config.TokenAuthenticator;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    public static final String HEADER_STRING = "Token"; // Cabeçalho padrão para o token


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (path.startsWith("/auth") || path.startsWith("/user/register")) {
            return chain.filter(exchange);
        }


        String token = exchange.getRequest().getHeaders().getFirst(HEADER_STRING);
        System.out.println(token);

        try {

            Claims claims = TokenAuthenticator.validateToken(token);

            String user = claims.getSubject();

            Integer userId = claims.get("username", Integer.class);

            String roles = claims.get("authorities", String.class);
            List<GrantedAuthority> grantedAuths = AuthorityUtils.commaSeparatedStringToAuthorityList(roles);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user, null, grantedAuths);

            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", user) // ID do usuário
                    .header("X-id", userId.toString()) // Roles como string separada por vírgulas
                    // Opcional: Se os serviços de backend precisarem do token original, envie-o
                    // .header("X-Auth-Token", token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));


        } catch (Exception e) {
            // Captura qualquer outra exceção e retorna 401
            System.err.println("Erro durante o processamento do JWT: " + e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
//    @Bean
//    public ReactiveUserDetailsService userDetailsService() {
//        return username -> Mono.just(User.withUsername(username).password("{noop}").roles("NONE").build());
//    }
//
//    // O AuthenticationManager é necessário para o AuthenticationWebFilter
//    @Bean
//    public ReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService userDetailsService) {
//        // Não vamos usar um PasswordEncoder aqui, pois a senha é validada pelo Auth Service
//        // e o token é validado pelo JwtUtil. Este é um manager "dummy" para satisfazer a cadeia.
//        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
//    }
}
