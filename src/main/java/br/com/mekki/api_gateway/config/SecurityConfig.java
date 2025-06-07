package br.com.mekki.api_gateway.config;

import br.com.mekki.api_gateway.config.filters.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity // Habilita o Spring Security para ambientes reativos (WebFlux)
public class SecurityConfig {


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Desabilita CSRF (Cross-Site Request Forgery) - comum para APIs RESTful
                .authorizeExchange(exchange ->
                        exchange

                                .pathMatchers("/auth/**").permitAll()
                                .pathMatchers("/user/listall").hasRole("ADMIN")
                                .anyExchange().authenticated()
                )

                .httpBasic(httpBasic -> httpBasic.disable()) // Desabilitado para não forçar HTTP Basic na primeira fase.


                .formLogin(formLogin -> formLogin.disable()) // Desabilita o formulário de login padrão
                .addFilterBefore(new JwtAuthenticationFilter(),
                        SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        // Retorna um usuário dummy. O passwordEncoder {noop} significa sem codificação.
        return username -> Mono.just(User.withUsername(username).password("{noop}").roles("NONE").build());
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService userDetailsService) {
        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    }

}
