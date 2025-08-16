package com.saiteja.CloudGateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${auth0.audience}")
    private String audience;

    private final ReactiveClientRegistrationRepository repository;

    public SecurityConfig(ReactiveClientRegistrationRepository repository) {
        this.repository = repository;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(authorizeExchangeSpec ->
                        authorizeExchangeSpec.anyExchange().authenticated())
                .oauth2Login(oAuth2LoginSpec ->
                        oAuth2LoginSpec.authorizationRequestResolver(authorizationRequestResolver(repository)))
                .oauth2ResourceServer(oAuth2 -> oAuth2.jwt(
                        jwt -> jwt.jwtAuthenticationConverter(converter())
                ));
        return http.build();
    }

    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(ReactiveClientRegistrationRepository repository) {
        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(repository);

        resolver.setAuthorizationRequestCustomizer(authBuilderCustomizer());
        return resolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authBuilderCustomizer() {
        return customizer -> customizer
                .additionalParameters(
                        params ->
                                params.put("audience", audience));
    }

    @Bean
    public ReactiveJwtAuthenticationConverterAdapter converter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            JwtGrantedAuthoritiesConverter defaultConverter =new JwtGrantedAuthoritiesConverter();
            Collection<GrantedAuthority> authorities = defaultConverter.convert(jwt);
            Collection<GrantedAuthority> customAuthorities =
                    jwt.getClaimAsStringList("https://saitejabuffer.com/roles")
                            .stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList());
            authorities.addAll(customAuthorities);
            return authorities;
        });
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}
