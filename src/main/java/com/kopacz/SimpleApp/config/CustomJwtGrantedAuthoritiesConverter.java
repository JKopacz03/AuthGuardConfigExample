package com.kopacz.SimpleApp.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CustomJwtGrantedAuthoritiesConverter extends DelegatingJwtGrantedAuthoritiesConverter {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Extract roles
        List<String> roles = jwt.getClaimAsStringList("roles");
        Collection<GrantedAuthority> roleAuthorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        // Extract authorities
        List<String> authorities = jwt.getClaimAsStringList("authorities");
        Collection<GrantedAuthority> authorityAuthorities = authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Combine roles and authorities
        return Stream.concat(roleAuthorities.stream(), authorityAuthorities.stream())
                .collect(Collectors.toList());
    }
}
