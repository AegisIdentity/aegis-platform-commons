package io.aegis.commons.testing;

import java.util.Arrays;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;

/**
 * MockMvc helpers for exercising resource-server endpoints as an authenticated caller, with a tenant
 * claim and OAuth scopes, without minting a real token. Keeps security tests concise and consistent
 * across services.
 */
public final class AegisJwtTest {

    private AegisJwtTest() {
    }

    /** A bearer JWT for {@code subject} in {@code tenantId} carrying the given scopes. */
    public static JwtRequestPostProcessor jwtForTenant(String tenantId, String subject, String... scopes) {
        return SecurityMockMvcRequestPostProcessors.jwt()
                .jwt(jwt -> jwt
                        .subject(subject)
                        .claim("tenant", tenantId)
                        .claim("scope", String.join(" ", scopes)))
                .authorities(Arrays.stream(scopes)
                        .map(s -> (GrantedAuthority) new SimpleGrantedAuthority("SCOPE_" + s))
                        .toList());
    }
}
