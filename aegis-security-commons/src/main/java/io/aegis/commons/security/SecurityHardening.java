package io.aegis.commons.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Composable hardening helpers applied by every servlet service's {@code SecurityFilterChain}, so
 * the baseline (headers, stateless semantics, 401-not-302) is identical everywhere and reviewed once.
 *
 * <p>These methods deliberately do <em>not</em> touch {@code authorizeHttpRequests} or wire the
 * resource server — request matchers and the per-tenant issuer are service-specific, so the service
 * owns those, keeping the default-deny rule (see the hardening checklist) explicit and local.
 */
public final class SecurityHardening {

    private SecurityHardening() {
    }

    /**
     * Response security headers suitable for a JSON API or an app that serves HTML. Starts from a
     * strict CSP and tightens frame/referrer/permissions policy. Loosen the CSP only for specific,
     * justified needs rather than starting permissive.
     */
    public static HttpSecurity applyHardeningHeaders(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; "
                                + "base-uri 'self'; form-action 'self'"))
                .frameOptions(frame -> frame.deny())
                .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .permissionsPolicyHeader(pp -> pp.policy("geolocation=(), camera=(), microphone=()")));
        // X-Content-Type-Options: nosniff and HSTS are on by default — left in place.
        return http;
    }

    /**
     * Stateless bearer-token API defaults: no server session, CSRF disabled (there is no session to
     * forge against for a pure bearer API), 401 (not a 302 to a login page) for unauthenticated
     * requests. The caller still adds its {@code authorizeHttpRequests} rules and
     * {@code oauth2ResourceServer(...)} wiring.
     */
    public static HttpSecurity statelessBearerApi(HttpSecurity http) throws Exception {
        http
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http;
    }
}
