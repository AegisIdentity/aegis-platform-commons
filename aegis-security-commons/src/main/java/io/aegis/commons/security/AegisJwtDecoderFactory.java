package io.aegis.commons.security;

import io.aegis.commons.tenant.TenantId;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Builds a hardened {@link JwtDecoder} for Aegis resource servers so per-tenant issuer validation,
 * JWKS transport security, and {@code iss}/{@code aud}/tenant-claim checks are defined <em>once</em>
 * instead of re-implemented (and mis-implemented) per service. This is exactly the surface where a
 * gap causes cross-tenant privilege escalation.
 *
 * <p>Guarantees enforced at construction:
 * <ul>
 *   <li>the issuer and JWKS URIs must be {@code https://} — a plaintext JWKS URL lets a MitM swap
 *       signing keys and forge tokens (security review M-edge-2);</li>
 *   <li>the issuer must be present in an explicit allow-list — an unlisted issuer is rejected before
 *       any network call, so a rogue/typo issuer can never be trusted.</li>
 * </ul>
 *
 * <p>Guarantees enforced per token (in addition to signature + default timestamp validation):
 * {@code iss} equals the configured issuer, {@code aud} contains this resource server's audience, and
 * a non-blank, well-formed tenant claim is present.
 *
 * <p>Additive by design: this is a new helper. Existing services keep compiling and can adopt it
 * incrementally.
 */
public final class AegisJwtDecoderFactory {

    /** Default JWT claim carrying the tenant slug. */
    public static final String DEFAULT_TENANT_CLAIM = "tenant";

    private AegisJwtDecoderFactory() {
    }

    /**
     * Build a decoder validating {@code iss}, {@code aud}, and the default {@code tenant} claim.
     *
     * @param issuerUri       the expected token issuer (https); must be in {@code allowedIssuers}
     * @param jwkSetUri       the JWKS endpoint to fetch verification keys from (https)
     * @param audience        this resource server's own audience identifier
     * @param allowedIssuers  explicit allow-list of acceptable issuers
     */
    public static JwtDecoder create(String issuerUri, String jwkSetUri, String audience,
            Collection<String> allowedIssuers) {
        return create(issuerUri, jwkSetUri, audience, allowedIssuers, DEFAULT_TENANT_CLAIM);
    }

    /**
     * Build a decoder validating {@code iss}, {@code aud}, and a named tenant claim.
     */
    public static JwtDecoder create(String issuerUri, String jwkSetUri, String audience,
            Collection<String> allowedIssuers, String tenantClaim) {
        requireHttps(issuerUri, "issuerUri");
        requireHttps(jwkSetUri, "jwkSetUri");
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException("audience is required");
        }
        if (allowedIssuers == null || allowedIssuers.isEmpty()) {
            throw new IllegalArgumentException("an explicit issuer allow-list is required");
        }
        if (!allowedIssuers.contains(issuerUri)) {
            throw new IllegalArgumentException(
                    "issuer '" + issuerUri + "' is not in the allow-list " + allowedIssuers);
        }

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(validator(issuerUri, audience, tenantClaim));
        return decoder;
    }

    /**
     * The token validator applied by decoders from this factory: default timestamp/typ validators,
     * plus issuer, audience, and tenant-claim checks. Exposed so services (and tests) can reuse the
     * exact same rules without rebuilding a decoder.
     */
    public static OAuth2TokenValidator<Jwt> validator(String issuerUri, String audience,
            String tenantClaim) {
        String claim = (tenantClaim == null || tenantClaim.isBlank())
                ? DEFAULT_TENANT_CLAIM : tenantClaim;
        return new DelegatingOAuth2TokenValidator<>(List.of(
                JwtValidators.createDefaultWithIssuer(issuerUri),
                new JwtIssuerValidator(issuerUri),
                audienceValidator(audience),
                tenantClaimValidator(claim)));
    }

    private static OAuth2TokenValidator<Jwt> audienceValidator(String audience) {
        return jwt -> {
            List<String> aud = jwt.getAudience();
            if (aud != null && aud.contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                    "the required audience '" + audience + "' is missing", null));
        };
    }

    private static OAuth2TokenValidator<Jwt> tenantClaimValidator(String tenantClaim) {
        return jwt -> {
            Object raw = jwt.getClaim(tenantClaim);
            String value = raw == null ? null : raw.toString();
            if (value != null && !value.isBlank() && isWellFormedTenant(value)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                    "a valid '" + tenantClaim + "' claim is required", null));
        };
    }

    private static boolean isWellFormedTenant(String value) {
        try {
            TenantId.of(value);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static void requireHttps(String uri, String name) {
        Objects.requireNonNull(uri, name + " is required");
        if (!uri.toLowerCase(Locale.ROOT).startsWith("https://")) {
            throw new IllegalArgumentException(name + " must use https:// (got '" + uri + "')");
        }
    }
}
