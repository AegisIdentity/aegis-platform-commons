package io.aegis.commons.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

class AegisJwtDecoderFactoryTest {

    private static final String ISSUER = "https://auth.aegis.example/acme";
    private static final String JWKS = "https://auth.aegis.example/acme/oauth2/jwks";
    private static final String AUDIENCE = "aegis-identity-service";
    private static final List<String> ALLOWED = List.of(ISSUER, "https://auth.aegis.example/other");

    @Test
    void rejects_non_https_issuer() {
        assertThatThrownBy(() -> AegisJwtDecoderFactory.create(
                "http://auth.aegis.example/acme", JWKS, AUDIENCE, ALLOWED))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
    }

    @Test
    void rejects_non_https_jwks_uri() {
        assertThatThrownBy(() -> AegisJwtDecoderFactory.create(
                ISSUER, "http://auth.aegis.example/acme/oauth2/jwks", AUDIENCE, ALLOWED))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
    }

    @Test
    void rejects_issuer_not_in_allow_list() {
        assertThatThrownBy(() -> AegisJwtDecoderFactory.create(
                "https://auth.aegis.example/rogue", JWKS, AUDIENCE, ALLOWED))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("allow-list");
    }

    @Test
    void builds_decoder_for_valid_https_inputs() {
        JwtDecoder decoder = AegisJwtDecoderFactory.create(ISSUER, JWKS, AUDIENCE, ALLOWED);
        assertThat(decoder).isNotNull();
    }

    @Test
    void validator_accepts_token_with_matching_iss_aud_and_tenant() {
        OAuth2TokenValidatorResult result = validate(jwt -> { });
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void validator_rejects_wrong_audience() {
        OAuth2TokenValidatorResult result = validate(b -> b.audience(List.of("some-other-service")));
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void validator_rejects_missing_tenant_claim() {
        OAuth2TokenValidatorResult result = validate(b -> b.claims(c -> c.remove("tenant")));
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void validator_rejects_malformed_tenant_claim() {
        OAuth2TokenValidatorResult result = validate(b -> b.claim("tenant", "bad/tenant"));
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void validator_rejects_wrong_issuer() {
        OAuth2TokenValidatorResult result = validate(b -> b.issuer("https://auth.aegis.example/other"));
        assertThat(result.hasErrors()).isTrue();
    }

    private static OAuth2TokenValidatorResult validate(Consumer<Jwt.Builder> customizer) {
        OAuth2TokenValidator<Jwt> validator =
                AegisJwtDecoderFactory.validator(ISSUER, AUDIENCE, "tenant");
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuer(ISSUER)
                .audience(List.of(AUDIENCE))
                .claim("tenant", "acme")
                .issuedAt(Instant.now().minus(1, ChronoUnit.MINUTES))
                .expiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
        customizer.accept(builder);
        return validator.validate(builder.build());
    }
}
