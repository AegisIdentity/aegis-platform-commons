package io.aegis.commons.vault;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Transit is where ADR-0015's central claim is realized: <b>the private key never leaves Vault</b>.
 * The application sends bytes to be signed and receives a signature, so a memory-disclosure bug in a
 * Spring service cannot yield a tenant's signing key — because the key was never in the process.
 */
class VaultTransitTest {

    private FakeVaultClient client;
    private VaultTransit transit;
    private List<AuditEvent> published;

    @BeforeEach
    void setUp() {
        client = new FakeVaultClient();
        published = new ArrayList<>();
        AuditEventPublisher audit = published::add;
        transit = new VaultTransit(client, new TenantVaultPaths("aegis", VaultIsolation.PATH), audit);
        TenantContext.set(TenantId.of("acme"));
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    private static String b64(String raw) {
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void sign_posts_base64_input_to_the_tenant_scoped_sign_path() {
        client.respondTo("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature", "vault:v1:abcdef")));

        String signature = transit.sign("token-signing", "header.payload".getBytes(StandardCharsets.UTF_8));

        assertThat(signature).isEqualTo("vault:v1:abcdef");
        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.path()).isEqualTo("aegis/transit/sign/acme-token-signing");
        assertThat(call.body().get("input"))
                .isEqualTo(Base64.getEncoder().encodeToString("header.payload".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void created_keys_are_not_exportable() {
        // The whole security argument for Vault over KMS envelope encryption collapses if a key can
        // be exported, so this is asserted rather than assumed.
        transit.createKey("tenant-managed-my-key", TransitKeyType.RSA_4096);

        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.path()).isEqualTo("aegis/transit/keys/acme-tenant-managed-my-key");
        assertThat(call.body()).containsEntry("exportable", false);
        assertThat(call.body()).containsEntry("allow_plaintext_backup", false);
        assertThat(call.body()).containsEntry("type", "rsa-4096");
    }

    @Test
    void rotate_targets_the_rotate_endpoint_and_keeps_prior_versions_verifiable() {
        transit.rotate("token-signing");
        assertThat(client.lastCall().path()).isEqualTo("aegis/transit/keys/acme-token-signing/rotate");
    }

    @Test
    void verify_reports_the_valid_flag_from_vault() {
        client.respondTo("aegis/transit/verify/acme-token-signing",
                Map.of("data", Map.of("valid", true)));

        assertThat(transit.verify("token-signing", "data".getBytes(StandardCharsets.UTF_8), "vault:v1:x"))
                .isTrue();
    }

    @Test
    void verify_is_false_when_vault_says_nothing_rather_than_defaulting_to_true() {
        // An absent or malformed response must never read as a successful verification.
        assertThat(transit.verify("token-signing", "data".getBytes(StandardCharsets.UTF_8), "vault:v1:x"))
                .isFalse();
    }

    @Test
    void encrypt_and_decrypt_round_trip_through_the_expected_paths() {
        client.respondTo("aegis/transit/encrypt/acme-data-key",
                Map.of("data", Map.of("ciphertext", "vault:v1:cipher")));
        client.respondTo("aegis/transit/decrypt/acme-data-key",
                Map.of("data", Map.of("plaintext",
                        Base64.getEncoder().encodeToString("secret".getBytes(StandardCharsets.UTF_8)))));

        assertThat(transit.encrypt("data-key", "secret".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo("vault:v1:cipher");
        assertThat(new String(transit.decrypt("data-key", "vault:v1:cipher"), StandardCharsets.UTF_8))
                .isEqualTo("secret");
    }

    // --- JWS signing: the reason Vault is on the token path at all --------------------------------

    @Test
    void signs_with_the_algorithm_and_hash_a_JWS_RS256_header_promises() {
        // RS256 means RSASSA-PKCS1-v1_5 over SHA-256. Vault defaults transit RSA signing to PSS, so
        // omitting these would produce a signature no JWT verifier on earth accepts — and the
        // failure would surface as "invalid token" everywhere rather than as a signing error here.
        client.respondTo("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature", "vault:v1:" + b64("sig"))));

        transit.signJws("token-signing", "header.payload".getBytes(StandardCharsets.UTF_8));

        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.body()).containsEntry("signature_algorithm", "pkcs1v15");
        assertThat(call.body()).containsEntry("hash_algorithm", "sha2-256");
        assertThat(call.body()).containsEntry("prehashed", false);
    }

    @Test
    void strips_the_vault_version_prefix_and_returns_raw_signature_bytes() {
        // Vault returns "vault:v<n>:<base64>". A JWS needs the raw bytes; leaving the prefix on
        // produces a token that looks well-formed and never verifies.
        client.respondTo("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature", "vault:v3:" + b64("rawsig"))));

        byte[] signature = transit.signJws("token-signing", "data".getBytes(StandardCharsets.UTF_8));

        assertThat(new String(signature, StandardCharsets.UTF_8)).isEqualTo("rawsig");
    }

    @Test
    void a_signature_without_the_vault_prefix_is_rejected_rather_than_silently_mangled() {
        client.respondTo("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature", "not-a-vault-signature")));

        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> transit.signJws("token-signing", "d".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(VaultException.class);
    }

    // --- public key: the ONLY key material that may leave Vault -----------------------------------

    @Test
    void reads_the_latest_public_key_and_its_version() {
        client.respondTo("aegis/transit/keys/acme-token-signing", Map.of("data", Map.of(
                "latest_version", 2,
                "keys", Map.of(
                        "1", Map.of("public_key", "-----BEGIN PUBLIC KEY-----\nOLD\n-----END PUBLIC KEY-----"),
                        "2", Map.of("public_key", "-----BEGIN PUBLIC KEY-----\nNEW\n-----END PUBLIC KEY-----")))));

        VaultPublicKey key = transit.publicKey("token-signing");

        assertThat(key.version()).isEqualTo(2);
        assertThat(key.pem()).contains("NEW");
    }

    @Test
    void reads_every_key_version_so_prior_versions_stay_verifiable_after_rotation() {
        // Overlapping rotation (ADR-0007) depends on this: a token signed by v1 must still verify
        // after the key rotates to v2, so JWKS has to publish both.
        client.respondTo("aegis/transit/keys/acme-token-signing", Map.of("data", Map.of(
                "latest_version", 2,
                "keys", Map.of(
                        "1", Map.of("public_key", "PEM-1"),
                        "2", Map.of("public_key", "PEM-2")))));

        assertThat(transit.publicKeyVersions("token-signing"))
                .extracting(VaultPublicKey::version)
                .containsExactly(1, 2);
    }

    @Test
    void a_key_that_does_not_exist_yields_an_empty_version_list_not_an_exception() {
        assertThat(transit.publicKeyVersions("never-created")).isEmpty();
    }

    // --- the platform non-negotiable ------------------------------------------------------------

    @Test
    void audit_records_the_key_name_but_never_key_material_signature_or_plaintext() {
        client.respondTo("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature", "vault:v1:SUPERSECRETSIGNATURE")));
        transit.sign("token-signing", "sensitive-payload".getBytes(StandardCharsets.UTF_8));

        assertThat(published).hasSize(1);
        AuditEvent event = published.get(0);
        assertThat(event.type()).isEqualTo("vault");
        assertThat(event.action()).isEqualTo("transit.sign");
        assertThat(event.target()).isEqualTo("token-signing");
        assertThat(event.tenantId()).isEqualTo("acme");

        // "Audit events must never carry secrets" is a standing platform rule; here it is enforced.
        String rendered = event.attributes().toString() + event.target();
        assertThat(rendered).doesNotContain("SUPERSECRETSIGNATURE");
        assertThat(rendered).doesNotContain("sensitive-payload");
    }

    @Test
    void namespace_isolation_passes_the_namespace_instead_of_widening_the_path() {
        FakeVaultClient nsClient = new FakeVaultClient();
        VaultTransit nsTransit = new VaultTransit(
                nsClient, new TenantVaultPaths("aegis", VaultIsolation.NAMESPACE), event -> { });

        nsTransit.rotate("token-signing");

        assertThat(nsClient.lastCall().path()).isEqualTo("aegis/transit/keys/token-signing/rotate");
        assertThat(nsClient.lastCall().namespace()).isEqualTo("acme");
    }
}
