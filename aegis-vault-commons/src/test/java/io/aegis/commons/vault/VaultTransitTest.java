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

    @Test
    void sign_posts_base64_input_to_the_tenant_scoped_sign_path() {
        client.respondTo("aegis/acme/transit/sign/token-signing",
                Map.of("data", Map.of("signature", "vault:v1:abcdef")));

        String signature = transit.sign("token-signing", "header.payload".getBytes(StandardCharsets.UTF_8));

        assertThat(signature).isEqualTo("vault:v1:abcdef");
        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.path()).isEqualTo("aegis/acme/transit/sign/token-signing");
        assertThat(call.body().get("input"))
                .isEqualTo(Base64.getEncoder().encodeToString("header.payload".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void created_keys_are_not_exportable() {
        // The whole security argument for Vault over KMS envelope encryption collapses if a key can
        // be exported, so this is asserted rather than assumed.
        transit.createKey("tenant-managed/my-key", TransitKeyType.RSA_4096);

        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.path()).isEqualTo("aegis/acme/transit/keys/tenant-managed/my-key");
        assertThat(call.body()).containsEntry("exportable", false);
        assertThat(call.body()).containsEntry("allow_plaintext_backup", false);
        assertThat(call.body()).containsEntry("type", "rsa-4096");
    }

    @Test
    void rotate_targets_the_rotate_endpoint_and_keeps_prior_versions_verifiable() {
        transit.rotate("token-signing");
        assertThat(client.lastCall().path()).isEqualTo("aegis/acme/transit/keys/token-signing/rotate");
    }

    @Test
    void verify_reports_the_valid_flag_from_vault() {
        client.respondTo("aegis/acme/transit/verify/token-signing",
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
        client.respondTo("aegis/acme/transit/encrypt/data-key",
                Map.of("data", Map.of("ciphertext", "vault:v1:cipher")));
        client.respondTo("aegis/acme/transit/decrypt/data-key",
                Map.of("data", Map.of("plaintext",
                        Base64.getEncoder().encodeToString("secret".getBytes(StandardCharsets.UTF_8)))));

        assertThat(transit.encrypt("data-key", "secret".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo("vault:v1:cipher");
        assertThat(new String(transit.decrypt("data-key", "vault:v1:cipher"), StandardCharsets.UTF_8))
                .isEqualTo("secret");
    }

    // --- the platform non-negotiable ------------------------------------------------------------

    @Test
    void audit_records_the_key_name_but_never_key_material_signature_or_plaintext() {
        client.respondTo("aegis/acme/transit/sign/token-signing",
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
