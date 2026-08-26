package io.aegis.commons.vault;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * KV v2 wraps values in a double {@code data} envelope on read and a single one on write. Getting
 * that asymmetry wrong is the classic KV v2 bug — it silently yields nulls rather than failing — so
 * it is pinned here.
 */
class VaultSecretsTest {

    private FakeVaultClient client;
    private VaultSecrets secrets;

    @BeforeEach
    void setUp() {
        client = new FakeVaultClient();
        secrets = new VaultSecrets(client, new TenantVaultPaths("aegis", VaultIsolation.PATH));
        TenantContext.set(TenantId.of("acme"));
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void unwraps_the_kv_v2_double_data_envelope_on_read() {
        client.respondTo("aegis/acme/kv/data/datasource",
                Map.of("data", Map.of("data", Map.of("password", "s3cret", "username", "app"))));

        assertThat(secrets.get("datasource", "password")).contains("s3cret");
        assertThat(secrets.getAll("datasource"))
                .containsEntry("username", "app")
                .containsEntry("password", "s3cret");
    }

    @Test
    void wraps_values_in_a_single_data_envelope_on_write() {
        secrets.put("datasource", Map.of("password", "s3cret"));

        FakeVaultClient.Call call = client.lastCall();
        assertThat(call.path()).isEqualTo("aegis/acme/kv/data/datasource");
        assertThat(call.body()).containsKey("data");
        assertThat(call.body().get("data")).isEqualTo(Map.of("password", "s3cret"));
    }

    @Test
    void a_missing_secret_is_empty_not_an_exception() {
        assertThat(secrets.get("nope", "password")).isEmpty();
    }

    @Test
    void a_missing_key_within_an_existing_secret_is_empty() {
        client.respondTo("aegis/acme/kv/data/datasource",
                Map.of("data", Map.of("data", Map.of("username", "app"))));
        assertThat(secrets.get("datasource", "password")).isEmpty();
    }

    @Test
    void delete_targets_the_tenant_scoped_path() {
        secrets.delete("datasource");
        assertThat(client.lastCall().verb()).isEqualTo("DELETE");
        assertThat(client.lastCall().path()).isEqualTo("aegis/acme/kv/data/datasource");
    }
}
