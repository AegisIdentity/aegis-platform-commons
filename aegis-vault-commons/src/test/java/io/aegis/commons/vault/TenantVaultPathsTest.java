package io.aegis.commons.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.tenant.MissingTenantException;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The single most security-critical class in this module (ADR-0016).
 *
 * <p>The rule it enforces is the same one the platform already applies to {@code X-Aegis-Tenant} at
 * the edge: <b>tenant identity is derived, never accepted</b>. A caller supplies only a leaf name;
 * the tenant segment comes from {@link TenantContext}. There is deliberately no overload that takes
 * a tenant argument, because the existence of one is how cross-tenant bugs get written.
 */
class TenantVaultPathsTest {

    private final TenantVaultPaths paths = new TenantVaultPaths("aegis", VaultIsolation.PATH);

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void templates_the_tenant_segment_from_tenant_context() {
        TenantContext.set(TenantId.of("acme"));
        assertThat(paths.transitKey("token-signing")).isEqualTo("aegis/acme/transit/keys/token-signing");
        assertThat(paths.transitSign("token-signing")).isEqualTo("aegis/acme/transit/sign/token-signing");
        assertThat(paths.kv("datasource/password")).isEqualTo("aegis/acme/kv/data/datasource/password");
        assertThat(paths.pkiIssue("workload")).isEqualTo("aegis/acme/pki/issue/workload");
    }

    @Test
    void two_tenants_never_share_a_path() {
        TenantContext.set(TenantId.of("acme"));
        String acme = paths.transitKey("k");
        TenantContext.set(TenantId.of("globex"));
        String globex = paths.transitKey("k");

        assertThat(acme).isNotEqualTo(globex);
        assertThat(globex).doesNotContain("acme");
    }

    @Test
    void refuses_to_build_a_path_with_no_tenant_in_context() {
        // Failing closed matters more here than convenience: a path without a tenant segment would
        // be a platform-wide path, reachable by whichever tenant happened to trigger it.
        assertThatThrownBy(() -> paths.transitKey("k")).isInstanceOf(MissingTenantException.class);
    }

    // --- traversal and injection ---------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
            "../globex/transit/keys/token-signing",  // climb into another tenant
            "..",
            "a/../../b",
            "/absolute",                              // escape the mount
            "name%2f..%2fother",                      // percent-encoded separator
            "name\\other",                            // backslash
            "name with space",
            "name\tother",                            // control character
            "",
            "   ",
    })
    void rejects_a_name_that_could_escape_the_tenant_prefix(String hostile) {
        TenantContext.set(TenantId.of("acme"));
        assertThatThrownBy(() -> paths.transitKey(hostile))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void allows_legitimate_hierarchical_names() {
        // Tenant-managed keys live under a sub-path, so '/' must remain legal — the check has to
        // reject traversal without rejecting hierarchy.
        TenantContext.set(TenantId.of("acme"));
        assertThat(paths.transitKey("tenant-managed/my-key"))
                .isEqualTo("aegis/acme/transit/keys/tenant-managed/my-key");
        assertThat(paths.kv("app/prod/db.password"))
                .isEqualTo("aegis/acme/kv/data/app/prod/db.password");
    }

    @Test
    void the_tenant_segment_cannot_be_hostile_because_TenantId_already_validated_it() {
        // Defence in depth is good, but duplicated validation that can drift is not. TenantId's own
        // regex (^[A-Za-z0-9_-]{1,64}$) is what makes the tenant segment safe, and this test
        // documents that dependency so nobody weakens TenantId without noticing.
        assertThatThrownBy(() -> TenantId.of("../globex")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TenantId.of("a/b")).isInstanceOf(IllegalArgumentException.class);
    }

    // --- isolation modes ------------------------------------------------------------------------

    @Test
    void namespace_isolation_omits_the_tenant_from_the_path_and_names_it_separately() {
        // Vault Enterprise puts the tenant in a namespace header instead of the path. Application
        // code must be identical either way (ADR-0015), so only these two methods differ.
        TenantVaultPaths ns = new TenantVaultPaths("aegis", VaultIsolation.NAMESPACE);
        TenantContext.set(TenantId.of("acme"));

        assertThat(ns.transitKey("token-signing")).isEqualTo("aegis/transit/keys/token-signing");
        assertThat(ns.namespace()).isEqualTo("acme");
    }

    @Test
    void path_isolation_has_no_namespace() {
        TenantContext.set(TenantId.of("acme"));
        assertThat(paths.namespace()).isNull();
    }
}
