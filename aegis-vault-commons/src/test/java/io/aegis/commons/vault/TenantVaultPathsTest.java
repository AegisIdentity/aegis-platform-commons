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
    void scopes_transit_by_KEY_NAME_prefix_and_kv_by_PATH_segment() {
        // The two engines are scoped differently, and it is not arbitrary.
        //
        // A transit key name is a URL path segment and cannot contain "/", so the tenant has to be a
        // NAME PREFIX inside one shared mount. The obvious-looking alternative — a transit mount per
        // tenant — is a scaling dead end: Vault caps mounts at ~14,000 on Integrated Storage and
        // every additional mount lengthens leadership transfer, so a per-tenant mount puts a hard
        // ceiling on tenant count and degrades failover long before reaching it.
        //
        // KV v2 genuinely supports nested paths, so there the tenant is a path segment.
        TenantContext.set(TenantId.of("acme"));

        assertThat(paths.transitKey("token-signing")).isEqualTo("aegis/transit/keys/acme-token-signing");
        assertThat(paths.transitSign("token-signing")).isEqualTo("aegis/transit/sign/acme-token-signing");
        assertThat(paths.kv("datasource/password")).isEqualTo("aegis/kv/data/acme/datasource/password");
        assertThat(paths.pkiIssue("workload")).isEqualTo("aegis/pki/issue/acme-workload");
    }

    @Test
    void one_shared_mount_per_engine_so_tenant_count_is_not_capped_by_vault_mount_limits() {
        TenantContext.set(TenantId.of("acme"));
        // No tenant appears before the engine name — that is what keeps this a single mount.
        assertThat(paths.transitKey("k")).startsWith("aegis/transit/");
        assertThat(paths.kv("k")).startsWith("aegis/kv/");
        assertThat(paths.pkiIssue("k")).startsWith("aegis/pki/");
    }

    @Test
    void two_tenants_never_share_a_path() {
        TenantContext.set(TenantId.of("acme"));
        String acme = paths.transitKey("k");
        TenantContext.set(TenantId.of("globex"));
        String globex = paths.transitKey("k");

        assertThat(acme).isNotEqualTo(globex);
        assertThat(globex).doesNotContain("acme");
        assertThat(acme).isEqualTo("aegis/transit/keys/acme-k");
        assertThat(globex).isEqualTo("aegis/transit/keys/globex-k");
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
    void allows_hierarchical_KV_paths_but_not_hierarchical_transit_key_names() {
        // KV nests; transit does not, because a transit key name is a single URL path segment.
        // Accepting a "/" in a transit key name would silently produce a path Vault routes
        // somewhere else entirely.
        TenantContext.set(TenantId.of("acme"));
        assertThatThrownBy(() -> paths.transitKey("tenant-managed/my-key"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(paths.kv("app/prod/db.password"))
                .isEqualTo("aegis/acme/kv/data/app/prod/db.password".replace("acme/kv", "kv")
                        .replace("aegis/kv/data/", "aegis/kv/data/acme/"));
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
    void namespace_isolation_drops_the_tenant_prefix_because_the_namespace_already_carries_it() {
        // Vault Enterprise puts the tenant in a namespace header. Keeping the name prefix as well
        // would produce acme-token-signing INSIDE namespace acme/ — correct but confusing, and it
        // would make the two isolation modes produce different key names for the same logical key.
        TenantVaultPaths ns = new TenantVaultPaths("aegis", VaultIsolation.NAMESPACE);
        TenantContext.set(TenantId.of("acme"));

        assertThat(ns.transitKey("token-signing")).isEqualTo("aegis/transit/keys/token-signing");
        assertThat(ns.kv("datasource")).isEqualTo("aegis/kv/data/datasource");
        assertThat(ns.namespace()).isEqualTo("acme");
    }

    @Test
    void path_isolation_has_no_namespace() {
        TenantContext.set(TenantId.of("acme"));
        assertThat(paths.namespace()).isNull();
    }
}
