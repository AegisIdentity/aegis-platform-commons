package io.aegis.commons.vault;

import io.aegis.commons.tenant.TenantContext;
import java.util.regex.Pattern;

/**
 * Builds tenant-scoped Vault paths.
 *
 * <p><b>The security rule, and the reason this class exists:</b> the tenant is always <em>derived</em>
 * from {@link TenantContext} and never accepted from a caller. This is the same rule the platform
 * applies to the {@code X-Aegis-Tenant} header at the edge (ADR-0008) — tenant identity is derived,
 * never trusted from input. There is deliberately <b>no overload taking a tenant argument</b>: such
 * an overload is how cross-tenant bugs get written, because it looks harmless at the call site and
 * is impossible to audit for.
 *
 * <p><b>Why the engines are scoped differently.</b> One shared mount per engine, with the tenant
 * expressed differently depending on what the engine allows:
 *
 * <table>
 *   <tr><th>Engine</th><th>Tenant appears as</th><th>Why</th></tr>
 *   <tr><td>transit</td><td>key-name prefix — {@code acme-token-signing}</td>
 *       <td>A transit key name is a single URL path segment and cannot contain {@code /}</td></tr>
 *   <tr><td>kv-v2</td><td>path segment — {@code kv/data/acme/…}</td>
 *       <td>KV genuinely supports nested paths</td></tr>
 *   <tr><td>pki</td><td>role-name prefix — {@code acme-workload}</td>
 *       <td>Same single-segment constraint as transit</td></tr>
 * </table>
 *
 * <p>The obvious-looking alternative — a mount per tenant, {@code aegis/{tenant}/transit/…} — is a
 * scaling dead end. Vault caps mounts at roughly 14,000 on Integrated Storage, and every additional
 * mount lengthens leadership transfer, so per-tenant mounts put a hard ceiling on tenant count and
 * degrade failover long before that ceiling is reached. Isolation is achieved instead by per-tenant
 * policies globbing the name prefix ({@code path "aegis/transit/keys/acme-*"}), which costs nothing
 * and scales.
 *
 * <p>The tenant segment needs no sanitizing here because {@code TenantId} already validates against
 * {@code ^[A-Za-z0-9_-]{1,64}$} at construction — it cannot contain {@code /} or {@code ..}.
 * Re-validating would duplicate a rule that could then drift; the dependency is pinned by a test.
 */
public class TenantVaultPaths {

    /**
     * A single Vault path segment: no {@code /}, no traversal, no encoding tricks. Used for transit
     * key names and PKI role names, where a {@code /} would silently route the request elsewhere.
     */
    private static final Pattern SAFE_SEGMENT = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]*$");

    /** A KV path, where hierarchy is legitimate — but traversal still is not. */
    private static final Pattern SAFE_PATH = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._/-]*$");

    private final String mount;
    private final VaultIsolation isolation;

    public TenantVaultPaths(String mount, VaultIsolation isolation) {
        if (mount == null || mount.isBlank()) {
            throw new IllegalArgumentException("vault mount is required");
        }
        this.mount = mount;
        this.isolation = isolation == null ? VaultIsolation.PATH : isolation;
    }

    /** {@code aegis/transit/keys/{tenant}-{name}} */
    public String transitKey(String name) {
        return mount + "/transit/keys/" + scopedName(name);
    }

    public String transitKeyRotate(String name) {
        return transitKey(name) + "/rotate";
    }

    public String transitSign(String name) {
        return mount + "/transit/sign/" + scopedName(name);
    }

    public String transitVerify(String name) {
        return mount + "/transit/verify/" + scopedName(name);
    }

    public String transitEncrypt(String name) {
        return mount + "/transit/encrypt/" + scopedName(name);
    }

    public String transitDecrypt(String name) {
        return mount + "/transit/decrypt/" + scopedName(name);
    }

    /** {@code aegis/kv/data/{tenant}/{path}} — KV v2 stores data under a {@code data/} prefix. */
    public String kv(String path) {
        return mount + "/kv/data/" + scopedPath(path);
    }

    /** {@code aegis/pki/issue/{tenant}-{role}} */
    public String pkiIssue(String role) {
        return mount + "/pki/issue/" + scopedName(role);
    }

    /**
     * The Vault namespace for the current tenant, or {@code null} under {@link VaultIsolation#PATH}.
     * Callers pass this straight to {@link VaultClient}; it is ignored by Vault OSS.
     */
    public String namespace() {
        return isolation == VaultIsolation.NAMESPACE ? TenantContext.currentOrThrow().value() : null;
    }

    /**
     * Prefix a single-segment name with the tenant.
     *
     * <p>Under NAMESPACE isolation the prefix is omitted: the namespace header already carries the
     * tenant, and prefixing as well would give the same logical key a different name in each mode.
     */
    private String scopedName(String name) {
        validate(name, SAFE_SEGMENT, "vault name");
        return isolation == VaultIsolation.NAMESPACE
                ? name
                : TenantContext.currentOrThrow().value() + "-" + name;
    }

    private String scopedPath(String path) {
        validate(path, SAFE_PATH, "vault path");
        return isolation == VaultIsolation.NAMESPACE
                ? path
                : TenantContext.currentOrThrow().value() + "/" + path;
    }

    private static void validate(String value, Pattern pattern, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(what + " must not be blank");
        }
        if (!pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "unsafe " + what + ": must match " + pattern.pattern());
        }
        if (value.contains("..")) {
            // Redundant given the pattern excludes a leading dot, but traversal is the specific
            // thing this guard exists to stop, so it is checked by name rather than by implication.
            throw new IllegalArgumentException("unsafe " + what + ": traversal is not allowed");
        }
    }
}
