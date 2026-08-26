package io.aegis.commons.vault;

import io.aegis.commons.tenant.TenantContext;
import java.util.regex.Pattern;

/**
 * Builds tenant-scoped Vault paths.
 *
 * <p><b>The security rule, and the reason this class exists:</b> the tenant segment is always
 * <em>derived</em> from {@link TenantContext} and never accepted from a caller. This is the same
 * rule the platform applies to the {@code X-Aegis-Tenant} header at the edge (ADR-0008) — tenant
 * identity is derived, never trusted from input.
 *
 * <p>There is deliberately <b>no overload taking a tenant argument</b>. Such an overload is how
 * cross-tenant bugs get written: it looks harmless at the call site and is impossible to audit for.
 * The only way to reach another tenant's path is to change {@code TenantContext}, which the request
 * filter controls.
 *
 * <p>The tenant segment itself needs no sanitizing here because {@code TenantId} already validates
 * against {@code ^[A-Za-z0-9_-]{1,64}$} at construction — it cannot contain {@code /} or {@code ..}.
 * Re-validating it here would duplicate a rule that could then drift; the dependency is instead
 * pinned by a test.
 */
public class TenantVaultPaths {

    /**
     * Leaf names may be hierarchical ({@code tenant-managed/my-key}) but must be plainly safe:
     * alphanumerics, {@code . _ -} and {@code /}, starting with an alphanumeric. This admits real
     * hierarchy while excluding traversal, absolute paths, percent-encoding, backslashes,
     * whitespace and control characters in one pass.
     */
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._/-]*$");

    private final String mount;
    private final VaultIsolation isolation;

    public TenantVaultPaths(String mount, VaultIsolation isolation) {
        if (mount == null || mount.isBlank()) {
            throw new IllegalArgumentException("vault mount is required");
        }
        this.mount = mount;
        this.isolation = isolation == null ? VaultIsolation.PATH : isolation;
    }

    /** {@code aegis/{tenant}/transit/keys/{name}} — key creation, read, and (with /rotate) rotation. */
    public String transitKey(String name) {
        return base() + "/transit/keys/" + safe(name);
    }

    public String transitKeyRotate(String name) {
        return transitKey(name) + "/rotate";
    }

    public String transitSign(String name) {
        return base() + "/transit/sign/" + safe(name);
    }

    public String transitVerify(String name) {
        return base() + "/transit/verify/" + safe(name);
    }

    public String transitEncrypt(String name) {
        return base() + "/transit/encrypt/" + safe(name);
    }

    public String transitDecrypt(String name) {
        return base() + "/transit/decrypt/" + safe(name);
    }

    /** {@code aegis/{tenant}/kv/data/{path}} — KV v2 stores data under a {@code data/} prefix. */
    public String kv(String path) {
        return base() + "/kv/data/" + safe(path);
    }

    public String pkiIssue(String role) {
        return base() + "/pki/issue/" + safe(role);
    }

    /**
     * The Vault namespace for the current tenant, or {@code null} under {@link VaultIsolation#PATH}.
     * Callers pass this straight to {@link VaultClient}; it is ignored by Vault OSS.
     */
    public String namespace() {
        return isolation == VaultIsolation.NAMESPACE ? TenantContext.currentOrThrow().value() : null;
    }

    private String base() {
        // Under NAMESPACE isolation the tenant lives in a header, so the path must NOT repeat it —
        // duplicating it there would produce aegis/acme/... inside namespace acme/.
        return isolation == VaultIsolation.NAMESPACE
                ? mount
                : mount + "/" + TenantContext.currentOrThrow().value();
    }

    private static String safe(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("vault path segment must not be blank");
        }
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException(
                    "unsafe vault path segment: must match " + SAFE_NAME.pattern());
        }
        if (name.contains("..")) {
            // Redundant given the pattern excludes a leading dot, but traversal is the specific
            // thing this method exists to stop, so it is checked by name rather than by implication.
            throw new IllegalArgumentException("unsafe vault path segment: traversal is not allowed");
        }
        return name;
    }
}
