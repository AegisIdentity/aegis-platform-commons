package io.aegis.commons.vault;

/**
 * How tenants are separated inside Vault (ADR-0015).
 *
 * <p>Both modes exist so the same application code runs against Vault OSS and Vault Enterprise.
 * Only {@link TenantVaultPaths} knows the difference; nothing above it branches on this.
 */
public enum VaultIsolation {

    /** Vault OSS: tenant is a path segment, fenced by a generated per-tenant policy. */
    PATH,

    /** Vault Enterprise: tenant is a namespace, sent as a header; paths are tenant-free. */
    NAMESPACE
}
