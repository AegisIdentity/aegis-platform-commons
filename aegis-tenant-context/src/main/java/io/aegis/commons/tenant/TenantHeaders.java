package io.aegis.commons.tenant;

/** Wire constants for tenant propagation. */
public final class TenantHeaders {

    /**
     * Internal header carrying the resolved tenant id between the edge gateway and services.
     *
     * <p>Trust rule (see ARCHITECTURE.md §5.1 / §8): this header is authoritative only on
     * mTLS-authenticated internal connections. At the public edge the tenant is always
     * <em>derived</em> (from host/issuer) and never accepted from the client.
     */
    public static final String TENANT_ID = "X-Aegis-Tenant";

    private TenantHeaders() {
    }
}
