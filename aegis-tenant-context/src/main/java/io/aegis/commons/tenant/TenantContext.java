package io.aegis.commons.tenant;

import java.util.Optional;

/**
 * Holds the tenant bound to the current thread of execution.
 *
 * <p>Backed by an {@link InheritableThreadLocal} so simple child-thread work inherits the tenant.
 * Reactive/coroutine code must propagate the tenant explicitly (via Reactor context) rather than
 * relying on thread locals — see the reactive gateway for that path.
 *
 * <p>Callers <strong>must</strong> {@link #clear()} in a {@code finally} block to avoid leaking a
 * tenant across pooled-thread reuse — a leaked tenant is a cross-tenant data-exposure bug. The
 * {@code TenantContextFilter} does this for the request path.
 */
public final class TenantContext {

    private static final ThreadLocal<TenantId> CURRENT = new InheritableThreadLocal<>();

    private TenantContext() {
    }

    public static void set(TenantId tenantId) {
        if (tenantId == null) {
            throw new IllegalArgumentException("tenantId must not be null; use clear() to unset");
        }
        CURRENT.set(tenantId);
    }

    /** The current tenant, or empty if none is bound. */
    public static Optional<TenantId> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    /** The current tenant, or throw {@link MissingTenantException} if none is bound. */
    public static TenantId currentOrThrow() {
        TenantId id = CURRENT.get();
        if (id == null) {
            throw new MissingTenantException();
        }
        return id;
    }

    public static boolean isSet() {
        return CURRENT.get() != null;
    }

    public static void clear() {
        CURRENT.remove();
    }

    /**
     * Run an action with the given tenant bound, restoring the previous binding afterwards.
     * Prefer this over manual set/clear when nesting is possible.
     */
    public static void runAs(TenantId tenantId, Runnable action) {
        TenantId previous = CURRENT.get();
        try {
            set(tenantId);
            action.run();
        } finally {
            if (previous != null) {
                CURRENT.set(previous);
            } else {
                CURRENT.remove();
            }
        }
    }
}
