package io.aegis.commons.tenant;

import java.util.regex.Pattern;

/**
 * A validated tenant identifier. Immutable value type.
 *
 * <p>Tenant ids are opaque, URL-safe slugs (letters, digits, {@code _}, {@code -}), 1..64 chars.
 * This is a security-relevant type: an unvalidated tenant id flowing into a query, a Redis key, or a
 * signed header is a cross-tenant-isolation risk, so construction always validates.
 */
public record TenantId(String value) {

    private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    public TenantId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("tenant id must not be blank");
        }
        if (!VALID.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "tenant id must match " + VALID.pattern() + " but was '" + value + "'");
        }
    }

    /** Factory mirroring {@code UUID.fromString} style; identical to the canonical constructor. */
    public static TenantId of(String value) {
        return new TenantId(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
