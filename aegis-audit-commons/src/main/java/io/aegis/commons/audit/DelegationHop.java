package io.aegis.commons.audit;

import java.time.Instant;
import java.util.Set;

/**
 * One link in a {@link DelegationChain}: a principal that was authorized to act, and the scopes it
 * held when it did.
 *
 * @param principal namespaced principal id, e.g. {@code user:alice@acme}, {@code agent:planner}.
 *                  Required.
 * @param type      what kind of principal this is; {@code null} is normalized to
 *                  {@link PrincipalType#UNKNOWN} rather than rejected, because chains that arrive
 *                  from outside our boundary routinely omit it.
 * @param protocol  the wire protocol this hop was observed on ({@code mcp}, {@code a2a}, {@code ap2})
 *                  or {@code null} for a native hop. Informational only — no platform behaviour
 *                  branches on it, which is what keeps the core protocol-agnostic (ADR-0011).
 * @param at        when this hop was authorized; defaults to now when {@code null}.
 * @param scopes    scopes held <em>at this hop</em>. An <b>empty</b> set means "not recorded", not
 *                  "no authority" — see {@link DelegationChain#isMonotonicallyNarrowing()}.
 */
public record DelegationHop(
        String principal,
        PrincipalType type,
        String protocol,
        Instant at,
        Set<String> scopes) {

    public DelegationHop {
        if (principal == null || principal.isBlank()) {
            throw new IllegalArgumentException("delegation hop principal is required");
        }
        type = type == null ? PrincipalType.UNKNOWN : type;
        at = at == null ? Instant.now() : at;
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
    }

    /** A hop with no scopes recorded. */
    public static DelegationHop of(String principal, PrincipalType type) {
        return new DelegationHop(principal, type, null, Instant.now(), Set.of());
    }

    /** A hop carrying the scopes held at that point in the chain. */
    public static DelegationHop of(String principal, PrincipalType type, Set<String> scopes) {
        return new DelegationHop(principal, type, null, Instant.now(), scopes);
    }
}
