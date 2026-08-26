package io.aegis.commons.audit;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * An ordered record of who authorized whom — the spine of agent identity (ADR-0010).
 *
 * <p>Hops are ordered <b>root-first, nearest-last</b>: {@code hops[0]} is the party that originated
 * the authority (normally a human) and the final hop is the principal that actually acted. The
 * invariant is borrowed directly from RFC 8693 token exchange: the <b>subject never changes</b>
 * while the <b>actor chain grows</b>. That is what makes the chain useful for forensics as well as
 * authorization — the accountable party is always {@link #root()}, however deep delegation went.
 *
 * <p>Immutable; {@link #append(DelegationHop)} returns a new chain.
 */
public record DelegationChain(List<DelegationHop> hops) {

    private static final DelegationChain EMPTY = new DelegationChain(List.of());

    public DelegationChain {
        hops = hops == null ? List.of() : List.copyOf(hops);
    }

    public static DelegationChain empty() {
        return EMPTY;
    }

    public static DelegationChain of(DelegationHop... hops) {
        return new DelegationChain(hops == null ? List.of() : List.of(hops));
    }

    @JsonIgnore
    public boolean isEmpty() {
        return hops.isEmpty();
    }

    /** Number of hops. */
    @JsonIgnore
    public int depth() {
        return hops.size();
    }

    /** The originating, accountable principal — normally the human. */
    @JsonIgnore
    public Optional<DelegationHop> root() {
        return hops.isEmpty() ? Optional.empty() : Optional.of(hops.get(0));
    }

    /** The principal that actually acted — what {@code AuditEvent.actor()} reflects. */
    @JsonIgnore
    public Optional<DelegationHop> effective() {
        return hops.isEmpty() ? Optional.empty() : Optional.of(hops.get(hops.size() - 1));
    }

    /** A new chain with {@code hop} appended; this chain is unchanged. */
    public DelegationChain append(DelegationHop hop) {
        List<DelegationHop> next = new ArrayList<>(hops);
        next.add(hop);
        return new DelegationChain(next);
    }

    /**
     * Whether authority only ever narrowed along this chain.
     *
     * <p>This is the invariant that defeats <b>delegation laundering</b> — the agent-native
     * privilege-escalation primitive, in which a low-privilege agent delegates to a high-privilege
     * one and receives back a result it could never have obtained directly (see THREAT-MODEL,
     * agent STRIDE "E").
     *
     * <p><b>Unrecorded scopes are not evaluated.</b> A pair is only compared when <em>both</em> hops
     * carry a non-empty scope set; an empty set means "not recorded at this hop", and asserting
     * either safety or violation across a gap would be inventing information. This is a deliberate
     * decision rather than an oversight: a detector must not raise an alert on missing data. The
     * consequence — that a chain with gaps can pass this check — is accepted, and is why this method
     * is a <em>signal</em> for the detection pipeline and never the sole authorization control.
     */
    @JsonIgnore
    public boolean isMonotonicallyNarrowing() {
        return firstWideningHop().isEmpty();
    }

    /**
     * The first hop that widened authority relative to the hop before it, if any. Returning the hop
     * rather than a boolean lets an alert name the offending principal instead of merely reporting
     * that something, somewhere, went wrong.
     */
    @JsonIgnore
    public Optional<DelegationHop> firstWideningHop() {
        for (int i = 1; i < hops.size(); i++) {
            DelegationHop previous = hops.get(i - 1);
            DelegationHop current = hops.get(i);
            if (previous.scopes().isEmpty() || current.scopes().isEmpty()) {
                continue; // not recorded — see javadoc
            }
            if (!previous.scopes().containsAll(current.scopes())) {
                return Optional.of(current);
            }
        }
        return Optional.empty();
    }
}
