package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The delegation chain is the spine of agent identity (ADR-0010): an ordered record of who
 * authorized whom. The invariant borrowed from RFC 8693 is that the <em>subject never changes</em>
 * while the <em>actor chain grows</em> — so the root of the chain is always the accountable party,
 * however deep the delegation went.
 */
class DelegationChainTest {

    private static DelegationHop hop(String principal, String... scopes) {
        return new DelegationHop(principal, PrincipalType.AGENT, null, Instant.now(), Set.of(scopes));
    }

    @Test
    void empty_chain_has_no_root_or_effective_actor() {
        DelegationChain chain = DelegationChain.empty();
        assertThat(chain.isEmpty()).isTrue();
        assertThat(chain.depth()).isZero();
        assertThat(chain.root()).isEmpty();
        assertThat(chain.effective()).isEmpty();
    }

    @Test
    void root_is_the_first_hop_and_effective_is_the_last() {
        DelegationChain chain = DelegationChain.of(
                new DelegationHop("user:alice", PrincipalType.HUMAN, null, Instant.now(), Set.of("files:read")),
                hop("agent:planner", "files:read"),
                hop("agent:researcher", "files:read"));

        assertThat(chain.depth()).isEqualTo(3);
        assertThat(chain.root()).get().extracting(DelegationHop::principal).isEqualTo("user:alice");
        assertThat(chain.effective()).get().extracting(DelegationHop::principal).isEqualTo("agent:researcher");
    }

    @Test
    void append_returns_a_new_chain_and_leaves_the_original_untouched() {
        DelegationChain original = DelegationChain.of(hop("agent:planner", "files:read"));
        DelegationChain extended = original.append(hop("agent:researcher", "files:read"));

        assertThat(original.depth()).isEqualTo(1);
        assertThat(extended.depth()).isEqualTo(2);
        assertThat(extended.effective()).get().extracting(DelegationHop::principal).isEqualTo("agent:researcher");
    }

    @Test
    void hops_are_an_immutable_copy() {
        DelegationChain chain = DelegationChain.of(hop("agent:a", "s"));
        assertThatThrownBy(() -> chain.hops().add(hop("agent:b", "s")))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void scopes_are_an_immutable_copy() {
        DelegationHop h = hop("agent:a", "files:read");
        assertThatThrownBy(() -> h.scopes().add("files:write"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejects_a_blank_principal() {
        assertThatThrownBy(() -> new DelegationHop(" ", PrincipalType.AGENT, null, Instant.now(), Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void null_type_defaults_to_unknown_rather_than_failing() {
        assertThat(new DelegationHop("x", null, null, Instant.now(), Set.of()).type())
                .isEqualTo(PrincipalType.UNKNOWN);
    }

    // --- the delegation-laundering invariant (THREAT-MODEL, agent STRIDE "E") -------------------

    @Test
    void narrowing_scopes_along_the_chain_is_valid() {
        DelegationChain chain = DelegationChain.of(
                hop("agent:planner", "files:read", "files:write"),
                hop("agent:researcher", "files:read"));
        assertThat(chain.isMonotonicallyNarrowing()).isTrue();
        assertThat(chain.firstWideningHop()).isEmpty();
    }

    @Test
    void identical_scopes_still_count_as_narrowing() {
        DelegationChain chain = DelegationChain.of(
                hop("agent:planner", "files:read"),
                hop("agent:researcher", "files:read"));
        assertThat(chain.isMonotonicallyNarrowing()).isTrue();
    }

    @Test
    void widening_scopes_is_delegation_laundering_and_names_the_offending_hop() {
        DelegationChain chain = DelegationChain.of(
                hop("agent:low", "files:read"),
                hop("agent:high", "files:read", "admin:all"));

        assertThat(chain.isMonotonicallyNarrowing()).isFalse();
        assertThat(chain.firstWideningHop()).get().extracting(DelegationHop::principal).isEqualTo("agent:high");
    }

    @Test
    void a_single_hop_is_trivially_narrowing() {
        assertThat(DelegationChain.of(hop("agent:solo", "a", "b")).isMonotonicallyNarrowing()).isTrue();
        assertThat(DelegationChain.empty().isMonotonicallyNarrowing()).isTrue();
    }

    @Test
    void hops_with_unrecorded_scopes_are_not_evaluated_rather_than_assumed_safe_or_unsafe() {
        // An empty scope set means "not recorded at this hop", not "no authority". We cannot assert
        // narrowing across a gap, so the pair is skipped — and this is deliberate, documented
        // behaviour rather than an accident, hence the explicit test.
        DelegationChain chain = DelegationChain.of(
                hop("agent:a", "files:read"),
                hop("agent:b"),
                hop("agent:c", "admin:all"));
        assertThat(chain.isMonotonicallyNarrowing()).isTrue();
    }
}
