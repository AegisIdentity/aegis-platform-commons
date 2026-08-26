package io.aegis.commons.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.audit.PrincipalType;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Accountability before autonomy: an agent that no one owns cannot be created. */
class AgentPrincipalTest {

    private static AgentPrincipal agent(String owner) {
        return new AgentPrincipal("agent:planner", "acme", owner,
                AutonomyLevel.SUPERVISED, AgentStatus.ACTIVE, Instant.now());
    }

    @Test
    void an_agent_must_name_an_accountable_owner() {
        // The owner edge is what makes "the agent did it" answerable. Without it there is no human
        // or service to escalate to, revoke, or hold responsible — so it is a hard constraint
        // rather than a validation warning.
        assertThatThrownBy(() -> agent(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> agent("  ")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requires_id_and_tenant() {
        assertThatThrownBy(() -> new AgentPrincipal(" ", "acme", "user:alice",
                AutonomyLevel.SUPERVISED, AgentStatus.ACTIVE, Instant.now()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AgentPrincipal("agent:x", " ", "user:alice",
                AutonomyLevel.SUPERVISED, AgentStatus.ACTIVE, Instant.now()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void defaults_are_the_safe_ones() {
        AgentPrincipal a = new AgentPrincipal("agent:x", "acme", "user:alice", null, null, null);
        // A null autonomy level must not mean "unrestricted".
        assertThat(a.autonomy()).isEqualTo(AutonomyLevel.CONFIRM_EACH);
        assertThat(a.status()).isEqualTo(AgentStatus.SUSPENDED);
    }

    @Test
    void only_an_active_agent_may_act() {
        assertThat(agent("user:alice").isActive()).isTrue();
        assertThat(new AgentPrincipal("agent:x", "acme", "user:alice",
                AutonomyLevel.SUPERVISED, AgentStatus.REVOKED, Instant.now()).isActive()).isFalse();
    }

    @Test
    void converts_to_a_delegation_hop_so_the_audit_chain_can_carry_it() {
        AgentPrincipal a = agent("user:alice");
        var hop = a.toDelegationHop(java.util.Set.of("files:read"));

        assertThat(hop.principal()).isEqualTo("agent:planner");
        assertThat(hop.type()).isEqualTo(PrincipalType.AGENT);
        assertThat(hop.scopes()).containsExactly("files:read");
    }
}
