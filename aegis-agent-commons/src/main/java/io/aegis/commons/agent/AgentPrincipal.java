package io.aegis.commons.agent;

import io.aegis.commons.audit.DelegationHop;
import io.aegis.commons.audit.PrincipalType;
import java.time.Instant;
import java.util.Set;

/**
 * A non-human, delegated principal.
 *
 * <p>The {@code ownerPrincipal} — the "owner edge" — is <b>mandatory</b>, and that is the single
 * most important constraint in this type. It is what makes "the agent did it" an answerable
 * statement: there is always a human or service to notify, to escalate to, and to hold accountable.
 * An agent nobody owns is an agent nobody will notice misbehaving, so the constructor refuses to
 * create one.
 *
 * @param id             namespaced agent id, e.g. {@code agent:planner}
 * @param tenantId       owning tenant — agents are tenant-scoped like every other principal
 * @param ownerPrincipal the accountable human or service. Required.
 * @param autonomy       how much it may do unattended; {@code null} means {@link AutonomyLevel#CONFIRM_EACH}
 * @param status         lifecycle state; {@code null} means {@link AgentStatus#SUSPENDED}
 * @param createdAt      registration time
 */
public record AgentPrincipal(
        String id,
        String tenantId,
        String ownerPrincipal,
        AutonomyLevel autonomy,
        AgentStatus status,
        Instant createdAt) {

    public AgentPrincipal {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("agent id is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("agent tenantId is required");
        }
        if (ownerPrincipal == null || ownerPrincipal.isBlank()) {
            throw new IllegalArgumentException(
                    "agent ownerPrincipal is required — an agent must have an accountable owner");
        }
        // Null must never resolve to the permissive option.
        autonomy = autonomy == null ? AutonomyLevel.CONFIRM_EACH : autonomy;
        status = status == null ? AgentStatus.SUSPENDED : status;
        createdAt = createdAt == null ? Instant.now() : createdAt;
    }

    public boolean isActive() {
        return status == AgentStatus.ACTIVE;
    }

    /** Bridge into the audit delegation chain (ADR-0010). */
    public DelegationHop toDelegationHop(Set<String> scopes) {
        return new DelegationHop(id, PrincipalType.AGENT, null, Instant.now(), scopes);
    }
}
