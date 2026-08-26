package io.aegis.commons.audit;

import io.aegis.commons.tenant.TenantContext;
import java.time.Instant;
import java.util.Map;
import org.slf4j.MDC;

/**
 * An immutable audit record. This is the platform's forensic trail — the analogue of Okta's System
 * Log. Events are attributable (tenant + actor), typed ({@code action}), and outcome-tagged.
 *
 * <p>Never put secrets (passwords, tokens, full assertions) in {@code attributes} — audit records
 * are widely readable and streamed to customer SIEMs. Attribute values should be identifiers and
 * decisions, not credentials.
 *
 * @param type        coarse category, e.g. {@code auth}, {@code authz}, {@code admin}, {@code identity}
 * @param action      specific action, e.g. {@code login}, {@code token.issued}, {@code user.created}
 * @param outcome     success / failure / denied
 * @param tenantId    owning tenant (may be null for pre-tenant-resolution events)
 * @param actor       subject performing the action (user id, client id, or {@code anonymous})
 * @param target      the object acted upon (may be null)
 * @param correlationId request correlation id, for cross-service stitching (may be null)
 * @param at          event time
 * @param attributes  extra non-sensitive context
 * @param onBehalfOf  the <em>root</em> principal whose authority is being exercised — the
 *                    accountable human or service at the head of {@code delegationChain}. Null for
 *                    ordinary, non-delegated events.
 * @param delegationChain who authorized whom, root-first (ADR-0010). Never null — empty when the
 *                    event has no delegation, so callers need no null check.
 * @param agentInstanceId identifier for one <em>run</em> of an agent, distinguishing a single
 *                    execution from the agent definition. Null for non-agent events.
 * @param toolInvocationId correlates the request, result and any error of one tool call.
 */
public record AuditEvent(
        String type,
        String action,
        AuditOutcome outcome,
        String tenantId,
        String actor,
        String target,
        String correlationId,
        Instant at,
        Map<String, String> attributes,
        // --- added 2026-08-26 (ADR-0010). ADDITIVE ONLY: the nine fields above keep their exact
        // names and meanings because this record is serialized to customer SIEMs. In particular
        // `actor` still means "the effective (last-hop) actor" — do not redefine it. ---
        String onBehalfOf,
        DelegationChain delegationChain,
        String agentInstanceId,
        String toolInvocationId) {

    public AuditEvent {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("audit event type is required");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("audit event action is required");
        }
        if (outcome == null) {
            throw new IllegalArgumentException("audit event outcome is required");
        }
        if (at == null) {
            throw new IllegalArgumentException("audit event time is required");
        }
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
        delegationChain = delegationChain == null ? DelegationChain.empty() : delegationChain;
    }

    /**
     * Nine-argument constructor preserved for source compatibility.
     *
     * <p>Downstream repos construct {@code AuditEvent} directly. Adding record components would
     * otherwise be a source-breaking change across the polyrepo, which ADR-0010 forbids — so this
     * overload stays. Do not remove it.
     */
    public AuditEvent(
            String type,
            String action,
            AuditOutcome outcome,
            String tenantId,
            String actor,
            String target,
            String correlationId,
            Instant at,
            Map<String, String> attributes) {
        this(type, action, outcome, tenantId, actor, target, correlationId, at, attributes,
                null, DelegationChain.empty(), null, null);
    }

    /** Start a builder that auto-fills tenant (from {@link TenantContext}), correlation id, and time. */
    public static Builder of(String type, String action, AuditOutcome outcome) {
        return new Builder(type, action, outcome);
    }

    public static final class Builder {
        private final String type;
        private final String action;
        private final AuditOutcome outcome;
        private String tenantId = TenantContext.current().map(t -> t.value()).orElse(null);
        private String actor = "anonymous";
        private String target;
        private String correlationId = MDC.get("correlationId");
        private Instant at = Instant.now();
        private final java.util.Map<String, String> attributes = new java.util.LinkedHashMap<>();
        private String onBehalfOf;
        private DelegationChain delegationChain = DelegationChain.empty();
        private String agentInstanceId;
        private String toolInvocationId;
        /** Tracks whether the caller named an actor explicitly, so {@link #delegation} never overrides one. */
        private boolean actorExplicit;

        private Builder(String type, String action, AuditOutcome outcome) {
            this.type = type;
            this.action = action;
            this.outcome = outcome;
        }

        public Builder tenant(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder actor(String actor) {
            this.actor = actor;
            this.actorExplicit = true;
            return this;
        }

        public Builder target(String target) {
            this.target = target;
            return this;
        }

        public Builder at(Instant at) {
            this.at = at;
            return this;
        }

        public Builder attribute(String key, String value) {
            if (key != null && value != null) {
                this.attributes.put(key, value);
            }
            return this;
        }

        /**
         * Attach a delegation chain, deriving the two fields that must agree with it:
         * {@code actor} becomes the effective (last) hop and {@code onBehalfOf} becomes the root
         * hop. Deriving rather than requiring both to be passed is what keeps the forensic record
         * and the authorization decision from drifting apart (ADR-0010).
         *
         * <p>An actor named explicitly via {@link #actor(String)} always wins, whichever order the
         * two calls are made in.
         */
        public Builder delegation(DelegationChain chain) {
            this.delegationChain = chain == null ? DelegationChain.empty() : chain;
            this.delegationChain.root()
                    .ifPresent(root -> this.onBehalfOf = root.principal());
            if (!actorExplicit) {
                this.delegationChain.effective()
                        .ifPresent(effective -> this.actor = effective.principal());
            }
            return this;
        }

        /** Override the derived root principal. Rarely needed — prefer {@link #delegation}. */
        public Builder onBehalfOf(String onBehalfOf) {
            this.onBehalfOf = onBehalfOf;
            return this;
        }

        public Builder agentInstanceId(String agentInstanceId) {
            this.agentInstanceId = agentInstanceId;
            return this;
        }

        public Builder toolInvocationId(String toolInvocationId) {
            this.toolInvocationId = toolInvocationId;
            return this;
        }

        public AuditEvent build() {
            return new AuditEvent(type, action, outcome, tenantId, actor, target,
                    correlationId, at, attributes,
                    onBehalfOf, delegationChain, agentInstanceId, toolInvocationId);
        }
    }
}
