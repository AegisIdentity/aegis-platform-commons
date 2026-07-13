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
        Map<String, String> attributes) {

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

        public AuditEvent build() {
            return new AuditEvent(type, action, outcome, tenantId, actor, target,
                    correlationId, at, attributes);
        }
    }
}
