package io.aegis.commons.audit;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A one-call, never-throwing convenience over {@link AuditEventPublisher} for services that emit
 * domain events. It builds the {@link AuditEvent} and publishes it, swallowing any failure so an
 * audit problem can never break the business operation it describes — the "audit degrades, never
 * breaks" rule, in one place instead of a hand-written try/catch per call site.
 *
 * <p>A blank {@code actor} is normalised to {@code "system"} so the trail never has an empty actor.
 */
public class AuditRecorder {

    private static final Logger log = LoggerFactory.getLogger(AuditRecorder.class);

    private final AuditEventPublisher publisher;

    public AuditRecorder(AuditEventPublisher publisher) {
        this.publisher = publisher;
    }

    /** Record a successful domain action. */
    public void record(String type, String action, String tenant, String actor, String target) {
        record(type, action, AuditOutcome.SUCCESS, tenant, actor, target, Map.of());
    }

    /** Record a successful domain action with one detail attribute. */
    public void record(String type, String action, String tenant, String actor, String target,
                       String detailKey, String detailValue) {
        record(type, action, AuditOutcome.SUCCESS, tenant, actor, target,
                detailValue == null ? Map.of() : Map.of(detailKey, detailValue));
    }

    /** Record a domain action with an explicit outcome and attributes. Never throws. */
    public void record(String type, String action, AuditOutcome outcome, String tenant, String actor,
                       String target, Map<String, String> attributes) {
        try {
            AuditEvent.Builder builder = AuditEvent.of(type, action, outcome)
                    .tenant(tenant)
                    .actor(actor == null || actor.isBlank() ? "system" : actor)
                    .target(target);
            if (attributes != null) {
                attributes.forEach(builder::attribute);
            }
            publisher.publish(builder.build());
        } catch (RuntimeException ex) {
            log.warn("audit record failed (type={}, action={}): {}", type, action, ex.toString());
        }
    }
}
