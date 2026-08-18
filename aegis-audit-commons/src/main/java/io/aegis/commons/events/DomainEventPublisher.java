package io.aegis.commons.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Publishes <em>business / integration</em> domain events onto per-domain Kafka topics — the
 * choreography backbone that decouples services' side effects (ARCHITECTURE §4.4 / ADR-0003). This
 * is deliberately a <b>separate concern from {@code AuditEventPublisher}</b>:
 *
 * <ul>
 *   <li><b>Different topics.</b> Business events go to per-domain topics (e.g.
 *       {@code aegis.tenant.lifecycle}), not the single {@code aegis.audit.events} audit topic, so a
 *       consumer subscribes to the domain it cares about rather than filtering one firehose.</li>
 *   <li><b>Different fate.</b> An audit publish is best-effort with a durable log floor; a business
 *       event is meant to <em>drive</em> another service, so consumers are idempotent and the stream
 *       is at-least-once. The two must not share fate — a broker hiccup must never suppress a
 *       compliance record, and an audit-retention purge must never drop an integration event.</li>
 *   <li><b>Different contract.</b> Business events are a versioned contract between services
 *       (schemas in {@code aegis-platform-docs/api/events/}); audit events are a forensic format.</li>
 * </ul>
 *
 * <p><b>Delivery.</b> The send is fire-and-forget with failure logged. For a flow that has an
 * independent correctness floor (e.g. tenant-key provisioning also happens lazily on first use), a
 * dropped event is a missed <em>optimization</em>, not a lost side effect, so best-effort is
 * sufficient. A flow with <em>no</em> floor (e.g. outbound provisioning) must use the transactional
 * <b>outbox</b> pattern — persist the event in the same DB transaction as the state change and relay
 * it — to avoid the dual-write problem; that is a documented per-flow decision, not this class's job.
 *
 * <p><b>Partition key.</b> Events are keyed by the aggregate id (tenant, user) so a given aggregate's
 * events stay in per-partition order for its consumer.
 */
public class DomainEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(DomainEventPublisher.class);

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper mapper;

    public DomainEventPublisher(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Publish {@code payload} (serialised to JSON) to {@code topic}, partitioned by {@code key}.
     *
     * @param topic   the per-domain topic, e.g. {@code aegis.tenant.lifecycle}
     * @param key     the aggregate id for partition ordering (tenant id, user id)
     * @param payload the event object — should carry an {@code eventType} and {@code occurredAt}
     */
    public void publish(String topic, String key, Object payload) {
        String json;
        try {
            json = mapper.writeValueAsString(payload);
        } catch (Exception e) {
            log.warn("domain_event_serialization_failed topic={} key={}", topic, key);
            return;
        }
        try {
            kafkaTemplate.send(topic, key, json).whenComplete((result, ex) -> {
                if (ex != null) {
                    // Surfaced so the outage is visible. For floor-backed flows this is a missed
                    // optimization; for floor-less flows the producer must use an outbox instead.
                    log.warn("domain_event_publish_failed topic={} key={}: {}", topic, key, ex.toString());
                }
            });
        } catch (Exception e) {
            log.warn("domain_event_send_threw topic={} key={}: {}", topic, key, e.toString());
        }
    }
}
