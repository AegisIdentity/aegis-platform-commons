package io.aegis.commons.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Publishes audit events to Kafka — the platform's forensic event stream (the CloudTrail / Okta
 * System Log analogue). Every security-relevant action across every service flows onto one topic, so
 * a single consumer (the audit sink) can build an append-only, queryable record of everything that
 * happened, and the same stream can be tee'd to a customer SIEM.
 *
 * <p><b>Never on the critical path.</b> An audit publish must not fail a business request. The send
 * is fire-and-forget (async {@code KafkaTemplate}); a broker outage logs a warning and drops the
 * <em>streaming</em> copy, but the event is not lost — this publisher is always composed with
 * {@link LoggingAuditEventPublisher}, so the log is the always-on floor and Kafka is the enhancement.
 * This is the same "audit must degrade, never break" rule the logging publisher already follows.
 *
 * <p><b>Partition key = tenant.</b> Keying by tenant id keeps a tenant's events in per-partition
 * order (so a consumer sees that tenant's timeline correctly) and spreads load across partitions by
 * tenant. Events with no tenant (pre-resolution) use a stable {@code "platform"} key.
 */
public class KafkaAuditEventPublisher implements AuditEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(KafkaAuditEventPublisher.class);
    private static final String NO_TENANT_KEY = "platform";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final String topic;
    private final ObjectMapper mapper;

    public KafkaAuditEventPublisher(KafkaTemplate<String, String> kafkaTemplate, String topic) {
        this.kafkaTemplate = kafkaTemplate;
        this.topic = topic;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Override
    public void publish(AuditEvent event) {
        String json;
        try {
            json = mapper.writeValueAsString(event);
        } catch (Exception e) {
            // Never let serialization break the request path (mirrors LoggingAuditEventPublisher).
            log.warn("audit_kafka_serialization_failed type={} action={}", event.type(), event.action());
            return;
        }
        String key = (event.tenantId() == null || event.tenantId().isBlank())
                ? NO_TENANT_KEY : event.tenantId();
        try {
            // Async: returns a future we attach a failure callback to rather than blocking the caller.
            kafkaTemplate.send(topic, key, json).whenComplete((result, ex) -> {
                if (ex != null) {
                    // The log publisher already captured this event, so it is not lost — only the
                    // streaming copy is dropped. Surface it so the outage is visible.
                    log.warn("audit_kafka_publish_failed topic={} type={} action={}: {}",
                            topic, event.type(), event.action(), ex.toString());
                }
            });
        } catch (Exception e) {
            // KafkaTemplate can throw synchronously if the producer cannot be created at all.
            log.warn("audit_kafka_send_threw topic={} type={} action={}: {}",
                    topic, event.type(), event.action(), e.toString());
        }
    }
}
