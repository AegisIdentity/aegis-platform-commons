package io.aegis.commons.audit;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fans one audit event out to several publishers — in practice the always-on
 * {@link LoggingAuditEventPublisher} plus the {@link KafkaAuditEventPublisher} when Kafka is
 * configured.
 *
 * <p>The ordering guarantee that matters: **logging first, then streaming**. The log is the durable
 * floor that must never be skipped, so it is published before the Kafka copy is attempted, and one
 * delegate throwing must not stop the others — a broker hiccup cannot suppress the logged record.
 */
public class CompositeAuditEventPublisher implements AuditEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(CompositeAuditEventPublisher.class);

    private final List<AuditEventPublisher> delegates;

    public CompositeAuditEventPublisher(List<AuditEventPublisher> delegates) {
        this.delegates = List.copyOf(delegates);
    }

    @Override
    public void publish(AuditEvent event) {
        for (AuditEventPublisher delegate : delegates) {
            try {
                delegate.publish(event);
            } catch (Exception e) {
                // Isolate delegates: a failure in one (e.g. Kafka) must not deny the others (the log).
                log.warn("audit_delegate_failed {}: {}", delegate.getClass().getSimpleName(), e.toString());
            }
        }
    }
}
