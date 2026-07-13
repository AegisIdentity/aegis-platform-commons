package io.aegis.commons.audit;

/**
 * SPI for emitting audit events. The default {@link LoggingAuditEventPublisher} writes structured
 * JSON to the log pipeline; production deployments add a Kafka/SIEM adapter (per service) that also
 * implements this interface, typically decorating the logging one.
 */
public interface AuditEventPublisher {

    void publish(AuditEvent event);
}
