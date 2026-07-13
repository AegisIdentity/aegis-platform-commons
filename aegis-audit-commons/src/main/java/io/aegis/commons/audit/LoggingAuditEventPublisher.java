package io.aegis.commons.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Emits audit events as single-line structured JSON on a dedicated {@code AUDIT} logger, so a log
 * shipper can route them to the audit store / SIEM. Failures ({@link AuditOutcome#FAILURE} /
 * {@link AuditOutcome#DENIED}) are logged at WARN so they surface even under an INFO threshold.
 */
public class LoggingAuditEventPublisher implements AuditEventPublisher {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    private final ObjectMapper mapper;

    public LoggingAuditEventPublisher() {
        this(new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS));
    }

    public LoggingAuditEventPublisher(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void publish(AuditEvent event) {
        String json;
        try {
            json = mapper.writeValueAsString(event);
        } catch (Exception e) {
            // Never let audit serialization break the request path; degrade to a plain line.
            AUDIT.warn("audit_serialization_failed type={} action={} outcome={}",
                    event.type(), event.action(), event.outcome());
            return;
        }
        if (event.outcome() == AuditOutcome.SUCCESS) {
            AUDIT.info(json);
        } else {
            AUDIT.warn(json);
        }
    }
}
