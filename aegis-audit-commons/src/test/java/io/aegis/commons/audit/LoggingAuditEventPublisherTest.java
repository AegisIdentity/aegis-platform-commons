package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class LoggingAuditEventPublisherTest {

    private final LoggingAuditEventPublisher publisher = new LoggingAuditEventPublisher();
    private Logger auditLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setUp() {
        auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        appender = new ListAppender<>();
        appender.start();
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        auditLogger.detachAppender(appender);
    }

    @Test
    void success_event_logs_json_at_info() {
        publisher.publish(AuditEvent.of("auth", "login", AuditOutcome.SUCCESS).actor("u1").build());

        assertThat(appender.list).hasSize(1);
        ILoggingEvent logged = appender.list.get(0);
        assertThat(logged.getLevel()).isEqualTo(Level.INFO);
        assertThat(logged.getFormattedMessage())
                .contains("\"type\":\"auth\"")
                .contains("\"action\":\"login\"")
                .contains("\"outcome\":\"SUCCESS\"")
                .contains("\"actor\":\"u1\"");
    }

    @Test
    void failure_event_logs_at_warn_so_it_surfaces() {
        publisher.publish(AuditEvent.of("auth", "login", AuditOutcome.FAILURE).build());
        assertThat(appender.list.get(0).getLevel()).isEqualTo(Level.WARN);
    }

    @Test
    void denied_event_logs_at_warn() {
        publisher.publish(AuditEvent.of("authz", "access", AuditOutcome.DENIED).build());
        assertThat(appender.list.get(0).getLevel()).isEqualTo(Level.WARN);
    }
}
