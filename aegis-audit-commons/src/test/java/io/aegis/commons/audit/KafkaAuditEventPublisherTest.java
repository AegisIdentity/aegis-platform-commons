package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

/**
 * The Kafka audit publisher's contract: it serialises the event to JSON, keys by tenant for
 * per-tenant ordering, and — critically — never lets a broker problem propagate to the caller, since
 * an audit publish sits on the business request path.
 */
class KafkaAuditEventPublisherTest {

    private static final String TOPIC = "aegis.audit.events";

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, String> template = mock(KafkaTemplate.class);

    private final KafkaAuditEventPublisher publisher = new KafkaAuditEventPublisher(template, TOPIC);

    private static AuditEvent event(String tenant) {
        return new AuditEvent("auth", "login", AuditOutcome.SUCCESS, tenant, "alice", null,
                "corr-1", Instant.parse("2026-08-18T10:00:00Z"), Map.of("ip", "203.0.113.7"));
    }

    @Test
    void publishes_the_event_as_json_keyed_by_tenant() {
        when(template.send(eq(TOPIC), any(), any()))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        publisher.publish(event("acme"));

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
        verify(template).send(eq(TOPIC), key.capture(), value.capture());

        assertThat(key.getValue()).isEqualTo("acme"); // per-tenant partition affinity
        assertThat(value.getValue())
                .contains("\"type\":\"auth\"")
                .contains("\"action\":\"login\"")
                .contains("\"tenantId\":\"acme\"")
                .contains("\"actor\":\"alice\"")
                // ISO-8601, not an epoch number — the sink and SIEM read timestamps, not longs.
                .contains("2026-08-18T10:00:00Z");
    }

    @Test
    void an_event_with_no_tenant_uses_a_stable_platform_key() {
        when(template.send(eq(TOPIC), any(), any()))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        publisher.publish(event(null));

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(template).send(eq(TOPIC), key.capture(), any());
        assertThat(key.getValue()).isEqualTo("platform");
    }

    /** A synchronous producer failure must be swallowed — audit must degrade, never break a request. */
    @Test
    void a_synchronous_send_failure_does_not_propagate() {
        doThrow(new RuntimeException("no broker")).when(template).send(eq(TOPIC), any(), any());

        // Must not throw.
        publisher.publish(event("acme"));
    }

    /** An async send failure must also be swallowed (the log publisher still captured the event). */
    @Test
    void an_asynchronous_send_failure_does_not_propagate() {
        CompletableFuture<SendResult<String, String>> failed = new CompletableFuture<>();
        failed.completeExceptionally(new RuntimeException("broker down"));
        when(template.send(eq(TOPIC), any(), any())).thenReturn(failed);

        // Must not throw even though the future completes exceptionally.
        publisher.publish(event("acme"));
    }
}
