package io.aegis.commons.events;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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
 * The domain-event publisher: serialise to JSON, publish to the given topic keyed by the aggregate
 * id, and — like every publisher on the request path — never let a broker problem propagate.
 */
class DomainEventPublisherTest {

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, String> template = mock(KafkaTemplate.class);
    private final DomainEventPublisher publisher = new DomainEventPublisher(template);

    private record TenantEvent(String eventType, String slug, Instant occurredAt) {
    }

    @Test
    void publishes_the_payload_as_json_to_the_given_topic_keyed_by_aggregate() {
        when(template.send(any(), any(), any()))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        publisher.publish("aegis.tenant.lifecycle", "acme",
                new TenantEvent("tenant.created", "acme", Instant.parse("2026-08-18T10:00:00Z")));

        ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
        verify(template).send(eq("aegis.tenant.lifecycle"), eq("acme"), value.capture());
        assertThat(value.getValue())
                .contains("\"eventType\":\"tenant.created\"")
                .contains("\"slug\":\"acme\"")
                .contains("2026-08-18T10:00:00Z"); // ISO-8601, not epoch
    }

    @Test
    void a_synchronous_send_failure_does_not_propagate() {
        doThrow(new RuntimeException("no broker")).when(template).send(any(), any(), any());

        assertThatCode(() -> publisher.publish("t", "k", Map.of("eventType", "x")))
                .doesNotThrowAnyException();
    }

    @Test
    void an_asynchronous_send_failure_does_not_propagate() {
        CompletableFuture<SendResult<String, String>> failed = new CompletableFuture<>();
        failed.completeExceptionally(new RuntimeException("broker down"));
        when(template.send(any(), any(), any())).thenReturn(failed);

        assertThatCode(() -> publisher.publish("t", "k", Map.of("eventType", "x")))
                .doesNotThrowAnyException();
    }
}
