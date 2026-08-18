package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * The composite's job is to guarantee the durable log floor is written even when the streaming
 * delegate (Kafka) fails — the "audit degrades, never breaks" rule applied across delegates.
 */
class CompositeAuditEventPublisherTest {

    private static AuditEvent event() {
        return new AuditEvent("admin", "user.created", AuditOutcome.SUCCESS, "acme", "root", "bob",
                null, Instant.now(), Map.of());
    }

    @Test
    void fans_the_event_out_to_every_delegate() {
        AtomicInteger a = new AtomicInteger();
        AtomicInteger b = new AtomicInteger();
        var composite = new CompositeAuditEventPublisher(List.of(
                e -> a.incrementAndGet(), e -> b.incrementAndGet()));

        composite.publish(event());

        assertThat(a.get()).isEqualTo(1);
        assertThat(b.get()).isEqualTo(1);
    }

    @Test
    void a_failing_delegate_does_not_prevent_the_others() {
        AtomicInteger logged = new AtomicInteger();
        // First delegate is the "log floor"; a later "kafka" delegate throws.
        var composite = new CompositeAuditEventPublisher(List.of(
                e -> logged.incrementAndGet(),
                e -> {
                    throw new RuntimeException("kafka down");
                }));

        composite.publish(event()); // must not throw

        assertThat(logged.get())
                .as("the durable log floor must be written even when a later delegate fails")
                .isEqualTo(1);
    }

    @Test
    void the_first_delegate_is_published_before_a_later_one_throws() {
        StringBuilder order = new StringBuilder();
        var composite = new CompositeAuditEventPublisher(List.of(
                e -> order.append("log;"),
                e -> {
                    order.append("kafka;");
                    throw new RuntimeException("boom");
                }));

        composite.publish(event());

        // Log first, then the streaming attempt — the ordering the durable-floor guarantee needs.
        assertThat(order.toString()).isEqualTo("log;kafka;");
    }
}
