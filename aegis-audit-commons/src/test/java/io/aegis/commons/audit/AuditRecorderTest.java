package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * The shared emit helper used by the service emitters (mfa/scim/social). Its two guarantees:
 * publishing never throws (audit degrades, never breaks the caller), and a blank actor becomes
 * {@code system} so the trail never has an empty actor.
 */
class AuditRecorderTest {

    @Test
    void records_a_success_event_with_the_given_fields() {
        AtomicReference<AuditEvent> captured = new AtomicReference<>();
        AuditRecorder recorder = new AuditRecorder(captured::set);

        recorder.record("mfa", "mfa.totp.enrolled", "acme", "alice", "alice");

        AuditEvent event = captured.get();
        assertThat(event.type()).isEqualTo("mfa");
        assertThat(event.action()).isEqualTo("mfa.totp.enrolled");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.tenantId()).isEqualTo("acme");
        assertThat(event.actor()).isEqualTo("alice");
        assertThat(event.target()).isEqualTo("alice");
    }

    @Test
    void carries_an_explicit_outcome_and_attributes() {
        AtomicReference<AuditEvent> captured = new AtomicReference<>();
        AuditRecorder recorder = new AuditRecorder(captured::set);

        recorder.record("mfa", "mfa.totp.failed", AuditOutcome.FAILURE, "acme", "alice", "alice",
                Map.of("reason", "bad_code"));

        assertThat(captured.get().outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(captured.get().attributes()).containsEntry("reason", "bad_code");
    }

    @Test
    void a_blank_actor_becomes_system() {
        AtomicReference<AuditEvent> captured = new AtomicReference<>();
        AuditRecorder recorder = new AuditRecorder(captured::set);

        recorder.record("scim", "scim.user.provisioned", "acme", "  ", "bob");

        assertThat(captured.get().actor()).isEqualTo("system");
    }

    @Test
    void a_publisher_failure_never_propagates() {
        AuditRecorder recorder = new AuditRecorder(e -> {
            throw new RuntimeException("kafka down");
        });

        assertThatCode(() -> recorder.record("idp", "idp.created", "acme", "root", "google"))
                .doesNotThrowAnyException();
    }
}
