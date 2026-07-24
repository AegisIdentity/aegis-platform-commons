package io.aegis.commons.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

class AuthenticationAuditListenerTest {

    private final List<AuditEvent> captured = new ArrayList<>();
    private final AuditEventPublisher publisher = captured::add;
    private final AuthenticationAuditListener listener = new AuthenticationAuditListener(publisher);

    @Test
    void success_event_records_success_with_actor() {
        var auth = UsernamePasswordAuthenticationToken.authenticated("bob", null, List.of());
        listener.onSuccess(new AuthenticationSuccessEvent(auth));

        assertThat(captured).hasSize(1);
        AuditEvent event = captured.get(0);
        assertThat(event.type()).isEqualTo("auth");
        assertThat(event.action()).isEqualTo("login");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.actor()).isEqualTo("bob");
    }

    @Test
    void failure_event_hashes_actor_and_records_reason() {
        // The user typed their password into the username field (a common mistake).
        var auth = UsernamePasswordAuthenticationToken.unauthenticated("hunter2-my-password", "secret");
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(auth,
                new BadCredentialsException("bad")));

        assertThat(captured).hasSize(1);
        AuditEvent event = captured.get(0);
        assertThat(event.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(event.attributes()).containsEntry("reason", "BadCredentialsException");
        // The attempted principal must be hashed, never stored in cleartext.
        assertThat(event.actor()).startsWith("sha256:");
        assertThat(event.actor()).doesNotContain("hunter2-my-password");
        // No field (actor or attributes) may contain the attempted password.
        assertThat(event.actor()).doesNotContain("secret");
        assertThat(event.attributes().values()).noneMatch(v -> v.contains("secret"));
    }

    @Test
    void failure_actor_hash_is_deterministic_for_correlation() {
        var a1 = UsernamePasswordAuthenticationToken.unauthenticated("mallory", "x");
        var a2 = UsernamePasswordAuthenticationToken.unauthenticated("mallory", "y");
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(a1, new BadCredentialsException("bad")));
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(a2, new BadCredentialsException("bad")));

        assertThat(captured).hasSize(2);
        assertThat(captured.get(0).actor()).isEqualTo(captured.get(1).actor());
    }
}
