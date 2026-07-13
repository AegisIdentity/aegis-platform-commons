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
    void failure_event_records_failure_with_reason() {
        var auth = UsernamePasswordAuthenticationToken.unauthenticated("mallory", "secret");
        listener.onFailure(new AuthenticationFailureBadCredentialsEvent(auth,
                new BadCredentialsException("bad")));

        assertThat(captured).hasSize(1);
        AuditEvent event = captured.get(0);
        assertThat(event.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(event.actor()).isEqualTo("mallory");
        assertThat(event.attributes()).containsEntry("reason", "BadCredentialsException");
        // The failure record must NOT contain the attempted password.
        assertThat(event.attributes().values()).noneMatch(v -> v.contains("secret"));
    }
}
