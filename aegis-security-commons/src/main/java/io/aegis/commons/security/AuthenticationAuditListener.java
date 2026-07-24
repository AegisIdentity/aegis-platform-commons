package io.aegis.commons.security;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;

/**
 * Bridges Spring Security's authentication/authorization events into the audit trail, so failed
 * logins and denied authorizations are observable in production — often the only forensic evidence
 * after an incident. Success is recorded too, for the System-Log timeline.
 *
 * <p>Authorization events require a {@code SpringAuthorizationEventPublisher} bean to be published;
 * authentication events are published by Spring Boot's default publisher out of the box.
 */
public class AuthenticationAuditListener {

    private final AuditEventPublisher audit;

    public AuthenticationAuditListener(AuditEventPublisher audit) {
        this.audit = audit;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        audit.publish(AuditEvent.of("auth", "login", AuditOutcome.SUCCESS)
                .actor(name(event.getAuthentication() == null ? null : event.getAuthentication().getName()))
                .build());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        // On failure the "principal" is the *attempted* username — and users routinely mistype their
        // password into the username field. Hashing it keeps a cleartext credential out of the audit
        // trail while a deterministic (unsalted) digest still lets repeated failures be correlated.
        audit.publish(AuditEvent.of("auth", "login", AuditOutcome.FAILURE)
                .actor(hashedActor(event.getAuthentication() == null
                        ? null : event.getAuthentication().getName()))
                .attribute("reason", event.getException() == null
                        ? "unknown" : event.getException().getClass().getSimpleName())
                .build());
    }

    @EventListener
    public void onAuthorizationDenied(AuthorizationDeniedEvent<?> event) {
        audit.publish(AuditEvent.of("authz", "access", AuditOutcome.DENIED)
                .actor(name(event.getAuthentication() == null ? null
                        : event.getAuthentication().get() == null ? null
                        : event.getAuthentication().get().getName()))
                .build());
    }

    private static String name(String candidate) {
        return (candidate == null || candidate.isBlank()) ? "anonymous" : candidate;
    }

    /**
     * Deterministic, non-reversible actor label for failed attempts: {@code sha256:<first 16 hex>}.
     * Truncated to keep the trail readable; a possibly-mistyped password never appears in cleartext.
     */
    private static String hashedActor(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return "anonymous";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(candidate.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a required JCA algorithm; if it is somehow absent, never fall back to cleartext.
            return "sha256:unavailable";
        }
    }
}
