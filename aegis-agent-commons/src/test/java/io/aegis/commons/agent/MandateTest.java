package io.aegis.commons.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * A {@link Mandate} is bounded, provable authorization from a human to an agent. AP2 uses exactly
 * this shape for payments — amount ceiling, merchant category, time window, single-use vs recurring
 * — and the identical structure expresses a tool-call ceiling, which is why it lives in the
 * protocol-agnostic core rather than in a payments adapter (ADR-0011).
 */
class MandateTest {

    private static final Instant ISSUED = Instant.parse("2026-08-26T10:00:00Z");

    private static Mandate mandate(Set<String> allowed, int maxUses, Duration window) {
        return new Mandate("user:alice", "agent:shopper",
                new MandateConstraints(window, maxUses, allowed, Map.of("amount", "100.00")),
                ISSUED, "sig:abc");
    }

    @Test
    void permits_an_allowed_action_inside_the_window_and_use_count() {
        Mandate m = mandate(Set.of("mcp:files/read"), 3, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:files/read", ISSUED.plusSeconds(60), 1))
                .isEqualTo(MandateDecision.PERMIT);
    }

    @Test
    void denies_after_the_window_expires() {
        Mandate m = mandate(Set.of("mcp:files/read"), 3, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:files/read", ISSUED.plusSeconds(601), 1))
                .isEqualTo(MandateDecision.EXPIRED);
    }

    @Test
    void denies_once_the_use_count_is_exhausted() {
        Mandate m = mandate(Set.of("mcp:files/read"), 3, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:files/read", ISSUED.plusSeconds(60), 3))
                .isEqualTo(MandateDecision.EXHAUSTED);
    }

    @Test
    void denies_an_action_outside_the_allow_list() {
        Mandate m = mandate(Set.of("mcp:files/read"), 3, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:shell/exec", ISSUED.plusSeconds(60), 0))
                .isEqualTo(MandateDecision.ACTION_NOT_ALLOWED);
    }

    @Test
    void an_empty_allow_list_denies_everything() {
        // Default-deny is a platform non-negotiable. An empty allow-list is the *most* restrictive
        // configuration, never an "unset means allow all" escape hatch.
        Mandate m = mandate(Set.of(), 3, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:files/read", ISSUED.plusSeconds(60), 0))
                .isEqualTo(MandateDecision.ACTION_NOT_ALLOWED);
    }

    @Test
    void supports_a_trailing_wildcard_in_the_allow_list() {
        Mandate m = mandate(Set.of("mcp:search/*"), 5, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:search/web", ISSUED.plusSeconds(60), 0)).isEqualTo(MandateDecision.PERMIT);
        assertThat(m.permits("mcp:shell/exec", ISSUED.plusSeconds(60), 0))
                .isEqualTo(MandateDecision.ACTION_NOT_ALLOWED);
    }

    @Test
    void a_wildcard_must_not_match_across_the_namespace_separator() {
        // "mcp:search/*" must not authorize "mcp:search-evil/x" — prefix matching without this check
        // silently widens every mandate.
        Mandate m = mandate(Set.of("mcp:search/*"), 5, Duration.ofMinutes(10));
        assertThat(m.permits("mcp:search-evil/x", ISSUED.plusSeconds(60), 0))
                .isEqualTo(MandateDecision.ACTION_NOT_ALLOWED);
    }

    @Test
    void exposes_typed_limits_for_a_domain_adapter_to_interpret() {
        // The core stores the limit; it does not know what "amount" means. A payments adapter does.
        assertThat(mandate(Set.of("x"), 1, Duration.ofMinutes(1)).constraints().limits())
                .containsEntry("amount", "100.00");
    }
}
