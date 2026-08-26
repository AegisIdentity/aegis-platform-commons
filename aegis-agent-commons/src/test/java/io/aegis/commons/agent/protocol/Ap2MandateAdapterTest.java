package io.aegis.commons.agent.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.agent.Mandate;
import io.aegis.commons.agent.MandateDecision;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * AP2 v0.2.0. A payment mandate is bound to the <em>user's</em> signing key, not the agent's, and
 * the agent never sees the payment credential. Aegis verifies and bounds the mandate; it does not
 * process payments.
 */
class Ap2MandateAdapterTest {

    private static final String MANDATE_JSON = """
            {
              "subject": "user:alice@acme",
              "grantee": "agent:shopper",
              "issuedAt": "2026-08-26T10:00:00Z",
              "constraints": {
                "windowSeconds": 600,
                "maxUses": 1,
                "allowedActions": ["payment:charge"],
                "limits": { "amount": "100.00", "currency": "USD" }
              },
              "proof": "sig:abc123"
            }
            """;

    @Test
    void maps_an_ap2_mandate_onto_the_core_model() {
        Mandate m = Ap2MandateAdapter.parse(MANDATE_JSON);

        assertThat(m.subject()).isEqualTo("user:alice@acme");
        assertThat(m.grantee()).isEqualTo("agent:shopper");
        assertThat(m.constraints().limits()).containsEntry("amount", "100.00");
        assertThat(m.proof()).isEqualTo("sig:abc123");
    }

    @Test
    void a_single_use_mandate_is_exhausted_after_one_use() {
        Mandate m = Ap2MandateAdapter.parse(MANDATE_JSON);
        Instant now = Instant.parse("2026-08-26T10:01:00Z");

        assertThat(m.permits("payment:charge", now, 0)).isEqualTo(MandateDecision.PERMIT);
        assertThat(m.permits("payment:charge", now, 1)).isEqualTo(MandateDecision.EXHAUSTED);
    }

    @Test
    void the_window_bounds_replay() {
        Mandate m = Ap2MandateAdapter.parse(MANDATE_JSON);
        assertThat(m.permits("payment:charge", Instant.parse("2026-08-26T10:11:00Z"), 0))
                .isEqualTo(MandateDecision.EXPIRED);
    }

    @Test
    void an_action_the_mandate_never_authorized_is_denied() {
        Mandate m = Ap2MandateAdapter.parse(MANDATE_JSON);
        assertThat(m.permits("payment:refund", Instant.parse("2026-08-26T10:01:00Z"), 0))
                .isEqualTo(MandateDecision.ACTION_NOT_ALLOWED);
    }

    @Test
    void reports_the_protocol_it_adapts() {
        assertThat(Ap2MandateAdapter.PROTOCOL).isEqualTo("ap2");
    }
}
