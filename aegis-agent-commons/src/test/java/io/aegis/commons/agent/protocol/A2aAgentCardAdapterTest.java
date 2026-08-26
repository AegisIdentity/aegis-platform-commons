package io.aegis.commons.agent.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.commons.agent.AgentPrincipal;
import io.aegis.commons.agent.AutonomyLevel;
import org.junit.jupiter.api.Test;

/**
 * A2A v1.0. The protocol advertises capabilities via Agent Cards but deliberately leaves credential
 * management and card verification to implementers — which is precisely the gap an identity platform
 * exists to close. The load-bearing rule here: an unverified card confers <b>no</b> authority.
 */
class A2aAgentCardAdapterTest {

    private static final String CARD_JSON = """
            {
              "name": "researcher",
              "description": "Searches and summarizes",
              "url": "https://agents.partner.example/researcher",
              "version": "1.2.0",
              "skills": [
                { "id": "search", "name": "Web search" },
                { "id": "summarize", "name": "Summarize" }
              ]
            }
            """;

    @Test
    void parses_a_card_into_the_protocol_agnostic_model() {
        A2aAgentCard card = A2aAgentCardAdapter.parse(CARD_JSON, true);

        assertThat(card.name()).isEqualTo("researcher");
        assertThat(card.url()).isEqualTo("https://agents.partner.example/researcher");
        assertThat(card.skills()).containsExactlyInAnyOrder("search", "summarize");
        assertThat(card.signatureVerified()).isTrue();
    }

    @Test
    void a_verified_card_confers_its_advertised_skills() {
        A2aAgentCard card = A2aAgentCardAdapter.parse(CARD_JSON, true);
        assertThat(A2aAgentCardAdapter.effectiveSkills(card))
                .containsExactlyInAnyOrder("search", "summarize");
    }

    @Test
    void an_unverified_card_confers_zero_authority() {
        // The card still parses — we want it recorded — but nothing it claims is honoured.
        // Default-deny applied to a foreign assertion.
        A2aAgentCard card = A2aAgentCardAdapter.parse(CARD_JSON, false);

        assertThat(card.skills()).hasSize(2);          // what it CLAIMS
        assertThat(A2aAgentCardAdapter.effectiveSkills(card)).isEmpty();  // what it GETS
    }

    @Test
    void an_unverified_card_yields_a_principal_that_cannot_act_alone() {
        AgentPrincipal principal = A2aAgentCardAdapter.toPrincipal(
                A2aAgentCardAdapter.parse(CARD_JSON, false), "acme", "user:alice");

        assertThat(principal.autonomy()).isEqualTo(AutonomyLevel.CONFIRM_EACH);
    }

    @Test
    void a_verified_card_still_starts_supervised_not_autonomous() {
        // Verification proves WHO the peer is. It says nothing about whether we trust it to act
        // unsupervised, so it must not silently promote autonomy.
        AgentPrincipal principal = A2aAgentCardAdapter.toPrincipal(
                A2aAgentCardAdapter.parse(CARD_JSON, true), "acme", "user:alice");

        assertThat(principal.autonomy()).isEqualTo(AutonomyLevel.SUPERVISED);
        assertThat(principal.ownerPrincipal()).isEqualTo("user:alice");
    }

    @Test
    void card_hash_detects_a_peer_silently_broadening_its_capabilities() {
        A2aAgentCard before = A2aAgentCardAdapter.parse(CARD_JSON, true);
        A2aAgentCard after = A2aAgentCardAdapter.parse(
                CARD_JSON.replace("{ \"id\": \"summarize\", \"name\": \"Summarize\" }",
                        "{ \"id\": \"summarize\", \"name\": \"Summarize\" },\n { \"id\": \"shell\", \"name\": \"Run shell\" }"),
                true);

        assertThat(before.cardHash()).isNotEqualTo(after.cardHash());
    }

    @Test
    void reports_the_protocol_it_adapts() {
        assertThat(A2aAgentCardAdapter.PROTOCOL).isEqualTo("a2a");
    }
}
