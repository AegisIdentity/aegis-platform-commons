package io.aegis.commons.agent.protocol;

import java.util.Set;

/**
 * An A2A Agent Card as parsed by {@link A2aAgentCardAdapter}.
 *
 * <p>{@code skills} is what the card <em>claims</em>. What it is actually granted is
 * {@link A2aAgentCardAdapter#effectiveSkills(A2aAgentCard)}, which is empty unless the card's
 * signature was verified. Keeping claim and grant as separate concepts is the point: we want the
 * claim recorded for forensics even when we refuse to honour it.
 *
 * @param cardHash content hash over the card's meaning-bearing fields, so a peer silently
 *                 broadening its own advertised capabilities is detectable
 */
public record A2aAgentCard(
        String name,
        String description,
        String url,
        String version,
        Set<String> skills,
        boolean signatureVerified,
        String cardHash) {

    public A2aAgentCard {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("agent card name is required");
        }
        skills = skills == null ? Set.of() : Set.copyOf(skills);
    }
}
