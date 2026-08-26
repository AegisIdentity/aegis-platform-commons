package io.aegis.commons.agent.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.commons.agent.AgentPrincipal;
import io.aegis.commons.agent.AgentStatus;
import io.aegis.commons.agent.AutonomyLevel;
import io.aegis.commons.agent.CanonicalJson;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * Translates an A2A (Agent2Agent v1.0) Agent Card into the protocol-agnostic model.
 *
 * <p>A2A advertises capabilities through Agent Cards but <b>deliberately leaves credential
 * management and card verification to implementers</b> — it does not mandate how a card is proven
 * authentic. That gap is exactly what an identity platform is for, and this adapter closes it with
 * one rule: <b>an unverified card confers no authority</b>.
 */
public final class A2aAgentCardAdapter {

    public static final String PROTOCOL = "a2a";

    private A2aAgentCardAdapter() {
    }

    /**
     * @param signatureVerified whether the caller has already verified the card's signature against
     *                          the tenant's trust store. This adapter does not verify signatures
     *                          itself — it has no key material — but it will not let an unverified
     *                          card grant anything.
     */
    public static A2aAgentCard parse(String cardJson, boolean signatureVerified) {
        JsonNode root = CanonicalJson.parse(cardJson);

        JsonNode name = root.get("name");
        if (name == null || name.asText().isBlank()) {
            throw new IllegalArgumentException("A2A agent card has no name");
        }

        Set<String> skills = new LinkedHashSet<>();
        JsonNode skillsNode = root.get("skills");
        if (skillsNode != null && skillsNode.isArray()) {
            skillsNode.forEach(skill -> {
                JsonNode id = skill.get("id");
                if (id != null && !id.asText().isBlank()) {
                    skills.add(id.asText());
                }
            });
        }

        return new A2aAgentCard(
                name.asText(),
                text(root, "description"),
                text(root, "url"),
                text(root, "version"),
                skills,
                signatureVerified,
                hashOf(name.asText(), text(root, "url"), skills));
    }

    /**
     * The skills the card actually gets, as opposed to the ones it claims.
     *
     * <p>Empty for an unverified card. Default-deny applied to a foreign assertion: we record what
     * an unverified peer says about itself, and act on none of it.
     */
    public static Set<String> effectiveSkills(A2aAgentCard card) {
        return card.signatureVerified() ? card.skills() : Set.of();
    }

    /**
     * Project a card onto a local principal.
     *
     * <p>A verified card starts {@link AutonomyLevel#SUPERVISED}, never {@code AUTONOMOUS}:
     * verification establishes <em>who</em> a peer is, which is a different question from whether we
     * trust it to act unattended. Conflating the two would let any peer that can sign a card promote
     * itself.
     */
    public static AgentPrincipal toPrincipal(A2aAgentCard card, String tenantId, String ownerPrincipal) {
        return new AgentPrincipal(
                "agent:" + card.name(),
                tenantId,
                ownerPrincipal,
                card.signatureVerified() ? AutonomyLevel.SUPERVISED : AutonomyLevel.CONFIRM_EACH,
                card.signatureVerified() ? AgentStatus.ACTIVE : AgentStatus.SUSPENDED,
                Instant.now());
    }

    private static String text(JsonNode root, String field) {
        JsonNode node = root.get(field);
        return node == null ? null : node.asText();
    }

    private static String hashOf(String name, String url, Set<String> skills) {
        // TreeSet: a card that merely reorders its skills is not a change.
        return CanonicalJson.sha256Hex(
                "name=" + name + "\nurl=" + url + "\nskills=" + new TreeSet<>(skills));
    }
}
