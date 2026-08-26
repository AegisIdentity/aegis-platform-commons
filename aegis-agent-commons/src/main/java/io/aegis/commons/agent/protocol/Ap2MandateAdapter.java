package io.aegis.commons.agent.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.commons.agent.CanonicalJson;
import io.aegis.commons.agent.Mandate;
import io.aegis.commons.agent.MandateConstraints;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Translates an AP2 (Agent Payments Protocol v0.2.0) mandate into the protocol-agnostic
 * {@link Mandate}.
 *
 * <p>Aegis's role is to verify and bound the mandate, not to move money. The payment-specific
 * limits ({@code amount}, {@code currency}) pass through into
 * {@link MandateConstraints#limits()} where a payments integration can interpret them — the core
 * stores them without ascribing meaning.
 */
public final class Ap2MandateAdapter {

    public static final String PROTOCOL = "ap2";

    private Ap2MandateAdapter() {
    }

    public static Mandate parse(String mandateJson) {
        JsonNode root = CanonicalJson.parse(mandateJson);

        JsonNode constraints = root.get("constraints");
        if (constraints == null) {
            throw new IllegalArgumentException("AP2 mandate has no constraints — refusing to treat "
                    + "an unbounded mandate as valid");
        }

        Set<String> allowedActions = new LinkedHashSet<>();
        JsonNode actions = constraints.get("allowedActions");
        if (actions != null && actions.isArray()) {
            actions.forEach(action -> allowedActions.add(action.asText()));
        }

        Map<String, String> limits = new LinkedHashMap<>();
        JsonNode limitsNode = constraints.get("limits");
        if (limitsNode != null) {
            for (Iterator<String> it = limitsNode.fieldNames(); it.hasNext(); ) {
                String field = it.next();
                limits.put(field, limitsNode.get(field).asText());
            }
        }

        JsonNode window = constraints.get("windowSeconds");
        JsonNode maxUses = constraints.get("maxUses");

        return new Mandate(
                text(root, "subject"),
                text(root, "grantee"),
                new MandateConstraints(
                        Duration.ofSeconds(window == null ? 0 : window.asLong()),
                        maxUses == null ? 0 : maxUses.asInt(),
                        allowedActions,
                        limits),
                root.get("issuedAt") == null ? Instant.now() : Instant.parse(root.get("issuedAt").asText()),
                text(root, "proof"));
    }

    private static String text(JsonNode root, String field) {
        JsonNode node = root.get(field);
        return node == null ? null : node.asText();
    }
}
