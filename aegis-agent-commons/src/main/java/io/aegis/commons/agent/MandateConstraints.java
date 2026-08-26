package io.aegis.commons.agent;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

/**
 * The bounds of a {@link Mandate}.
 *
 * <p>AP2 expresses payment authority as amount ceiling + merchant category + time window +
 * single-use/recurring. The identical structure expresses "at most 50 tool calls, only from this
 * list, expiring in 10 minutes", which is why constraints live in the protocol-agnostic core
 * (ADR-0011) rather than in a payments adapter.
 *
 * @param window         validity duration measured from the mandate's issue time
 * @param maxUses        how many times it may be exercised; {@code 1} is single-use
 * @param allowedActions exact action ids, or a trailing-{@code *} prefix pattern. <b>Empty means
 *                       deny-all</b> — never "unset means allow".
 * @param limits         domain-specific numeric or textual limits the core stores but does not
 *                       interpret (e.g. {@code amount}); an adapter gives them meaning
 */
public record MandateConstraints(
        Duration window,
        int maxUses,
        Set<String> allowedActions,
        Map<String, String> limits) {

    public MandateConstraints {
        window = window == null ? Duration.ZERO : window;
        if (maxUses < 0) {
            throw new IllegalArgumentException("maxUses must not be negative");
        }
        allowedActions = allowedActions == null ? Set.of() : Set.copyOf(allowedActions);
        limits = limits == null ? Map.of() : Map.copyOf(limits);
    }

    /**
     * Whether {@code action} is covered.
     *
     * <p>A trailing {@code *} matches by prefix <em>including the separator</em>, so
     * {@code mcp:search/*} covers {@code mcp:search/web} but not {@code mcp:search-evil/x}. Omitting
     * the separator from the prefix is the classic way a wildcard silently widens every grant.
     */
    public boolean allows(String action) {
        if (action == null || allowedActions.isEmpty()) {
            return false; // default-deny
        }
        for (String pattern : allowedActions) {
            if (pattern.equals(action)) {
                return true;
            }
            if (pattern.endsWith("*") && action.startsWith(pattern.substring(0, pattern.length() - 1))) {
                return true;
            }
        }
        return false;
    }
}
