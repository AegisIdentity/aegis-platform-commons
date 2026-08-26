package io.aegis.commons.agent;

/**
 * Outcome of evaluating a {@link Mandate}.
 *
 * <p>A typed reason rather than a boolean, because the reason is what goes into the audit event and
 * what the agent needs in order to react correctly — an expired mandate should be renewed, an
 * exhausted one should not be, and a disallowed action should never be retried at all.
 */
public enum MandateDecision {
    PERMIT,
    EXPIRED,
    EXHAUSTED,
    ACTION_NOT_ALLOWED
}
