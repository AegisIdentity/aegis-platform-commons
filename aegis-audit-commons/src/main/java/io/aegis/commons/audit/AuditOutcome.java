package io.aegis.commons.audit;

/** Outcome of an audited action. Maps to the 401/403 distinction and success paths. */
public enum AuditOutcome {
    /** The action was permitted and completed. */
    SUCCESS,
    /** Authentication failed (we don't know who you are). */
    FAILURE,
    /** Authenticated but not authorized (we know who you are; the answer is no). */
    DENIED
}
