package io.aegis.commons.agent;

/** How much an agent may do without a human in the loop. Ordered least-to-most trusted. */
public enum AutonomyLevel {

    /** Every action requires explicit human approval. The safe default. */
    CONFIRM_EACH,

    /** Acts freely within policy; escalates when it would exceed its ceiling. */
    SUPERVISED,

    /** Acts without escalation inside its mandate. Granted deliberately, never by default. */
    AUTONOMOUS
}
