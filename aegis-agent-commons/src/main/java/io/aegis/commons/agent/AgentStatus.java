package io.aegis.commons.agent;

/** Lifecycle state of a registered agent. */
public enum AgentStatus {

    /** Registered but not yet permitted to act — the default for anything not explicitly activated. */
    SUSPENDED,

    /** May act, subject to policy and mandate. */
    ACTIVE,

    /** Permanently withdrawn. Never returns to {@link #ACTIVE}; register a new agent instead. */
    REVOKED
}
