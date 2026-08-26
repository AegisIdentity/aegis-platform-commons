package io.aegis.commons.audit;

/**
 * What kind of principal occupies a hop in a {@link DelegationChain}.
 *
 * <p>Deliberately protocol-agnostic (ADR-0011): MCP, A2A and AP2 all map onto these, and none of
 * them appear here. A vendor SDK never appears here either.
 */
public enum PrincipalType {

    /** A person. Only a human can be the ultimate source of delegated authority. */
    HUMAN,

    /** An AI agent acting on delegated authority. */
    AGENT,

    /** A workload/service acting as itself (client-credentials, mesh workload). */
    SERVICE,

    /** A tool or resource endpoint being invoked — the terminal hop. */
    TOOL,

    /**
     * Type not asserted. Used when a chain arrives from outside our trust boundary and we decline to
     * guess — an unverified claim is recorded as unknown rather than upgraded to a fact.
     */
    UNKNOWN
}
