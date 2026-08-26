package io.aegis.commons.agent.protocol;

import com.nimbusds.jose.jwk.JWK;
import java.util.List;

/**
 * The keys a tenant trusts to sign Agent Cards.
 *
 * <p>Per tenant, deliberately: one tenant's partner must not become silently trusted by every other
 * tenant. An empty list means trust nothing, which is the correct default for an unconfigured tenant.
 */
@FunctionalInterface
public interface AgentCardTrustStore {

    /** Public keys this tenant accepts. Never null; empty means trust nothing. */
    List<JWK> trustedKeys(String tenantId);
}
