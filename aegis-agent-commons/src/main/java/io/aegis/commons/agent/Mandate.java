package io.aegis.commons.agent;

import java.time.Instant;

/**
 * Bounded, provable authorization from a subject to a grantee.
 *
 * <p>Modelled on AP2's mandate, whose defining property is that it is bound to the <b>subject's</b>
 * signing key rather than the agent's, and that the agent never sees the underlying credential. The
 * platform verifies and bounds mandates; it does not process payments.
 *
 * <p>{@code proof} is carried but <em>not verified here</em> — signature verification needs the
 * subject's key material and therefore belongs to the authorization server, which has it. Keeping
 * this type free of crypto keeps it usable in the detection pipeline, where no keys are available.
 *
 * @param subject     who authorized — holds the signing key
 * @param grantee     who may act
 * @param constraints the bounds
 * @param issuedAt    when issued; the {@code window} is measured from here
 * @param proof       signature over the canonical form, verified elsewhere
 */
public record Mandate(
        String subject,
        String grantee,
        MandateConstraints constraints,
        Instant issuedAt,
        String proof) {

    public Mandate {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("mandate subject is required");
        }
        if (grantee == null || grantee.isBlank()) {
            throw new IllegalArgumentException("mandate grantee is required");
        }
        constraints = constraints == null
                ? new MandateConstraints(null, 0, null, null)  // deny-all
                : constraints;
        issuedAt = issuedAt == null ? Instant.now() : issuedAt;
    }

    /**
     * Evaluate one attempted action.
     *
     * <p>Checks run expiry → exhaustion → allow-list so the returned reason is the most actionable
     * one: there is no point telling a caller its action is disallowed if the mandate already
     * expired.
     *
     * @param usesSoFar how many times this mandate has already been exercised
     */
    public MandateDecision permits(String action, Instant now, int usesSoFar) {
        Instant expiresAt = issuedAt.plus(constraints.window());
        if (now == null || !now.isBefore(expiresAt)) {
            return MandateDecision.EXPIRED;
        }
        if (usesSoFar >= constraints.maxUses()) {
            return MandateDecision.EXHAUSTED;
        }
        if (!constraints.allows(action)) {
            return MandateDecision.ACTION_NOT_ALLOWED;
        }
        return MandateDecision.PERMIT;
    }
}
