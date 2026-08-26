package io.aegis.commons.agent.protocol;

/**
 * Outcome of verifying an A2A Agent Card signature.
 *
 * <p>Typed rather than boolean because the outcomes mean different things operationally.
 * {@link #NO_SIGNATURE} is a peer that never signed — possibly just not configured yet.
 * {@link #BAD_SIGNATURE} is a card that was <em>altered</em>, which is an attack signal.
 * {@link #UNTRUSTED_KEY} is a validly-signed card from a key we do not trust — exactly what an
 * impersonating peer produces. Collapsing them into one boolean would discard the distinction that
 * tells an operator which of those happened.
 */
public enum CardVerification {

    VERIFIED,

    /** No signatures present. Confers no authority, but is not evidence of tampering. */
    NO_SIGNATURE,

    /** Signature present and cryptographically valid, but not by a key this tenant trusts. */
    UNTRUSTED_KEY,

    /** Signature does not match the card content — the card was altered after signing. */
    BAD_SIGNATURE,

    /** The card or its signature block could not be parsed. */
    MALFORMED
}
