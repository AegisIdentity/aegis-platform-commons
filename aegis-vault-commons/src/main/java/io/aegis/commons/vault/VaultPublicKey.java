package io.aegis.commons.vault;

/**
 * One version of a Transit key's <b>public</b> half.
 *
 * <p>The only key material that ever leaves Vault. The private half cannot be exported — keys are
 * created with {@code exportable=false} — which is the whole basis of ADR-0015's claim that a
 * memory-disclosure bug in a service cannot yield a tenant's signing key.
 *
 * @param version Vault key version. Rotation increments it; earlier versions remain able to verify,
 *                which is what makes overlapping-{@code kid} rotation safe.
 * @param pem     PEM-encoded public key
 */
public record VaultPublicKey(int version, String pem) {

    public VaultPublicKey {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("public key PEM is required");
        }
    }
}
