package io.aegis.commons.vault;

/** Transit key types the platform uses. Wire values are Vault's own identifiers. */
public enum TransitKeyType {

    RSA_2048("rsa-2048"),
    RSA_4096("rsa-4096"),
    ECDSA_P256("ecdsa-p256"),
    ECDSA_P384("ecdsa-p384"),
    ED25519("ed25519"),
    /** Symmetric, for encrypt/decrypt rather than signing. */
    AES256_GCM96("aes256-gcm96");

    private final String wireValue;

    TransitKeyType(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }
}
